#include "evict.h"

static volatile uint8_t *cache_ev_buf;
static volatile uint8_t *cache_ev_buf2;
static volatile uint8_t *tlbevbuf;

static void evict_dtlb_set(unsigned int set)
{
	for (int i = 0; i < EVICT_FACTOR * DTLB_WAYS; i++) {
		int offset = (set + i*DTLB_SETS)*PAGE_SIZE + TLB_EVICTION_L1_SET*CACHELINE_SZ;
		tlbevbuf[offset];
#ifdef SANITY
		assert(vaddr_t((uint8_t *)&(tlbevbuf[offset])).dtlb_set() == set);
#endif
	}
}

static void evict_stlb_set(unsigned int set)
{
	unsigned int rand_addr, set_idx;
	constexpr unsigned int REPS = 200; // SPEEDUP: linear shrink TLB eviction

	for (unsigned int i = 0; i < REPS; i++) {
		rand_addr = rand() % (STLB_BONUS_FACTOR * EVICT_FACTOR * STLB_WAYS);
		set_idx = ((rand_addr ^ set) | (rand_addr << 7))*PAGE_SIZE + TLB_EVICTION_L1_SET*CACHELINE_SZ;
		tlbevbuf[set_idx];
#ifdef SANITY
		assert(vaddr_t((uint8_t *)&(tlbevbuf[set_idx])).stlb_set() == set);
#endif
	}
}

static void init_cache_evset(void)
{
	cache_ev_buf = (uint8_t *) alloc_contiguous_pages(NULL, 0);
	cache_ev_buf2 = (uint8_t *) alloc_contiguous_pages(NULL, 0);
	// Prevent zero-dedup.
	for(size_t sz = 0; sz < HUGE_PAGE_SZ; sz += PAGE_SIZE) {
		cache_ev_buf[sz] = 0x42;
		cache_ev_buf2[sz] = 0x42;
	}
}

static void measure_latencies(void)
{
	uint64_t med, off, times[N_MEASUREMENTS];
	#define P_ADDR (0x300000000000LLU + (1LLU << (21+3)) + (1LLU << (30+3)))
	uint8_t *p = (uint8_t *)mmap((void *)P_ADDR, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_POPULATE|MAP_FIXED_NOREPLACE, -1, 0); assert(p == (void *)P_ADDR);
	*p = 0x42;

	pr_info("                   min :  q1 : med :  q3\n");
	pr_info("Data latencies:\n");

	for (unsigned int i = 0; i < N_MEASUREMENTS; i++) {
		off = rand() % (PAGE_SIZE-CACHELINE_SZ);
		load(p+off);
		times[i] = time_access(p+off);
	}
	med = median_sort(times, N_MEASUREMENTS);
	pr_info("L1D$ latency:      %3lu : %3lu : %3lu : %3lu\n", times[0], times[N_MEASUREMENTS/4], med, times[3*N_MEASUREMENTS/4]);

	for (unsigned int i = 0; i < N_MEASUREMENTS; i++) {
		off = rand() % (PAGE_SIZE-CACHELINE_SZ);
		load(p+off);
		lfence();
		for (int j = 0; j < L1_WAYS * EVICT_FACTOR; j++)
			cache_ev_buf[j*PAGE_SIZE+off];
		times[i] = time_access(p+off);
	}
	med = median_sort(times, N_MEASUREMENTS);
	pr_info("L2$  latency:      %3lu : %3lu : %3lu : %3lu\n", times[0], times[N_MEASUREMENTS/4], med, times[3*N_MEASUREMENTS/4]);

	for (unsigned int i = 0; i < N_MEASUREMENTS; i++) {
		off = rand() % (PAGE_SIZE-CACHELINE_SZ);
		load(p+off);
		lfence();
		evict_l1_l2_set((((uint64_t)p + off) >> 6) & 0x3f);
		times[i] = time_access(p+off);
	}
	med = median_sort(times, N_MEASUREMENTS);
	pr_info("L3$  latency:      %3lu : %3lu : %3lu : %3lu\n", times[0], times[N_MEASUREMENTS/4], med, times[3*N_MEASUREMENTS/4]);

	for (unsigned int i = 0; i < N_MEASUREMENTS; i++) {
		off = rand() % (PAGE_SIZE-CACHELINE_SZ);
		load(p+off);
		lfence();
		clflush(p+off);
		times[i] = time_access(p+off);
	}
	med = median_sort(times, N_MEASUREMENTS);
	pr_info("DRAM latency:      %3lu : %3lu : %3lu : %3lu (clflush)\n", times[0], times[N_MEASUREMENTS/4], med, times[3*N_MEASUREMENTS/4]);

	////////////////////////////////////////////////////////////////////////////

	pr_info("Page table walk latencies:\n");

	p += PAGE_SIZE / 2;

	for (unsigned int i = 0; i < N_MEASUREMENTS; i++) {
		load(p);
		lfence();
		evict_tlb(p);
		lfence();
		times[i] = time_access(p);
	}
	med = median_sort(times, N_MEASUREMENTS);
	pr_info("PTE L1D$ latency:  %3lu : %3lu : %3lu : %3lu\n", times[0], times[N_MEASUREMENTS/4], med, times[3*N_MEASUREMENTS/4]);

	for (unsigned int i = 0; i < N_MEASUREMENTS; i++) {
		load(p);
		lfence();
		evict_tlb(p);
		lfence();
		for (int j = 0; j < L1_WAYS * EVICT_FACTOR; j++)
			cache_ev_buf[j*PAGE_SIZE];
		lfence();
		times[i] = time_access(p);
	}
	med = median_sort(times, N_MEASUREMENTS);
	pr_info("PTE L2$  latency:  %3lu : %3lu : %3lu : %3lu\n", times[0], times[N_MEASUREMENTS/4], med, times[3*N_MEASUREMENTS/4]);

	for (unsigned int i = 0; i < N_MEASUREMENTS; i++) {
		load(p);
		lfence();
		evict_tlb(p);
		lfence();
		evict_l1_l2_set(vaddr_t(p).pte_l1_set());
		procfs_clflush_pte(p);
		lfence();
		times[i] = time_access(p);
	}
	med = median_sort(times, N_MEASUREMENTS);
	pr_info("PTE DRAM latency:  %3lu : %3lu : %3lu : %3lu\n", times[0], times[N_MEASUREMENTS/4], med, times[3*N_MEASUREMENTS/4]);
	munmap((void *)P_ADDR, PAGE_SIZE);
}

/* SPEEDUP instead of this single virtually contiguous buffer, TLB eviction might
 * go better with random pages throughout virtual address space; try it out?
 * Expected gain: ?
 */
static void init_tlb_evbuf(void)
{
	// XOR-7 uses bits va[25:12] for indexing, pick those bits zero.
	tlbevbuf = (uint8_t *)mmap((void *) (0x123LLU << 26), STLB_SETS * STLB_WAYS * STLB_BONUS_FACTOR * EVICT_FACTOR * PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_POPULATE|MAP_FIXED_NOREPLACE, -1, 0);
	assert(tlbevbuf != MAP_FAILED);
}

static void init_eviction_buffers(void)
{
	init_cache_evset();
	init_tlb_evbuf();
}

void evict_l1_l2_set(unsigned int l2_set)
{
	unsigned l1_set = LSB(l2_set, 6);
	/* SPEEDUP: only evict *one* L2 cache set and its L1 cache set below.
	 * Expected gain: cache eviction 32x
	 */
	assert(((L2_SETS / L1_SETS) * L2_WAYS) * L1_SETS * CACHELINE_SZ == HUGE_PAGE_SZ);
	for(size_t sz = l1_set*CACHELINE_SZ; sz < HUGE_PAGE_SZ; sz += L1_SETS*CACHELINE_SZ) {
		cache_ev_buf[sz];
		cache_ev_buf2[sz];
	}
}

void evict_l2_set(unsigned int l2_set)
{
	assert(L2_SETS * L2_WAYS * CACHELINE_SZ == HUGE_PAGE_SZ);
	for(size_t sz = l2_set*CACHELINE_SZ; sz < HUGE_PAGE_SZ; sz += L2_SETS*CACHELINE_SZ) {
		cache_ev_buf[sz];
		lfence();
		cache_ev_buf2[sz];
		lfence();
	}
}

void evict_tlb(vaddr_t va)
{
	if((uint64_t)va.stlb_set() != (STLB_CHUNK1(va.va) ^ STLB_CHUNK2(va.va))) {
		pr_info("Inconsistency... va stlb_set = %u, calculated = %llu from chunk1 = %llu and chunk2 = %llu\n", va.stlb_set(), (STLB_CHUNK1(va.va) ^ STLB_CHUNK2(va.va)), STLB_CHUNK1(va.va), STLB_CHUNK2(va.va));
	}
	assert((uint64_t)va.stlb_set() == (STLB_CHUNK1(va.va) ^ STLB_CHUNK2(va.va)));
	evict_dtlb_set(va.dtlb_set());
	evict_stlb_set(va.stlb_set());
}

void eviction_init(void)
{
	init_eviction_buffers();
	measure_latencies();
}

int l2_set(physaddr_t pa)
{
	return (pa >> 6) & (L2_SETS - 1);
}

static uint64_t time_pte_eviction(vaddr_t va, set_t pte_l2_set)
{
	uint64_t times[N_MEASUREMENTS];

	for (unsigned int i = 0; i < N_MEASUREMENTS; i++) {
		load(va.get_ptr() + DATA_LOAD_L1_SET*CACHELINE_SZ);
		lfence();
		evict_tlb(va);
		lfence();
		evict_l2_set(pte_l2_set);
		times[i] = time_access(va.get_ptr() + DATA_LOAD_L1_SET*CACHELINE_SZ);
	}

#ifdef SANITY
	sort(times, N_MEASUREMENTS);
	pr_info("VA %lx, L2$ set %3x |", va.va, pte_l2_set);
	print_histogram(times, N_MEASUREMENTS);
#endif

	return median_sort(times, N_MEASUREMENTS);
}

set_t find_pte_l2_set(vaddr_t va)
{
	static std::map<vaddr_t, set_t> cache; // va --> l2set(pte(va))
	constexpr uint64_t THRES = 20;
	uint64_t times[L2_SETS/L1_SETS];
	set_t l2set;
	int idx;

	if (cfg.evict_pte_cache == evict_l1_l2_set)
		return va.pte_l1_set();
	if(cfg.cheat_preload_time) 
		return l2_set(procfs_pte_pa(va));

	// If we computed this va's pte's l2 set already, just lookup the result.
	const auto it = cache.find(va);
	if (it != cache.end())
		return it->second;

	int count = 0;
	do {
		for (int i = 0; i < L2_SETS/L1_SETS; i++) {
			l2set = va.pte_l1_set() + i*L1_SETS;
			times[i] = time_pte_eviction(va, l2set);
		}
		idx = unique_above(times, L2_SETS/L1_SETS, THRES);
		if (++count % 100 == 0) {
			pr_info("WARNING | find_pte_l2_set(%lx) stuck in do/while loop...\n", va.va);
			for (int i = 0; i < L2_SETS/L1_SETS; i++)
				pr_info("%lu ", times[i]);
			pr_info("\n");
			return -1;
		}
	} while (idx < 0);

	l2set = va.pte_l1_set() + idx * L1_SETS;
	cache.insert(std::make_pair(va, l2set));

	if (l2set != l2_set(procfs_pte_pa(va))) {
		pr_info("PTE L2 SET ERROR: real = %d,  found = %d\n", l2_set(procfs_pte_pa(va)), l2set);
		for (int i = 0; i < L2_SETS/L1_SETS; i++)
			pr_info("%lu ", times[i]);
		pr_info("\n");
	}

	return l2set;
}
