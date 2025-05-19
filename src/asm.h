#ifndef _ASM_H
#define _ASM_H

#include <inttypes.h>


static inline __attribute__((always_inline)) void clflush(void* p) {
	asm volatile("clflush (%0)\n"::"r"(p));
}

static inline __attribute__((always_inline)) void clflushopt(void* p) {
	asm volatile("clflushopt (%0)\n"::"r"(p));
}
static inline __attribute__((always_inline)) uint64_t rdtscp(void) {
	uint64_t lo, hi;
	asm volatile("rdtscp\n" : "=a" (lo), "=d" (hi) :: "rcx");
	return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) void mfence() {
	asm volatile ("mfence\n");
}

static inline __attribute__((always_inline)) void lfence() {
	asm volatile ("lfence\n");
}

static inline __attribute__((always_inline)) void prefetcht0(void *addr) {
    asm volatile("prefetcht0 (%0)\n\t" :: "r" (addr):);
}

static inline __attribute__((always_inline)) void cpuid(void) {
	asm volatile ("xor %%rax, %%rax\ncpuid\n\t" ::: "%rax", "%rbx", "%rcx", "%rdx"); 
}

static inline __attribute__((always_inline)) void load(void *addr) { 
	*(volatile char *)addr;
}

static inline uint64_t time_prefetch(volatile void *addr)
{
    unsigned start_low, start_high, end_low, end_high;
    uint64_t start, end, duration;

    asm volatile (
        "xor %%rax, %%rax\n\t"
        "cpuid\n\t"
        "rdtsc\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "prefetcht0 (%4)\n\t"
        "rdtscp\n\t"
        "mov %%edx, %2\n\t"
        "mov %%eax, %3\n\t"
        "xor %%rax, %%rax\n\t"
        "cpuid\n\t"
        : "=&r" (start_high), "=&r" (start_low), "=r" (end_high), "=r" (end_low)
        : "r" (addr)
        : "%rax", "%rbx", "%rcx", "%rdx"
    );

    start = ((uint64_t)start_high << 32) | (uint64_t)start_low;
    end = ((uint64_t)end_high << 32) | (uint64_t)end_low;
    duration = end - start;

    return duration;
}



#endif