#ifndef _UTIL_H
#define _UTIL_H

#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <sys/prctl.h>
#include <signal.h>
#include <map>
#include <array>
#include <set>
#include <vector>
#include <iostream>
#include <random>
#include <algorithm>
#include <sys/sysinfo.h>

#include "asm.h"


#define DEGUB_DO_PRELOAD_TIME

typedef void (*evict_func_t)(unsigned int);

typedef struct config {
	int cheat_gadget_base; // debug
	int spray_ratio;
	evict_func_t evict_pte_cache;
	int cheat_preload_time; // debug
	uint pte_user_ratio;
} cfg_t;

extern const cfg_t cfg;

#define pr_info(...) \
		do { fprintf(stdout, __VA_ARGS__); fflush(stdout); } while(0)

#define pr_err(...) \
		do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while(0)

#define check(r) \
		do { if (r < 0) { perror("perror"); pr_err("%s:%d r=%d, errno=%d\n", __FILE__, __LINE__, r, errno); exit(EXIT_FAILURE); } } while(0)

#define ROUNDDOWN(a, n)                                                        \
({                                                                             \
	uintptr_t __a = (uintptr_t) (a);                                           \
	(typeof(a)) (__a - __a % (n));                                             \
})

#define MASK_LSB(v, n) ((v) & ~((1ULL << (n)) - 1ULL))
#define LSB(v, n)      ((v) & ((1ULL << (n)) -1ULL))
#define ALIGN(x, n_bits) (((x) + (1 << (n_bits)) - 1) & -(1 << (n_bits)))

#define STLB_CHUNK1(v)   (((v) & ( ((1ULL << (PAGE_SHIFT + 7)) - 1))) >> (PAGE_SHIFT))
#define STLB_CHUNK2(v)   (((v) & (((1ULL << 7) - 1) << (PAGE_SHIFT + 7))) >> (PAGE_SHIFT + 7))

#define SYS_MEM_SPRAY_FACTOR 2 / 100000

#define PTE_STRIDE 512
#define PAGE_SHIFT 12
#define PTE_SHIFT (PAGE_SHIFT + 9)
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PAGE_ALIGN_PTR(p) ((uint8_t *) (((uint64_t)p) & ~((1ULL << PAGE_SHIFT) - 1)))
#define GB (1ULL << 30)
#define MB (1ULL << 20)
#define KB (1ULL << 10)
#define HUGE_PAGE_SZ (2 * MB)
#define SUPER_PAGE_SZ (1 * GB)
#define VMA_FILE_FACTOR 56 // This is to avoid reaching the limit of VMAs for our process (i.e., 2^16)
#define ALLOC_SIZE_VMA_MERGE (VMA_FILE_FACTOR * (PAGE_SIZE * PTE_STRIDE))
#define SUPER_PAGE_TLB_ENTRIES 4

#define CACHELINE_SZ 64
#define TARGET_PTE_OFFSET_CACHELINE (0UL * CACHELINE_SZ)

#define CACHE_THRES 100

#define PRELOAD_TIME_HIT_THRESH 20

#define BPU_TRAINING_ROUNDS 1 

#define BIT(x, n) (((x) >> (n)) & 0x1)

#define CPU 4
#define SYS_MEM_IN_GB 16
#define SYS_MEM (GB * SYS_MEM_IN_GB)

#define ZERO_PG_PROT (PROT_READ)
#define ZERO_PG_MMAP_FLAGS (MAP_PRIVATE | MAP_POPULATE | MAP_ANON | MAP_FIXED | MAP_NORESERVE)
#define DATA_PG_PROT (PROT_READ | PROT_WRITE)
#define DATA_PG_MMAP_FLAGS (MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE | MAP_NORESERVE)

#define MARKER_LEN 64


// According to /Documentation/arch/x86/x86_64/mm.rst, the direct-map is in this range (faster than scanning all of lowmem)
#define KVA_START 0xffff888000000000
#define KVA_END 0xffffc87fffffffff
#define LINEAR_MAPPING_ALIGN SUPER_PAGE_SZ // on modern systems direct-map is mapped using 1GB pages

/* From Intel 11th Gen onwards, we find some evidence of an Invalid Page Cache (IPC).                                                                                                                                      
 * Namely, after prefetching an invalid page (eg non-present page), consecutive
 * prefetches to the same page execute very fast.
 * If we prefetch a few other invalid pages in between, the prefetch of the
 * initial page becomes slow again. This suggests the MMU caches prefetches to
 * invalid pages. The values below we experimentally determined.
 */
#define IPC_SIZE 4
#define EVICT_FACTOR_IPC 10
#define EVSET_SIZE_IPC (EVICT_FACTOR_IPC * IPC_SIZE)

#define USER_CANONICALITY 0
#define KERNEL_CANONICALITY 1

typedef int set_t; // Cache (or TLB) set.
typedef uint64_t kva_t;
typedef uint64_t physaddr_t;
typedef uint8_t bank_t;
typedef int aid_t; // Allocation identifier type. -1 means invalid.
typedef std::pair<std::vector<aid_t>, std::vector<aid_t>> hamm_patt_t; // first = victims, second = aggressors

/*
 * Struct to make the management of a virtual address easier. I.e., get the offset bits for the 
 * page table hierarchy without individually doing bitmasks. Also some operator overloading for C++
 * management :).
 */
typedef union __vaddr {
	struct {
		uint64_t page_offset:12;
		uint64_t pte_offset:9;
		uint64_t pmd_offset:9;
		uint64_t pud_offset:9;
		uint64_t pgd_offset:9;
		uint64_t canonicality:16;
	}__attribute__((packed, aligned(8))) addr;
	uint64_t va;

	__vaddr(uint8_t *p): va((uint64_t) p) {}
	__vaddr(void *p): va((uint64_t) p) {}
	__vaddr(char *p): va((uint64_t) p) {}
	__vaddr(uint64_t v): va(v) {}
	__vaddr(): va(-1ULL) {}

	operator bool() const {
		return va != 0;
	}
	bool operator<(const __vaddr& other) const {
		return va < other.va;
	}
	__vaddr& operator+=(const __vaddr& other) {
		this->va += other.va;
		return *this;
	}
	__vaddr operator+(const __vaddr& other) const {
		return __vaddr(va + other.va);
	}
	__vaddr operator-(const __vaddr& other) const {
		return __vaddr(va - other.va);
	}

	inline uint8_t *get_ptr() const {return reinterpret_cast<uint8_t *>(va);}
	inline set_t l1_set() const {return addr.page_offset >> 6;}
	inline set_t pte_l1_set() const {return addr.pte_offset >> 3;}
	inline set_t pmd_l1_set() const {return addr.pmd_offset >> 3;}
	inline set_t pud_l1_set() const {return addr.pud_offset >> 3;}
	inline set_t pgd_l1_set() const {return addr.pgd_offset >> 3;}
	inline set_t dtlb_set() const {return LSB(addr.pte_offset, 4);}
	inline set_t stlb_set() const {return LSB((va >> PAGE_SHIFT) ^ (va >> (PAGE_SHIFT + 7)), 7);} // va[25:19] ^ va[18:12]
} vaddr_t;

uint64_t dist(uint64_t, uint64_t);

int cmp_uint64_t(const void *, const void *);

void sort(uint64_t[], unsigned);

uint64_t median_sort(uint64_t[], unsigned);

uint64_t minimum_sort(uint64_t[], unsigned);

int unique_above(uint64_t[], unsigned, uint64_t);

int occurrences_in(int A[], unsigned size, int val);

int count_between(uint64_t A[], uint size, uint64_t low, uint64_t high);

void set_cpu_affinity(int);

int get_sibling(int cpu_id);

uint8_t *alloc_zero_page_fixed(const void *, int);

uint64_t lrand(void);

void evict_ipc(void);

uint64_t get_phys_addr(uint64_t);

uint64_t mem_available(void);

void dump_meminfo(void);

void dump_maps(void);

char *file_read_all(const char *);

uint64_t file_read_lx(const char *);

kva_t procfs_read_gadget_base(void);

physaddr_t procfs_get_physaddr(uint8_t *);

kva_t procfs_get_pud(uint8_t *);

kva_t procfs_get_pmd(uint8_t *);

kva_t procfs_get_pte(uint8_t *);

physaddr_t procfs_pte_pa(vaddr_t uaddr);

void procfs_preload_pte(uint8_t *);

void procfs_invlpg(uint8_t *);

void procfs_clflush_pte(uint8_t *);

void procfs_sim_hammer(physaddr_t);

int probe_direct_map(kva_t, kva_t, uint64_t);

pid_t contention_init(void);

void transiently_load(void *);

uint64_t time_empty(void);

uint64_t time_access(void *);

void *alloc_contiguous_pages(void *, int);

uint64_t clock_read();

void step_start();

void step_end();

void print_histogram_header(unsigned int);

void print_histogram(uint64_t *, unsigned int);

#define STRR(s) #s
#define STR(s) STRR(s)
#define dump_hex(name) pr_info("%40s = %lx\n", STR(name), (uint64_t)name);
#define dump_dec(name) pr_info("%40s = %lu\n", STR(name), (uint64_t)name);

#endif // _UTIL_H
