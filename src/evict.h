#ifndef _EVICT_H
#define _EVICT_H

#include "util.h"

#define N_MEASUREMENTS 10 // SPEEDUP: linear shrink.

#define EVICT_FACTOR 4 // if replacement is not perfect LRU it's better to touch more lines

// L1$ indexing function: LIN-64
#define L1_SETS 64
#define L1_WAYS 12

// L2$ indexing function: LIN-2048
#define BITS_L2SETS 11
#define L2_SETS 2048
#define L2_WAYS 16

// L3$ indexing function: see evict.c's l3_set().
#define L3_SETS 49152
#define L3_WAYS 12
#define L3_SIZE (L3_SETS * L3_WAYS * 64)

// DTLB indexing function: LIN-16
#define DTLB_SETS 16
#define DTLB_WAYS 6

// STLB indexing function: XOR-7
#define STLB_SETS 128
#define STLB_WAYS 16 // TLB;DR reports 13-16
#define STLB_BONUS_FACTOR 4 // On top of EVICT_FACTOR.

/* Don't let our TLB eviction interfere too much with data cache eviction:
 * isolate our TLB eviction set traversals to one particular L1 data cache set.
 *
 * SPEEDUP - maybe use multiple L1/2$ sets to speed up TLB eviction.
 * Expected gain: 1-100x tlb eviction?
 */
#define TLB_EVICTION_L1_SET (L1_SETS-1)

#define DATA_LOAD_L1_SET (L1_SETS - 2)

int l2_set(physaddr_t pa);

int l3_set(physaddr_t pa);

void evict_l1_l2_set(unsigned int);

void evict_l2_set(unsigned int);

void evict_l3_set(unsigned int);

void evict_user_pte(vaddr_t uaddr, unsigned pte_l2_set);

void evict_tlb(vaddr_t);

void eviction_init(void);

set_t find_pte_l2_set(vaddr_t va);

#endif // _EVICT_H
