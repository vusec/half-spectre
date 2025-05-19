#ifndef HAMMER_H
#define HAMMER_H

#include "util.h"

#define N_BANKS 32
#define BANK_CONFLICT_THRES 295
#define PATT_ROUNDS 600000
#define PATT_LEN 10
#define NR_BANK_FUNCS 5


#define PRESENT_BIT 0
#define RW_BIT      1
#define US_BIT      2
#define PWT_BIT     3
#define PCD_BIT     4
#define A_BIT       5
#define AVL_BIT     6
#define PS_BIT      7
#define NX_BIT      63

#define PFN_BITS 22 // This is limited by the amount of system memory we have on our machine (i.e., 16GB) - we don't want to go above that as that would go outside the range of PFNs in the system and cause a crash
#define N_CONTROL_BITS 12

// Default PTE data patterns for hammering. This is before the optimization described in Section 7.5 (and Figure 7) in the paper.

constexpr uint64_t hammering_pte_data_patt =  (1ULL << NX_BIT) | (1ULL << RW_BIT) | (1ULL << US_BIT) |(1ULL << A_BIT) | (1ULL << AVL_BIT) | (1ULL << PRESENT_BIT) | (((1ULL << PFN_BITS) - 1) << N_CONTROL_BITS);

constexpr uint64_t hammering_pte_data_patt_inverse = (1ULL << NX_BIT) | (1ULL << RW_BIT) | (1ULL << US_BIT) | (1ULL << A_BIT) | (1ULL << AVL_BIT) | (1ULL << PRESENT_BIT);

int hammer(std::vector<hamm_patt_t>&);

int bank(physaddr_t);

int row(physaddr_t);

physaddr_t mate(physaddr_t);

int compute_ava(physaddr_t, physaddr_t[6]);

int compute_vxxaxa(physaddr_t, physaddr_t[6]);

std::vector<hamm_patt_t> get_min_dist_patt(bank_t target_bk, const std::map<bank_t, std::vector<hamm_patt_t>>& bk_to_patts);

#endif // HAMMER_H
