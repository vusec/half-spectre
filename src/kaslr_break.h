#ifndef _KASLR_BREAK_H
#define _KASLR_BREAK_H

#include <inttypes.h>
#include "util.h"

kva_t direct_map(void);

uint64_t get_tlb_hit_threshold(void);

void kaslr_break(uint64_t);

#endif // _KASLR_BREAK_H
