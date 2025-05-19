#ifndef _PRLIMIT_H
#define _PRLIMIT_H

#include "util.h"
#include "gadget_base.h"

void speculatively_load_relative(uint64_t, int);

void speculatively_load(uint64_t);

void speculatively_load_relative_tlb(uint64_t, int);

void speculatively_load_tlb(uint64_t);

void do_prlimit_init(void);

#endif // _PRLIMIT_H
