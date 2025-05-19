#ifndef _PRELOAD_TIME_H
#define _PRELOAD_TIME_H

#include <inttypes.h>

void evict_caches_tlb(void);

void synthetic_preload_time_stage(void);

void half_synthetic_preload_time_stage(void);

void test_preload_time_stage(void);

#endif // _PRELOAD_TIME_H