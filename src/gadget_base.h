#ifndef _GADGET_BASE_H
#define _GADGET_BASE_H

#include "util.h"

kva_t gadget_base(void);

physaddr_t gadget_base_pa(void);

void prefetch_gadget_base(uint64_t);

#endif // _GADGET_BASE_H
