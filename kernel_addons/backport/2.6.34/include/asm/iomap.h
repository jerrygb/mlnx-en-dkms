#ifndef __IOMAP__BACKPORT_H_TO_2_6_32___
#define __IOMAP__BACKPORT_H_TO_2_6_32___

#if !defined(CONFIG_PPC32) && !defined(CONFIG_PPC64)
#include_next <asm/kmap_types.h>
#include_next <asm/iomap.h>
#endif

#endif /* __IOMAP__BACKPORT_H_TO_2_6_32___ */
