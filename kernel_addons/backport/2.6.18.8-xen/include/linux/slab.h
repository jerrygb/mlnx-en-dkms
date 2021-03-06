#ifndef LINUX_SLAB_BACKPORT_tO_2_6_22_H
#define LINUX_SLAB_BACKPORT_tO_2_6_22_H

#include_next <linux/slab.h>

static inline
struct kmem_cache *
kmem_cache_create_for_2_6_22 (const char *name, size_t size, size_t align,
			      unsigned long flags,
			      void (*ctor)(void*, struct kmem_cache *, unsigned long)
			      )
{
	return kmem_cache_create(name, size, align, flags, ctor, NULL);
}

#define kmem_cache_create kmem_cache_create_for_2_6_22

#endif
