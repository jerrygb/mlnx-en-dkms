/*
 * Basic general purpose allocator for managing special purpose memory
 * not managed by the regular kmalloc/kfree interface.
 * Uses for this includes on-device special memory, uncached memory
 * etc.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */


/*
 *  General purpose special memory pool descriptor.
 */
struct gen_pool {
	rwlock_t lock;
	struct list_head chunks;	/* list of chunks in this pool */
	int min_alloc_order;		/* minimum allocation order */
};

/*
 *  General purpose special memory pool chunk descriptor.
 */
struct gen_pool_chunk {
	spinlock_t lock;
	struct list_head next_chunk;	/* next chunk in pool */
	unsigned long start_addr;	/* starting address of memory chunk */
	unsigned long end_addr;		/* ending address of memory chunk */
	unsigned long bits[0];		/* bitmap for allocating memory chunk */
};

extern struct gen_pool *ib_gen_pool_create(int, int);
extern int ib_gen_pool_add(struct gen_pool *, unsigned long, size_t, int);
extern void ib_gen_pool_destroy(struct gen_pool *);
extern unsigned long ib_gen_pool_alloc(struct gen_pool *, size_t);
extern void ib_gen_pool_free(struct gen_pool *, unsigned long, size_t);

#define gen_pool_create ib_gen_pool_create
#define gen_pool_add ib_gen_pool_add
#define gen_pool_destroy ib_gen_pool_destroy
#define gen_pool_alloc ib_gen_pool_alloc
#define gen_pool_free ib_gen_pool_free
