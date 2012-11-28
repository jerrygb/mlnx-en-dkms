/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <linux/mlx4/cq.h>
#include <linux/mlx4/qp.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/vmalloc.h>

#include "mlx4_en.h"

enum {
	MIN_RX_ARM = 2048,
};

static int mlx4_en_alloc_frag(struct mlx4_en_priv *priv,
			      struct mlx4_en_rx_desc *rx_desc,
			      struct skb_frag_struct *skb_frags,
			      struct mlx4_en_rx_alloc *ring_alloc,
			      int i)
{
	struct mlx4_en_frag_info *frag_info = &priv->frag_info[i];
	struct mlx4_en_rx_alloc *page_alloc = &ring_alloc[i];
	struct page *page;
	dma_addr_t dma;
	bool new_page = false;

	if (page_alloc->offset == frag_info->last_offset) {
		/* Allocate new page */
		page = alloc_pages(GFP_ATOMIC | __GFP_COMP | __GFP_NOWARN,
				   MLX4_EN_ALLOC_ORDER);
		if (!page)
			return -ENOMEM;

		skb_frags[i].page = page_alloc->page;
		skb_frags[i].page_offset = page_alloc->offset;
		page_alloc->page = page;
		page_alloc->offset = frag_info->frag_align;
		new_page = true;
	} else {
		page = page_alloc->page;
		get_page(page);

		skb_frags[i].page = page;
		skb_frags[i].page_offset = page_alloc->offset;
		page_alloc->offset += frag_info->frag_stride;
	}
	dma = dma_map_single(priv->ddev, page_address(skb_frags[i].page) +
			     skb_frags[i].page_offset, frag_info->frag_size,
			     PCI_DMA_FROMDEVICE);
	if (unlikely(dma_mapping_error(priv->ddev, dma))) {
		en_err(priv, "Failed dma mapping page for RX buffer\n");
		put_page(page);
		if (new_page)
			page_alloc->offset = frag_info->last_offset;
		else
			page_alloc->offset -= frag_info->frag_stride;
		return -EFAULT;
	}
	rx_desc->data[i].addr = cpu_to_be64(dma);
	return 0;
}

static int mlx4_en_init_allocator(struct mlx4_en_priv *priv,
				  struct mlx4_en_rx_ring *ring)
{
	struct mlx4_en_rx_alloc *page_alloc;
	int i;

	for (i = 0; i < priv->num_frags; i++) {
		page_alloc = &ring->page_alloc[i];

		page_alloc->page = alloc_pages_node(ring->numa_node ,
						 GFP_ATOMIC | __GFP_COMP,
						MLX4_EN_ALLOC_ORDER);
		if (!page_alloc->page)
			page_alloc->page = alloc_pages(GFP_ATOMIC | __GFP_COMP,
					       MLX4_EN_ALLOC_ORDER);

		if (!page_alloc->page)
			goto out;

		page_alloc->offset = priv->frag_info[i].frag_align;
		en_dbg(DRV, priv, "Initialized allocator:%d with page:%p\n",
		       i, page_alloc->page);
	}
	return 0;

out:
	while (i--) {
		page_alloc = &ring->page_alloc[i];
		put_page(page_alloc->page);
		page_alloc->page = NULL;
	}
	return -ENOMEM;
}

static void mlx4_en_destroy_allocator(struct mlx4_en_priv *priv,
				      struct mlx4_en_rx_ring *ring)
{
	struct mlx4_en_rx_alloc *page_alloc;
	int i;

	for (i = 0; i < priv->num_frags; i++) {
		page_alloc = &ring->page_alloc[i];
		en_dbg(DRV, priv, "Freeing allocator:%d count:%d\n",
		       i, page_count(page_alloc->page));

		put_page(page_alloc->page);
		page_alloc->page = NULL;
	}
}

static void mlx4_en_init_rx_desc(struct mlx4_en_priv *priv,
				 struct mlx4_en_rx_ring *ring, int index)
{
	struct mlx4_en_rx_desc *rx_desc = ring->buf + ring->stride * index;
	struct skb_frag_struct *skb_frags = ring->rx_info +
					    (index << priv->log_rx_info);
	int possible_frags;
	int i;

	/* Set size and memtype fields */
	for (i = 0; i < priv->num_frags; i++) {
		skb_frags[i].size = priv->frag_info[i].frag_size;
		rx_desc->data[i].byte_count =
			cpu_to_be32(priv->frag_info[i].frag_size);
		rx_desc->data[i].lkey = cpu_to_be32(priv->mdev->mr.key);
	}

	/* If the number of used fragments does not fill up the ring stride,
	 * remaining (unused) fragments must be padded with null address/size
	 * and a special memory key */
	possible_frags = (ring->stride - sizeof(struct mlx4_en_rx_desc)) / DS_SIZE;
	for (i = priv->num_frags; i < possible_frags; i++) {
		rx_desc->data[i].byte_count = 0;
		rx_desc->data[i].lkey = cpu_to_be32(MLX4_EN_MEMTYPE_PAD);
		rx_desc->data[i].addr = 0;
	}
}

static int mlx4_en_prepare_rx_desc(struct mlx4_en_priv *priv,
				   struct mlx4_en_rx_ring *ring, int index)
{
	struct mlx4_en_rx_desc *rx_desc = ring->buf + (index * ring->stride);
	struct skb_frag_struct *skb_frags = ring->rx_info +
					    (index << priv->log_rx_info);
	int i;

	if (!ring->skbs[index]) {
		ring->skbs[index] = __netdev_alloc_skb(priv->dev,
						       SMALL_PACKET_SIZE + NET_IP_ALIGN,
						       GFP_ATOMIC);
		if (unlikely(!ring->skbs[index])) {
			en_dbg(RX_ERR, priv, "Failed allocating skb\n");
			return -ENOMEM;
		}
		skb_reserve(ring->skbs[index], NET_IP_ALIGN);
	}

	for (i = 0; i < priv->num_frags; i++) {
		if (!skb_frags[i].page) {
			if (mlx4_en_alloc_frag(priv, rx_desc, skb_frags,
					       ring->page_alloc, i))
				goto err;
		}
	}

	return 0;

err:
	while (i--) {
		put_page(skb_frags[i].page);
		skb_frags[i].page = NULL;
	}
	kfree_skb(ring->skbs[index]);
	ring->skbs[index] = NULL;
	return -ENOMEM;
}

static inline void mlx4_en_update_rx_prod_db(struct mlx4_en_rx_ring *ring)
{
	*ring->wqres.db.db = cpu_to_be32(ring->prod & 0xffff);
}

static void mlx4_en_free_rx_desc(struct mlx4_en_priv *priv,
				 struct mlx4_en_rx_ring *ring,
				 int index)
{
	struct skb_frag_struct *skb_frags;
	struct mlx4_en_rx_desc *rx_desc = ring->buf + (index << ring->log_stride);
	dma_addr_t dma;
	int nr;

	skb_frags = ring->rx_info + (index << priv->log_rx_info);
	for (nr = 0; nr < priv->num_frags; nr++) {
		if (skb_frags[nr].page) {
			en_dbg(DRV, priv, "Freeing fragment:%d\n", nr);
			dma = be64_to_cpu(rx_desc->data[nr].addr);

			en_dbg(DRV, priv, "Unmaping buffer at dma:0x%llx\n", (u64) dma);
			dma_unmap_single(priv->ddev, dma, skb_frags[nr].size,
					 PCI_DMA_FROMDEVICE);
			put_page(skb_frags[nr].page);
			memset(&skb_frags[nr], 0, sizeof(struct skb_frag_struct));
		}
	}
	if (ring->skbs[index])
		kfree_skb(ring->skbs[index]);
	ring->skbs[index] = NULL;
}

static int mlx4_en_fill_rx_buffers(struct mlx4_en_priv *priv)
{
	struct mlx4_en_rx_ring *ring;
	int ring_ind;
	int buf_ind;
	int new_size;
	int err;

	for (buf_ind = 0; buf_ind < priv->prof->rx_ring_size; buf_ind++) {
		for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++) {
			ring = priv->rx_ring[ring_ind];

			err = mlx4_en_prepare_rx_desc(priv, ring,
						      ring->actual_size);
                        if (err) {
				if (ring->actual_size < MLX4_EN_MIN_RX_SIZE) {
					en_err(priv, "Failed to allocate "
						     "enough rx buffers\n");
					return -ENOMEM;
				} else {
					new_size = rounddown_pow_of_two(ring->actual_size);
					en_warn(priv, "Only %d buffers allocated "
						      "reducing ring size to %d\n",
						ring->actual_size, new_size);
					goto reduce_rings;
				}
			}
			ring->actual_size++;
			ring->prod++;
		}
	}
	return 0;

reduce_rings:
	for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++) {
		ring = priv->rx_ring[ring_ind];
		while (ring->actual_size > new_size) {
			ring->actual_size--;
			ring->prod--;
			mlx4_en_free_rx_desc(priv, ring, ring->actual_size);
		}
	}

	return 0;
}

static void mlx4_en_free_rx_buf(struct mlx4_en_priv *priv,
				struct mlx4_en_rx_ring *ring)
{
	int index;

	en_dbg(DRV, priv, "Freeing Rx buf - cons:%d prod:%d\n",
	       ring->cons, ring->prod);

	/* Unmap and free Rx buffers */
	BUG_ON((u32) (ring->prod - ring->cons) > ring->actual_size);
	while (ring->cons != ring->prod) {
		index = ring->cons & ring->size_mask;
		en_dbg(DRV, priv, "Processing descriptor:%d\n", index);
		mlx4_en_free_rx_desc(priv, ring, index);
		++ring->cons;
	}
}


int mlx4_en_create_rx_ring(struct mlx4_en_priv *priv,
			   struct mlx4_en_rx_ring *ring, u32 size)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	int err;
	int tmp;

	ring->prod = 0;
	ring->cons = 0;
	ring->size = size;
	ring->size_mask = size - 1;
	ring->stride = roundup_pow_of_two(sizeof(struct mlx4_en_rx_desc) +
					  DS_SIZE * MLX4_EN_MAX_RX_FRAGS);
	ring->log_stride = ffs(ring->stride) - 1;
	ring->buf_size = ring->size * ring->stride + TXBB_SIZE;

	tmp = size * roundup_pow_of_two(MLX4_EN_MAX_RX_FRAGS *
					sizeof(struct skb_frag_struct));

	ring->rx_info = vmalloc_node(tmp, ring->numa_node);
	if (!ring->rx_info) {
		en_err(priv, "Failed allocating rx_info ring\n");
		return -ENOMEM;
	}
	en_dbg(DRV, priv, "Allocated rx_info ring at addr:%p size:%d\n",
		 ring->rx_info, tmp);
	memset(ring->rx_info, 0, tmp);

	tmp = size * sizeof(struct sk_buff *);
	ring->skbs = vmalloc_node(tmp, ring->numa_node);
	if (!ring->skbs) {
		en_err(priv, "failed to allocate skb pointers\n");
		err = -ENOMEM;
		goto err_ring;
	}
	memset(ring->skbs, 0, tmp);

	err = mlx4_alloc_hwq_res(mdev->dev, &ring->wqres,
				ring->buf_size, 2 * PAGE_SIZE, ring->numa_node);
	if (err)
		goto err_skbs;

	err = mlx4_en_map_buffer(&ring->wqres.buf, ring->numa_node);
	if (err) {
		en_err(priv, "Failed to map RX buffer\n");
		goto err_hwq;
	}
	ring->buf = ring->wqres.buf.direct.buf;

	/* Allocate LRO sessions */
	err =  mlx4_en_lro_init(ring, MLX4_EN_MAX_LRO_DESCRIPTORS);
	if (err) {
		en_err(priv, "Failed allocating lro sessions\n");
		goto err_map;
	}

	return 0;

err_map:
	mlx4_en_unmap_buffer(&ring->wqres.buf);
err_hwq:
	mlx4_free_hwq_res(mdev->dev, &ring->wqres, ring->buf_size);
err_skbs:
	vfree(ring->skbs);
err_ring:
	vfree(ring->rx_info);
	ring->rx_info = NULL;
	return err;
}

int mlx4_en_activate_rx_rings(struct mlx4_en_priv *priv)
{
	struct mlx4_en_rx_ring *ring;
	int i;
	int ring_ind;
	int err;
	int stride = roundup_pow_of_two(sizeof(struct mlx4_en_rx_desc) +
					DS_SIZE * priv->num_frags);

	for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++) {
		ring = priv->rx_ring[ring_ind];

		ring->prod = 0;
		ring->cons = 0;
		ring->actual_size = 0;
		ring->cqn = priv->rx_cq[ring_ind]->mcq.cqn;

		ring->stride = stride;
		if (ring->stride <= TXBB_SIZE)
			ring->buf += TXBB_SIZE;

		ring->log_stride = ffs(ring->stride) - 1;
		ring->buf_size = ring->size * ring->stride;

		memset(ring->buf, 0, ring->buf_size);
		memset(ring->skbs, 0, ring->size * sizeof(struct sk_buff *));
		memset(ring->rx_info, 0, ring->size * priv->num_frags *
					 sizeof(struct skb_frag_struct));
		mlx4_en_update_rx_prod_db(ring);

		/* Initailize all descriptors */
		for (i = 0; i < ring->size; i++)
			mlx4_en_init_rx_desc(priv, ring, i);
	
		/* Initialize page allocators */
		err = mlx4_en_init_allocator(priv, ring);
		if (err) {
			en_err(priv, "Failed initializing ring allocator\n");
			ring_ind--;
			goto err_allocator;
		}
	}
	err = mlx4_en_fill_rx_buffers(priv);
	if (err)
		goto err_buffers;

	for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++) {
		ring = priv->rx_ring[ring_ind];

		ring->size_mask = ring->actual_size - 1;
		mlx4_en_update_rx_prod_db(ring);
	}

	return 0;

err_buffers:
	for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++)
		mlx4_en_free_rx_buf(priv, priv->rx_ring[ring_ind]);

	ring_ind = priv->rx_ring_num - 1;
err_allocator:
	while (ring_ind >= 0) {
		mlx4_en_destroy_allocator(priv, priv->rx_ring[ring_ind]);
		ring_ind--;
	}
	return err;
}

void mlx4_en_destroy_rx_ring(struct mlx4_en_priv *priv,
			     struct mlx4_en_rx_ring *ring)
{
	struct mlx4_en_dev *mdev = priv->mdev;

	mlx4_en_lro_destroy(ring);
	mlx4_en_unmap_buffer(&ring->wqres.buf);
	mlx4_free_hwq_res(mdev->dev, &ring->wqres, ring->buf_size + TXBB_SIZE);
	vfree(ring->skbs);
	vfree(ring->rx_info);
	ring->rx_info = NULL;
}

void mlx4_en_deactivate_rx_ring(struct mlx4_en_priv *priv,
				struct mlx4_en_rx_ring *ring)
{
	mlx4_en_free_rx_buf(priv, ring);
	if (ring->stride <= TXBB_SIZE)
		ring->buf -= TXBB_SIZE;
	mlx4_en_destroy_allocator(priv, ring);
}


/* Unmap a completed descriptor and free unused pages */
int mlx4_en_complete_rx_desc(struct mlx4_en_priv *priv,
			     struct mlx4_en_rx_desc *rx_desc,
			     struct skb_frag_struct *skb_frags,
			     struct skb_frag_struct *skb_frags_rx,
			     struct mlx4_en_rx_alloc *page_alloc,
			     int length)
{
	struct mlx4_en_frag_info *frag_info;
	int nr;
	dma_addr_t dma;

	/* Collect used fragments while replacing them in the HW descirptors */
	for (nr = 0; nr < priv->num_frags; nr++) {
		frag_info = &priv->frag_info[nr];
		if (length <= frag_info->frag_prefix_size)
			break;

		/* Save page reference in skb */
		skb_frags_rx[nr].page = skb_frags[nr].page;
		skb_frags_rx[nr].size = skb_frags[nr].size;
		skb_frags_rx[nr].page_offset = skb_frags[nr].page_offset;
		/* set the current fragment as invalid, to be allocated later */
		skb_frags[nr].page = NULL;
		dma = be64_to_cpu(rx_desc->data[nr].addr);
		dma_unmap_single(priv->ddev, dma, skb_frags_rx[nr].size,
				 PCI_DMA_FROMDEVICE);
	}
	/* Adjust size of last fragment to match actual length */
	skb_frags_rx[nr - 1].size = length -
		priv->frag_info[nr - 1].frag_prefix_size;
	return nr;
}


struct sk_buff *mlx4_en_rx_skb(struct mlx4_en_priv *priv,
			       struct mlx4_en_rx_desc *rx_desc,
			       struct skb_frag_struct *skb_frags,
			       struct mlx4_en_rx_alloc *page_alloc,
			       struct mlx4_en_rx_ring *ring,
			       unsigned int length, u32 index)
{
	struct sk_buff *skb;
	void *va;
	int used_frags;

	skb = ring->skbs[index];
	skb->len = length;
	skb->truesize = length + sizeof(struct sk_buff);
	/*
	 * Mark the entry in ring skbs array as invalid
	 * New skb should be allocated during repost operation
	 */
	ring->skbs[index] = NULL;

	/* Get pointer to first fragment so we could copy the headers into the
	 * (linear part of the) skb */
	va = page_address(skb_frags[0].page) + skb_frags[0].page_offset;

	if (length <= SMALL_PACKET_SIZE) {
		/* We are copying all relevant data to the skb */
		skb_copy_to_linear_data(skb, va, length);
		skb->tail += length;
	} else {

		/* Move relevant fragments to skb */
		used_frags = mlx4_en_complete_rx_desc(priv, rx_desc, skb_frags,
						      skb_shinfo(skb)->frags,
						      page_alloc, length);
		skb_shinfo(skb)->nr_frags = used_frags;

		/* Copy headers into the skb linear buffer */
		memcpy(skb->data, va, HEADER_COPY_SIZE);
		skb->tail += HEADER_COPY_SIZE;

		/* Skip headers in first fragment */
		skb_shinfo(skb)->frags[0].page_offset += HEADER_COPY_SIZE;

		/* Adjust size of first fragment */
		skb_shinfo(skb)->frags[0].size -= HEADER_COPY_SIZE;
		skb->data_len = length - HEADER_COPY_SIZE;
	}
	return skb;
}

static inline int invalid_cqe(struct mlx4_cqe *cqe)
{
	/* Drop packet on bad receive or bad checksum */
	if (unlikely((cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) ==
		     MLX4_CQE_OPCODE_ERROR)) {
		return 1;
	}
	if (unlikely(cqe->badfcs_enc & MLX4_CQE_BAD_FCS)) {
		return 1;;
	}

	return 0;
}

static void validate_loopback(struct mlx4_en_priv *priv, struct sk_buff *skb)
{
	int i;
	int offset = ETH_HLEN;

	for (i = 0; i < MLX4_LOOPBACK_TEST_PAYLOAD; i++, offset++) {
		if (*(skb->data + offset) != (unsigned char) (i & 0xff))
			goto out_loopback;
	}
	/* Loopback found */
	priv->loopback_ok = 1;

out_loopback:
	dev_kfree_skb_any(skb);
}

int mlx4_en_process_rx_cq(struct net_device *dev, struct mlx4_en_cq *cq, int budget)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_cqe *cqe;
	struct mlx4_cq *mcq = &cq->mcq;
	struct mlx4_en_rx_ring *ring = priv->rx_ring[cq->ring];
	struct skb_frag_struct *skb_frags;
	struct mlx4_en_rx_desc *rx_desc;
	struct sk_buff *skb;
	struct net_device_stats *stats = &priv->stats;
	int index;
	unsigned int length;
	int polled = 0;
	int ip_summed;
	int factor = priv->cqe_factor;
	u32 cons_index = mcq->cons_index;
	u32 size_mask = ring->size_mask;
	int size = cq->size;
	struct mlx4_cqe *buf = cq->buf;
	u32 csum_none = 0, csum_ok = 0;
	bool lro = !!(dev->features & NETIF_F_LRO);

	if (!priv->port_up)
		return 0;

	/* We assume a 1:1 mapping between CQEs and Rx descriptors, so Rx
	 * descriptor offset can be deduced from the CQE index instead of
	 * reading 'cqe->index' */
	index = cons_index & size_mask;
	cqe = &cq->buf[(index << factor) + factor];

	/* Process all completed CQEs */
	while (XNOR(cqe->owner_sr_opcode & MLX4_CQE_OWNER_MASK,
		    cons_index & size)) {

		skb_frags = ring->rx_info + (index << priv->log_rx_info);
		rx_desc = ring->buf + (index << ring->log_stride);

		/*
		 * make sure we read the CQE after we read the ownership bit
		 */
		rmb();

		if (unlikely(invalid_cqe(cqe)))
			goto next;

		/*
		 * Packet is OK - process it.
		 */
		length = be32_to_cpu(cqe->byte_cnt);
		length -= ring->len_red;
		ring->bytes += length;
		ring->packets++;

		if (likely(priv->rx_csum)) {
			if ((cqe->status & cpu_to_be16(MLX4_CQE_STATUS_IPOK)) &&
			    (cqe->checksum == 0xffff)) {
				csum_ok++;
				if (lro && !mlx4_en_lro_rx(priv, ring, rx_desc,
							   skb_frags, length, cqe, index))
                                        goto next;

				/* LRO not possible, complete processing here */
				ip_summed = CHECKSUM_UNNECESSARY;
				INC_PERF_COUNTER(priv->pstats.lro_misses);
			} else {
				ip_summed = CHECKSUM_NONE;
				csum_none++;
			}
		} else {
			csum_none++;
			ip_summed = CHECKSUM_NONE;
		}

		skb = mlx4_en_rx_skb(priv, rx_desc, skb_frags,
				     ring->page_alloc, ring, length, index);
		if (!skb) {
			stats->rx_dropped++;
			goto next;
		}

                if (unlikely(priv->validate_loopback)) {
			validate_loopback(priv, skb);
			goto next;
		}

		skb->ip_summed = ip_summed;
		skb->protocol = eth_type_trans(skb, dev);
		skb_record_rx_queue(skb, cq->ring);

		/*
		 * Push it up the stack
		 * We have to check vlgrp since it is possible that vlans
		 * are not defined yet
		 */
		if (priv->vlgrp && (be32_to_cpu(cqe->vlan_my_qpn) &
				    MLX4_CQE_VLAN_PRESENT_MASK))
			vlan_hwaccel_receive_skb(skb, priv->vlgrp,
						 be16_to_cpu(cqe->sl_vid));
		else
			netif_receive_skb(skb);

next:
		++cons_index;
		index = cons_index & size_mask;
		cqe = &buf[(index << factor) + factor];
		if (++polled == budget) {
			/* We are here because we reached the NAPI budget -
			 * flush only pending LRO sessions */
			if (lro)
				mlx4_en_lro_flush(priv, ring, 0);
			goto out;
		}
	}

	/* If CQ is empty flush all LRO sessions unconditionally */
	if (lro)
		mlx4_en_lro_flush(priv, ring, 1);

out:
	AVG_PERF_COUNTER(priv->pstats.rx_coal_avg, polled);
	mcq->cons_index = cons_index;
	mlx4_cq_set_ci(mcq);
	wmb(); /* ensure HW sees CQ consumer before we post new buffers */
	ring->cons = mcq->cons_index;
	/*
	 * Repost all consumed descriptors.
	 * It is possible that we'll need to repost more the "polled" value.
	 * This can happen if we didn't succeed to repost everything in the
	 * previous round.
	 * To make sure we don't end up with an empty ring,
	 * in case allocation fails we return the "budget" value
	 * to NAPI callback to ensure we'll be called again.
	 */
	while (ring->prod < ring->cons + ring->actual_size) {
		if (mlx4_en_prepare_rx_desc(priv, ring, ring->prod & size_mask)) {
			/* Make sure we'll be called again to be able to repost */
			polled = budget;
			break;
		}
		ring->prod++;
	}
	mlx4_en_update_rx_prod_db(ring);
	ring->csum_ok += csum_ok;
	ring->csum_none += csum_none;
	return polled;
}

void mlx4_en_process_rx(struct mlx4_en_cq *cq)
{
	struct net_device *dev = cq->dev;
	int polled = 0;
	int processed = 0;

	while (polled < MLX4_EN_RX_LIMIT) {
		processed = mlx4_en_process_rx_cq(dev, cq, MLX4_EN_RX_BUDGET);
		if (processed < MLX4_EN_RX_BUDGET)
			break;
		polled += processed;
	}
}

void mlx4_en_rx_irq(struct mlx4_cq *mcq)
{
	struct mlx4_en_cq *cq = container_of(mcq, struct mlx4_en_cq, mcq);
	struct mlx4_en_priv *priv = netdev_priv(cq->dev);

	if (priv->port_up)
		napi_schedule(&cq->napi);
	else
		mlx4_en_arm_cq(priv, cq);
}

/* Rx CQ polling - called by NAPI */
int mlx4_en_poll_rx_cq(struct napi_struct *napi, int budget)
{
	struct mlx4_en_cq *cq = container_of(napi, struct mlx4_en_cq, napi);
	struct net_device *dev = cq->dev;
	struct mlx4_en_priv *priv = netdev_priv(dev);
	int done;

	done = mlx4_en_process_rx_cq(dev, cq, budget);

	/* If we used up all the quota - we're probably not done yet... */
	cq->tot_rx += done;
	if (done == budget) {
		INC_PERF_COUNTER(priv->pstats.napi_quota);
		if (cq->tot_rx >= MIN_RX_ARM) {
			napi_complete(napi);
			mlx4_en_arm_cq(priv, cq);
			cq->tot_rx = 0;
			return 0;
		}
	} else {
		/* Done for now */
		napi_complete(napi);
		mlx4_en_arm_cq(priv, cq);
		cq->tot_rx = 0;
		return done;
	}
	return budget;
}


/* Calculate the last offset position that accomodates a full fragment
 * (assuming fagment size = stride-align) */
static int mlx4_en_last_alloc_offset(struct mlx4_en_priv *priv, u16 stride, u16 align)
{
	u16 res = MLX4_EN_ALLOC_SIZE % stride;
	u16 offset = MLX4_EN_ALLOC_SIZE - stride - res + align;

	en_dbg(DRV, priv, "Calculated last offset for stride:%d align:%d "
			    "res:%d offset:%d\n", stride, align, res, offset);
	return offset;
}


static int frag_sizes[] = {
	FRAG_SZ0,
	FRAG_SZ1,
	FRAG_SZ2,
	FRAG_SZ3
};

void mlx4_en_calc_rx_buf(struct net_device *dev)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	int eff_mtu = dev->mtu + ETH_HLEN + VLAN_HLEN + ETH_LLC_SNAP_SIZE;
	int buf_size = 0;
	int i = 0;

	while (buf_size < eff_mtu) {
		priv->frag_info[i].frag_size =
			(eff_mtu > buf_size + frag_sizes[i]) ?
				frag_sizes[i] : eff_mtu - buf_size;
		priv->frag_info[i].frag_prefix_size = buf_size;
		if (!i)	{
			priv->frag_info[i].frag_align = 0;
			priv->frag_info[i].frag_stride =
				ALIGN(frag_sizes[i], SMP_CACHE_BYTES);
		} else {
			priv->frag_info[i].frag_align = 0;
			priv->frag_info[i].frag_stride =
				ALIGN(frag_sizes[i], SMP_CACHE_BYTES);
		}
		priv->frag_info[i].last_offset = mlx4_en_last_alloc_offset(
						priv, priv->frag_info[i].frag_stride,
						priv->frag_info[i].frag_align);
		buf_size += priv->frag_info[i].frag_size;
		i++;
	}

	priv->num_frags = i;
	priv->rx_skb_size = eff_mtu;
	priv->log_rx_info = ROUNDUP_LOG2(i * sizeof(struct skb_frag_struct));

	en_dbg(DRV, priv, "Rx buffer scatter-list (effective-mtu:%d "
		  "num_frags:%d):\n", eff_mtu, priv->num_frags);
	for (i = 0; i < priv->num_frags; i++) {
		en_dbg(DRV, priv, "  frag:%d - size:%d prefix:%d align:%d "
				"stride:%d last_offset:%d\n", i,
				priv->frag_info[i].frag_size,
				priv->frag_info[i].frag_prefix_size,
				priv->frag_info[i].frag_align,
				priv->frag_info[i].frag_stride,
				priv->frag_info[i].last_offset);
	}
}

/* RSS related functions */

static int mlx4_en_config_rss_qp(struct mlx4_en_priv *priv, int qpn,
				 struct mlx4_en_rx_ring *ring,
				 enum mlx4_qp_state *state,
				 struct mlx4_qp *qp)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_qp_context *context;
	int err = 0;

	context = kmalloc(sizeof *context , GFP_KERNEL);
	if (!context) {
		en_err(priv, "Failed to allocate qp context\n");
		return -ENOMEM;
	}

	err = mlx4_qp_alloc(mdev->dev, qpn, qp);
	if (err) {
		en_err(priv, "Failed to allocate qp #%x\n", qpn);
		goto out;
	}
	qp->event = mlx4_en_sqp_event;

	memset(context, 0, sizeof *context);
	mlx4_en_fill_qp_context(priv, ring->actual_size, ring->stride, 0, 0,
				qpn, ring->cqn, context);
	context->db_rec_addr = cpu_to_be64(ring->wqres.db.dma);

	if (mdev->dev->caps.flags & (1ull << 34)) {
		context->param3 |= cpu_to_be32(1 << 29);
		ring->len_red = 4;
	} else
		ring->len_red = 0;

	err = mlx4_qp_to_ready(mdev->dev, &ring->wqres.mtt, context, qp, state);
	if (err) {
		mlx4_qp_remove(mdev->dev, qp);
		mlx4_qp_free(mdev->dev, qp);
	}
	mlx4_en_update_rx_prod_db(ring);
out:
	kfree(context);
	return err;
}

/* Allocate rx qp's and configure them according to rss map */
int mlx4_en_config_rss_steer(struct mlx4_en_priv *priv)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_rss_map *rss_map = &priv->rss_map;
	struct mlx4_qp_context context;
	struct mlx4_rss_context *rss_context;
	void *ptr;
	u8 rss_mask = (MLX4_RSS_IPV4 | MLX4_RSS_TCP_IPV4 | MLX4_RSS_IPV6 |
		       MLX4_RSS_TCP_IPV6);
	int i, qpn;
	int err = 0;
	int good_qps = 0;

	if (priv->rx_ring_num == 1) {
		en_dbg(DRV, priv, "Configuring single RX ring (without RSS)\n");
		err = mlx4_en_config_rss_qp(priv, priv->base_qpn,
					    priv->rx_ring[0],
					    &rss_map->state[0],
					    &rss_map->qps[0]);
		if (err)
			en_err(priv, "Failed to configure single RX ring\n");
		rss_map->indir_qp.event = rss_map->qps[0].event;
		rss_map->indir_qp.qpn = rss_map->qps[0].qpn;
		rss_map->indir_qp.refcount = rss_map->qps[0].refcount;
		rss_map->indir_qp.free = rss_map->qps[0].free;
		return err;
	}

	en_dbg(DRV, priv, "Configuring rss steering\n");
	err = mlx4_qp_reserve_range(mdev->dev, priv->rx_ring_num,
				    roundup_pow_of_two(priv->rx_ring_num),
				    &rss_map->base_qpn, 0);
	if (err) {
		en_err(priv, "Failed reserving %d qps\n", priv->rx_ring_num);
		return err;
	}

	for (i = 0; i < priv->rx_ring_num; i++) {
		qpn = rss_map->base_qpn + i;
		err = mlx4_en_config_rss_qp(priv, qpn,
					    priv->rx_ring[i],
					    &rss_map->state[i],
					    &rss_map->qps[i]);
		if (err)
			goto rss_err;

		++good_qps;
	}

	/* Configure RSS indirection qp */
	err = mlx4_qp_alloc(mdev->dev, priv->base_qpn, &rss_map->indir_qp);
	if (err) {
		en_err(priv, "Failed to allocate RSS indirection QP\n");
		goto rss_err;
	}
	rss_map->indir_qp.event = mlx4_en_sqp_event;
	mlx4_en_fill_qp_context(priv, 0, 0, 0, 1, priv->base_qpn,
				priv->rx_ring[0]->cqn, &context);

	ptr = ((void *) &context) + offsetof(struct mlx4_qp_context, pri_path)
					+ MLX4_RSS_OFFSET_IN_QPC_PRI_PATH;
	rss_context = (struct mlx4_rss_context *) ptr;
	rss_context->base_qpn = cpu_to_be32(ilog2(priv->rx_ring_num) << 24 |
					    (rss_map->base_qpn));

	rss_context->default_qpn = cpu_to_be32(rss_map->base_qpn);
	if (priv->mdev->profile.udp_rss) {
		rss_mask |=  MLX4_RSS_UDP_IPV4 | MLX4_RSS_UDP_IPV6;
		rss_context->base_qpn_udp = rss_context->default_qpn;
	}

	rss_context->flags = rss_mask;

	err = mlx4_qp_to_ready(mdev->dev, &priv->res.mtt, &context,
			       &rss_map->indir_qp, &rss_map->indir_state);
	if (err)
		goto indir_err;

	return 0;

indir_err:
	mlx4_qp_modify(mdev->dev, NULL, rss_map->indir_state,
		       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->indir_qp);
	mlx4_qp_remove(mdev->dev, &rss_map->indir_qp);
	mlx4_qp_free(mdev->dev, &rss_map->indir_qp);
rss_err:
	for (i = 0; i < good_qps; i++) {
		mlx4_qp_modify(mdev->dev, NULL, rss_map->state[i],
			       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->qps[i]);
		mlx4_qp_remove(mdev->dev, &rss_map->qps[i]);
		mlx4_qp_free(mdev->dev, &rss_map->qps[i]);
	}
	mlx4_qp_release_range(mdev->dev, rss_map->base_qpn, priv->rx_ring_num);
	return err;
}

void mlx4_en_release_rss_steer(struct mlx4_en_priv *priv)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_rss_map *rss_map = &priv->rss_map;
	int i;

	if (priv->rx_ring_num == 1) {
		mlx4_qp_modify(mdev->dev, NULL, rss_map->state[0],
			       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->qps[0]);
		mlx4_qp_remove(mdev->dev, &rss_map->qps[0]);
		mlx4_qp_free(mdev->dev, &rss_map->qps[0]);
		return;
	}

	mlx4_qp_modify(mdev->dev, NULL, rss_map->indir_state,
		       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->indir_qp);
	mlx4_qp_remove(mdev->dev, &rss_map->indir_qp);
	mlx4_qp_free(mdev->dev, &rss_map->indir_qp);

	for (i = 0; i < priv->rx_ring_num; i++) {
		mlx4_qp_modify(mdev->dev, NULL, rss_map->state[i],
			       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->qps[i]);
		mlx4_qp_remove(mdev->dev, &rss_map->qps[i]);
		mlx4_qp_free(mdev->dev, &rss_map->qps[i]);
	}
	mlx4_qp_release_range(mdev->dev, rss_map->base_qpn, priv->rx_ring_num);
}




