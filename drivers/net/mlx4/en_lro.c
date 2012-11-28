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

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/if_vlan.h>
#include <linux/delay.h>

#include "mlx4_en.h"

#define IPV4_VERSION 0x4
#define IPV6_VERSION 0x6

/* LRO hash function - using sum of source and destination port LSBs is
 * good enough */
#define LRO_INDEX(th, size) \
	((*((u8 *) &th->source + 1) + *((u8 *) &th->dest + 1)) & (size - 1))

/* #define CONFIG_MLX4_EN_DEBUG_LRO */

#ifdef CONFIG_MLX4_EN_DEBUG_LRO
static void mlx4_en_lro_validate(struct mlx4_en_priv *priv, struct mlx4_en_lro *lro)
{
	int i;
	int size, size2;
	struct sk_buff *skb = lro->skb;
	skb_frag_t *frags;
	int len, len2;
	int cur_skb = 0;

	/* Sum fragment sizes of first skb */
	len = skb->len;
	size = skb_headlen(skb);
	frags = skb_shinfo(skb)->frags;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		size += frags[i].size;

	/* Add in fragments of linked skb's */
	skb = skb_shinfo(skb)->frag_list;
	while (skb) {
		cur_skb++;
		len2 = skb->len;
		if (skb_headlen(skb)) {
			mlx4_err(priv->mdev, "Bad LRO format: non-zero headlen "
				  "in fraglist (skb:%d)\n", cur_skb);
			return;
		}

		size2 = 0;
		frags = skb_shinfo(skb)->frags;
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
			size2 += frags[i].size;

		if (size2 != len2) {
			mlx4_err(priv->mdev, "Bad skb size:%d in LRO fraglist. "
				 "Expected:%d (skb:%d)\n", size2, len2, cur_skb);
			return;
		}
		size += size2;
		skb = skb->next;
	}

	if (size != len)
		mlx4_err(priv->mdev, "Bad LRO size:%d expected:%d\n", size, len);
}
#endif /* MLX4_EN_DEBUG_LRO */

/**
 *	mlx4_en_lro_flush_single - push the lro packet up the stack
 *	@priv: private data of net_device
 *	@ring: RX ring we currently operate on
 *	@lro: lro session to flush
 *
 *	Finalize skb by setting it's size and updating IP and TCP
 *	headers.
 */
static void mlx4_en_lro_flush_single(struct mlx4_en_priv *priv,
		   struct mlx4_en_rx_ring *ring, struct mlx4_en_lro *lro)
{
	struct sk_buff *skb = lro->skb;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct tcphdr *th;
	unsigned int headlen = skb_headlen(skb);
	__wsum tcp_hdr_csum;
	u32 *ts;

	if (lro->version == IPV4_VERSION) {
		iph = (struct iphdr *) skb->data;
		th = (struct tcphdr *)(iph + 1);

		/* Update IP length and checksum */
		iph->tot_len = htons(lro->tot_len);
		iph->check = 0;
		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

		/* TCP + IPv4 header checksum */
		th->check = 0;
		tcp_hdr_csum = csum_partial((u8 *)th, th->doff << 2, 0);
		lro->data_csum = csum_add(lro->data_csum, tcp_hdr_csum);
		th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				      lro->tot_len - (iph->ihl << 2),
				      IPPROTO_TCP, lro->data_csum);
	} else {
		ipv6h = (struct ipv6hdr *) skb->data;
		th = (struct tcphdr *)(ipv6h + 1);

		/* Update IP length */
		ipv6h->payload_len = htons(lro->tot_len -
					   sizeof(struct ipv6hdr));

		/* TCP + IPv6 header checksum */
		th->check = 0;
		tcp_hdr_csum = csum_partial((u8 *)th, th->doff << 2, 0);
		lro->data_csum = csum_add(lro->data_csum, tcp_hdr_csum);
		th->check = csum_ipv6_magic(&ipv6h->saddr, &ipv6h->daddr,
					    lro->tot_len - sizeof(*ipv6h),
					    IPPROTO_TCP, lro->data_csum);
	}

	/* Update latest TCP ack, window, psh, and timestamp */
	th->ack_seq = lro->ack_seq;
	th->window = lro->window;
	th->psh = !!lro->psh;
	if (lro->has_timestamp) {
		ts = (u32 *) (th + 1);
		ts[1] = htonl(lro->tsval);
		ts[2] = lro->tsecr;
	}

	/* Update skb */
	skb->len = lro->tot_len;
	skb->data_len = lro->tot_len - headlen;
	skb->truesize = skb->len + sizeof(struct sk_buff);
	skb_shinfo(skb)->gso_size = lro->mss;
	skb_shinfo(skb)->gso_type |= SKB_GSO_TCPV4;

#ifdef CONFIG_MLX4_EN_DEBUG_LRO
	mlx4_en_lro_validate(priv, lro);
#endif /* CONFIG_MLX4_EN_DEBUG_LRO */

       /* Push it up the stack */
       if (priv->vlgrp && lro->has_vlan)
	       vlan_hwaccel_receive_skb(skb, priv->vlgrp,
					be16_to_cpu(lro->vlan_prio));
       else
	       netif_receive_skb(skb);
       priv->dev->last_rx = jiffies;

	/* Increment stats */
	priv->port_stats.lro_flushed++;

	/* Move session back to the free list */
	hlist_del(&lro->node);
	hlist_del(&lro->flush_node);
	hlist_add_head(&lro->node, &ring->lro_free);
}

/**
 *	mlx4_en_lro_flush - flush expired lro sessions
 *	@priv: private data of net_device
 *	@ring: RX ring we currently operate on
 *	@all: if set will flush all lro sessions
 *
 *	Check expired (or all) lro sessions and push them up the stack
 */
void mlx4_en_lro_flush(struct mlx4_en_priv *priv, struct mlx4_en_rx_ring *ring, u8 all)
{
	struct mlx4_en_lro *lro;
	struct hlist_node *node, *tmp;

	hlist_for_each_entry_safe(lro, node, tmp, &ring->lro_flush, flush_node) {
		if (all || time_after(jiffies, lro->expires))
			mlx4_en_lro_flush_single(priv, ring, lro);
	}
}

/**
 *	mlx4_en_lro_append - append a packet to lro session
 *	@priv: private data of net_device
 *	@lro: lro session to append the packet to
 *	@rx_desc: RX descriptor that contains WQE dma address
 *	@skb_frags: an array of skb_frags that contain actual data
 *	@page_alloc: replacement pages
 *	@data_len: length of data only, without headers
 *	@hlen: length of all headers
 *
 *	Returns 0 if packet appened succesfully
 */
static inline int mlx4_en_lro_append(struct mlx4_en_priv *priv,
				   struct mlx4_en_lro *lro,
				   struct mlx4_en_rx_desc *rx_desc,
				   struct skb_frag_struct *skb_frags,
				   struct mlx4_en_rx_alloc *page_alloc,
				   unsigned int data_len,
				   int hlen)
{
	struct sk_buff *skb = lro->skb_last;
	struct skb_shared_info *info;
	struct skb_frag_struct *frags_copy;
	int nr_frags;

	if (skb_shinfo(skb)->nr_frags + priv->num_frags > MAX_SKB_FRAGS)
		return -ENOMEM;

	info = skb_shinfo(skb);

	/* Copy fragments from descriptor ring to skb */
	frags_copy = info->frags + info->nr_frags;
	nr_frags = mlx4_en_complete_rx_desc(priv, rx_desc, skb_frags,
						frags_copy,
						page_alloc,
						data_len + hlen);

	/* Skip over headers */
	frags_copy[0].page_offset += hlen;

	if (nr_frags == 1)
		frags_copy[0].size = data_len;
	else {
		/* Adjust size of last fragment to match packet length.
		 * Note: if this fragment is also the first one, the
		 *       operation is completed in the next line */
		frags_copy[nr_frags - 1].size = hlen + data_len -
				priv->frag_info[nr_frags - 1].frag_prefix_size;

		/* Adjust size of first fragment */
		frags_copy[0].size -= hlen;
	}

	/* Update skb bookkeeping */
	skb->len += data_len;
	skb->data_len += data_len;
	info->nr_frags += nr_frags;
	return 0;
}

/**
 *	mlx4_en_lro_find_session - find lro session that matches src/dst
 *	@mdev: mlx4_en_dev that we operate on
 *	@priv: private data of net_device
 *	@ring: RX ring we currently operate on
 *	@iph: IPv4 header to use if applied
 *	@ipv6h: IPv6 header to use if applied
 *	@th: TCP header with src/dst ports
 *	@version: the IPvX version to use
 *
 *	Returns the lro sessions matching src/dst IP and ports
 *	uses the IP version specified in @version
 */
static inline struct mlx4_en_lro *mlx4_en_lro_find_session(struct mlx4_en_dev *mdev,
						       struct mlx4_en_rx_ring *ring,
						       struct iphdr *iph,
						       struct ipv6hdr *ipv6h,
						       struct tcphdr *th,
						       int version)
{
	struct mlx4_en_lro *lro;
	struct hlist_node *node;
	int index = LRO_INDEX(th, mdev->profile.num_lro);
	struct hlist_head *list = &ring->lro_hash[index];

	if (version == IPV4_VERSION)
		hlist_for_each_entry(lro, node, list, node) {
			if (lro->sport_dport == *((u32 *) &th->source) &&
			    lro->saddr == iph->saddr &&
			    lro->daddr == iph->daddr)
				return lro;
		}
	else
		hlist_for_each_entry(lro, node, list, node) {
			if (lro->sport_dport == *((u32 *) &th->source) &&
			    ipv6_addr_equal(&lro->saddr_v6, &ipv6h->saddr) &&
			    ipv6_addr_equal(&lro->daddr_v6, &ipv6h->daddr))
				return lro;
		}

	return NULL;
}

/**
 *	mlx4_en_lro_alloc_session - allocate a new lro session
 *	@ring: RX ring we currently operate on
 *
 *	Returns a new lro session or NULL if no empty sessions left
 */
static inline struct mlx4_en_lro*
mlx4_en_lro_alloc_session(struct mlx4_en_rx_ring *ring)
{
	return hlist_empty(&ring->lro_free) ? NULL :
		hlist_entry(ring->lro_free.first, struct mlx4_en_lro, node);
}

/**
 *	mlx4_en_lro_tcp_data_csum - calculate unfolded checksum
 *	@iph: IPv4 header to use if applied
 *	@ipv6h: IPv6 header to use if applied
 *	@th: TCP header with src/dst ports
 *	@len: TCP data len, no headers
 *	@version: the IPvX version to use
 *
 *	Returns the unfolded checksum for the tcp data only
 */
static __wsum mlx4_en_lro_tcp_data_csum(struct iphdr *iph,
					struct ipv6hdr *ipv6h,
					struct tcphdr *th, int len,
					u32 version)
{
	__wsum tcp_csum;
	__wsum tcp_hdr_csum;
	__wsum tcp_ps_hdr_csum;

	tcp_csum = ~csum_unfold(th->check);
	tcp_hdr_csum = csum_partial((u8 *)th, th->doff << 2, tcp_csum);

	if (version == IPV4_VERSION) {
		tcp_ps_hdr_csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
						     len + (th->doff << 2),
						     IPPROTO_TCP, 0);
	} else {
		tcp_ps_hdr_csum = csum_ipv6_magic(&ipv6h->saddr, &ipv6h->daddr,
					    len + (th->doff << 2),
					    IPPROTO_TCP, 0);
		tcp_ps_hdr_csum = csum_unfold(tcp_ps_hdr_csum);
	}

	return csum_sub(csum_sub(tcp_csum, tcp_hdr_csum),
			tcp_ps_hdr_csum);
}

/**
 *	mlx4_en_can_lro - returns true if lro supported for this CQE
 *	@status - CQE status flags
 *
 *	Returns 1 for supported lro
 */
static inline int mlx4_en_can_lro(__be16 status)
{
	static __be16 status_all;
	static __be16 status_ipv4_ipok_tcp;
	static __be16 status_ipv6_ipok_tcp;

	status_all			   = cpu_to_be16(
					     MLX4_CQE_STATUS_IPV4    |
					     MLX4_CQE_STATUS_IPV4F   |
					     MLX4_CQE_STATUS_IPV6    |
					     MLX4_CQE_STATUS_IPV4OPT |
					     MLX4_CQE_STATUS_TCP     |
					     MLX4_CQE_STATUS_UDP     |
					     MLX4_CQE_STATUS_IPOK);
	status_ipv4_ipok_tcp		   = cpu_to_be16(
					     MLX4_CQE_STATUS_IPV4    |
					     MLX4_CQE_STATUS_IPOK    |
					     MLX4_CQE_STATUS_TCP);
	status_ipv6_ipok_tcp		   = cpu_to_be16(
					     MLX4_CQE_STATUS_IPV6    |
					     MLX4_CQE_STATUS_IPOK    |
					     MLX4_CQE_STATUS_TCP);

	status &= status_all;
	return (status == status_ipv4_ipok_tcp ||
		status == status_ipv6_ipok_tcp);
}

/**
 *	mlx4_en_lro_rx - handle large recieve offload packets
 *	@priv: private data of net_device
 *	@ring: RX ring we operate on
 *	@rx_desc: RX descriptor that contains WQE dma address
 *	@skb_frags: an array of skb_frags that contain actual data
 *	@lenght: byte count in the cqe
 *	@cqe: cqe we operate on
 *
 *	Returns 0 for success
 */
int mlx4_en_lro_rx(struct mlx4_en_priv *priv, struct mlx4_en_rx_ring *ring,
					  struct mlx4_en_rx_desc *rx_desc,
					  struct skb_frag_struct *skb_frags,
					  unsigned int length,
					  struct mlx4_cqe *cqe, u32 index)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_lro *lro;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h = NULL;
	struct tcphdr *th;
	struct mlx4_en_port_stats *pstats = &priv->port_stats;
	dma_addr_t dma;
	int tcp_hlen;
	int tcp_data_len;
	int hlen;
	u16 ip_len;
	void *va;
	u32 *ts;
	u32 seq;
	u32 tsval = (u32) ~0UL;
	u32 tsecr = 0;
	u32 ack_seq;
	u16 window;
	u32 version;
	int max_lro_header;
	/* This packet is eligible for LRO if it is:
	 * - DIX Ethernet (type interpretation)
	 * - TCP/IP (v4)
	 * - without IP options
	 * - not an IP fragment
	 * - TCP/IP (v6) */
	if (!mlx4_en_can_lro(cqe->status))
			return -1;

	/* Get pointer to TCP header. We already know that the packet is DIX Ethernet/IPv4/TCP
	 * with no VLAN (HW stripped it) and no IP options */
	va = page_address(skb_frags[0].page) + skb_frags[0].page_offset;
	iph = va + ETH_HLEN;
	if (iph->version == IPV4_VERSION) {
		/* IPV4 */
		version = IPV4_VERSION;
		th = (struct tcphdr *)(iph + 1);

		/* Preset constant size fields to avoid
		   additional IP version checking later */
		hlen = sizeof(struct iphdr);
		max_lro_header = ETH_HLEN +
				 sizeof(struct iphdr) +
				 sizeof(struct tcphdr) +
				 TCPOLEN_TSTAMP_ALIGNED;
	} else {
		/*IPV6*/
		version = IPV6_VERSION;
		ipv6h = va + ETH_HLEN;
		th = (struct tcphdr *)(ipv6h + 1);

		hlen = sizeof(struct ipv6hdr);
		max_lro_header = ETH_HLEN +
				 sizeof(struct ipv6hdr) +
				 sizeof(struct tcphdr) +
				 TCPOLEN_TSTAMP_ALIGNED;
	}

	/* Synchronsize headers for processing */
	dma = be64_to_cpu(rx_desc->data[0].addr);
	dma_sync_single_range_for_cpu(&mdev->pdev->dev, dma, 0,
				      max_lro_header, DMA_FROM_DEVICE);

	/* We only handle aligned timestamp options */
	tcp_hlen = (th->doff << 2);
	if (tcp_hlen == sizeof(*th) + TCPOLEN_TSTAMP_ALIGNED) {
		ts = (u32 *) (th + 1);
		if (unlikely(*ts != htonl((TCPOPT_NOP << 24) |
					  (TCPOPT_NOP << 16) |
					  (TCPOPT_TIMESTAMP << 8) |
					  TCPOLEN_TIMESTAMP)))
			goto sync_device;
		tsval = ntohl(ts[1]);
		tsecr = ts[2];
	} else if (tcp_hlen != sizeof(*th))
		goto sync_device;


	/* At this point we know we have a TCP packet that is likely to be
	 * eligible for LRO. Therefore, see now if we have an oustanding
	 * session that corresponds to this packet so we could flush it if
	 * something still prevents LRO */
	lro = mlx4_en_lro_find_session(mdev, ring, iph, ipv6h, th, version);

	/* ensure no bits set besides ack or psh */
	if (th->fin || th->syn || th->rst || th->urg || th->ece ||
	    th->cwr || !th->ack) {
		if (lro) {
			/* First flush session to keep packets in-order */
			mlx4_en_lro_flush_single(priv, ring, lro);
		}
		goto sync_device;
	}

	/* Get IP and TCP payload length */
	if (version == IPV4_VERSION) {
		ip_len = ntohs(iph->tot_len);
		tcp_data_len = ip_len - tcp_hlen - sizeof(struct iphdr);
	} else {
		ip_len = ntohs(ipv6h->payload_len) + sizeof(struct ipv6hdr);
		tcp_data_len = ip_len - tcp_hlen - sizeof(struct ipv6hdr);
	}

	/* Verify that the frame is big enough */
	if (unlikely(length < ETH_HLEN + ip_len)) {
		en_warn(priv, "Cannot LRO - ip payload exceeds frame!\n");
		goto sync_device;
	}

	seq = ntohl(th->seq);
	if (!tcp_data_len)
		goto flush_session;

	if (lro) {
		/* Check VLAN tag */
		if (be32_to_cpu(cqe->vlan_my_qpn) & MLX4_CQE_VLAN_PRESENT_MASK) {
			if (cqe->sl_vid != lro->vlan_prio || !lro->has_vlan) {
				mlx4_en_lro_flush_single(priv, ring, lro);
				goto sync_device;
			}
		} else if (lro->has_vlan) {
			mlx4_en_lro_flush_single(priv, ring, lro);
			goto sync_device;
		}

		/* Check sequence number */
		if (unlikely(seq != lro->next_seq)) {
			mlx4_en_lro_flush_single(priv, ring, lro);
			goto sync_device;
		}

		/* If the cummulative IP length is over 64K, flush and start
		 * a new session */
		if (lro->tot_len + tcp_data_len > 0xffff) {
			mlx4_en_lro_flush_single(priv, ring, lro);
			goto new_session;
		}

		/* Check timestamps */
		if (tcp_hlen != sizeof(*th)) {
			if (unlikely(lro->tsval > tsval || !tsecr))
				goto sync_device;
		}

		window = th->window;
		ack_seq = th->ack_seq;
		if (likely(tcp_data_len)) {
			/* Append the data! */
			hlen += ETH_HLEN + tcp_hlen;
			if (mlx4_en_lro_append(priv, lro, rx_desc, skb_frags,
							ring->page_alloc,
							tcp_data_len, hlen)) {
				mlx4_en_lro_flush_single(priv, ring, lro);
				goto sync_device;
			}
		} else {
			/* No data */
			dma_sync_single_range_for_device(&mdev->pdev->dev, dma,
							 0, max_lro_header,
							 DMA_FROM_DEVICE);
		}

		/* Update session */
		lro->psh |= th->psh;
		lro->next_seq += tcp_data_len;
		lro->data_csum = csum_block_add(lro->data_csum,
					mlx4_en_lro_tcp_data_csum(iph, ipv6h,
						th, tcp_data_len, version),
					lro->tot_len);
		lro->tot_len += tcp_data_len;
		lro->tsval = tsval;
		lro->tsecr = tsecr;
		lro->ack_seq = ack_seq;
		lro->window = window;
		if (tcp_data_len > lro->mss)
			lro->mss = tcp_data_len;
		pstats->lro_aggregated++;
		if (th->psh)
			mlx4_en_lro_flush_single(priv, ring, lro);
		return 0;
	}

new_session:
	if (th->psh)
		goto sync_device;
	lro = mlx4_en_lro_alloc_session(ring);
	if (lro) {
		skb = mlx4_en_rx_skb(priv, rx_desc, skb_frags, ring->page_alloc,
				     ring, ETH_HLEN + ip_len, index);
		if (skb) {
			int index;

			/* Add in the skb */
			lro->skb = skb;
			lro->skb_last = skb;
			skb->protocol = eth_type_trans(skb, priv->dev);
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_record_rx_queue(skb, priv->rx_ring_num > 1 ? 
				(be32_to_cpu(cqe->vlan_my_qpn) & 0xffffff) - priv->rss_map.base_qpn : 0);

			/* Initialize session */
			if (version == IPV4_VERSION) {
				lro->version = IPV4_VERSION;
				lro->saddr = iph->saddr;
				lro->daddr = iph->daddr;
			} else {
				lro->version = IPV6_VERSION;
				ipv6_addr_copy(&lro->saddr_v6, &ipv6h->saddr);
				ipv6_addr_copy(&lro->daddr_v6, &ipv6h->daddr);
			}
			lro->sport_dport = *((u32 *) &th->source);

			lro->next_seq = seq + tcp_data_len;
			lro->tot_len = ip_len;
			lro->psh = th->psh;
			lro->ack_seq = th->ack_seq;
			lro->window = th->window;
			lro->mss = tcp_data_len;
			lro->data_csum = mlx4_en_lro_tcp_data_csum(iph, ipv6h,
						th, tcp_data_len, version);

			/* Handle vlans */
			if (be32_to_cpu(cqe->vlan_my_qpn) & MLX4_CQE_VLAN_PRESENT_MASK) {
				lro->vlan_prio = cqe->sl_vid;
				lro->has_vlan = 1;
			} else
				lro->has_vlan = 0;

			/* Handle timestamps */
			if (tcp_hlen != sizeof(*th)) {
				lro->tsval = tsval;
				lro->tsecr = tsecr;
				lro->has_timestamp = 1;
			} else {
				lro->tsval = (u32) ~0UL;
				lro->has_timestamp = 0;
			}

			/* Activate this session */
			lro->expires = jiffies + HZ / 25;
			hlist_del(&lro->node);
			index = LRO_INDEX(th, mdev->profile.num_lro);

			hlist_add_head(&lro->node, &ring->lro_hash[index]);
			hlist_add_head(&lro->flush_node, &ring->lro_flush);
			pstats->lro_aggregated++;
			return 0;
		} else {
			/* Packet is dropped because we were not able to allocate new
			 * page for fragments */
			dma_sync_single_range_for_device(&mdev->pdev->dev, dma,
							 0, max_lro_header,
							 DMA_FROM_DEVICE);
			return 0;
		}
	} else {
		pstats->lro_no_desc++;
	}

flush_session:
	if (lro)
		mlx4_en_lro_flush_single(priv, ring, lro);
sync_device:
	dma_sync_single_range_for_device(&mdev->pdev->dev, dma, 0,
					 max_lro_header, DMA_FROM_DEVICE);
	return -1;
}

/**
 *	mlx4_en_lro_destroy - destory all lro sessions in a ring
 *	@ring: RX ring we operate on
 */
void mlx4_en_lro_destroy(struct mlx4_en_rx_ring *ring)
{
	struct mlx4_en_lro *lro;
	struct hlist_node *node, *tmp;

	hlist_for_each_entry_safe(lro, node, tmp, &ring->lro_free, node) {
		hlist_del(&lro->node);
		kfree(lro);
	}
	kfree(ring->lro_hash);
}

/**
 *	mlx4_en_lro_init - init lro hash table in a ring
 *	@ring: RX ring we operate on
 *	@num_lro: number of lro session to allocate for this ring
 *
 *	Returns 0 for success
 */
int mlx4_en_lro_init(struct mlx4_en_rx_ring *ring, int num_lro)
{
	struct mlx4_en_lro *lro;
	int i;

	INIT_HLIST_HEAD(&ring->lro_free);
	INIT_HLIST_HEAD(&ring->lro_flush);
	ring->lro_hash = kmalloc(sizeof(struct hlist_head) * num_lro,
				 GFP_KERNEL);
	if (!ring->lro_hash)
		return -ENOMEM;

	for (i = 0; i < num_lro; i++) {
		INIT_HLIST_HEAD(&ring->lro_hash[i]);

		lro = kzalloc_node(sizeof(struct mlx4_en_lro),
				GFP_KERNEL, ring->numa_node);

		if (!lro)
			lro = kzalloc(sizeof(struct mlx4_en_lro), GFP_KERNEL);

		if (!lro) {
			mlx4_en_lro_destroy(ring);
			return -ENOMEM;
		}
		INIT_HLIST_NODE(&lro->node);
		INIT_HLIST_NODE(&lro->flush_node);
		hlist_add_head(&lro->node, &ring->lro_free);
	}
	return 0;
}


