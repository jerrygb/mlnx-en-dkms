/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc. All rights reserved.
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
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/io-mapping.h>

#include <linux/mlx4/device.h>
#include <linux/mlx4/doorbell.h>

#include "mlx4.h"
#include "fw.h"
#include "icm.h"

MODULE_AUTHOR("Roland Dreier");
MODULE_DESCRIPTION("Mellanox ConnectX HCA low-level driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

struct workqueue_struct *mlx4_wq;

#ifdef CONFIG_MLX4_DEBUG

int mlx4_debug_level = 0;
module_param_named(debug_level, mlx4_debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Enable debug tracing if > 0");

#endif /* CONFIG_MLX4_DEBUG */

int mlx4_blck_lb=1;
module_param_named(block_loopback, mlx4_blck_lb, int, 0644);
MODULE_PARM_DESC(block_loopback, "Block multicast loopback packets if > 0");

static int high_rate_steer;
module_param(high_rate_steer, int, 0444);
MODULE_PARM_DESC(high_rate_steer, "Enable steering mode for higher packet rate"
				  " (default off)");

static int enable_qinq;
module_param(enable_qinq, bool, 0444);
MODULE_PARM_DESC(enable_qinq, "Set the device skips the first q-tag(vlan) in the packet and treat the secound vlan as the vlan tag."
			"(0/1 default: 0)");

#ifdef CONFIG_PCI_MSI

static int msi_x = 1;
module_param(msi_x, int, 0444);
MODULE_PARM_DESC(msi_x, "attempt to use MSI-X if nonzero");

#else /* CONFIG_PCI_MSI */

#define msi_x (0)

#endif /* CONFIG_PCI_MSI */

#ifdef CONFIG_PCI_IOV

#ifdef MLX4_SRIOV

static int sr_iov;
module_param(sr_iov, int, 0444);
MODULE_PARM_DESC(sr_iov, "enable #sr_iov functions if sr_iov > 0");

static int probe_vf;
module_param(probe_vf, int, 0444);
MODULE_PARM_DESC(probe_vf, "number of vfs to probe by pf driver (sr_iov > 0)");

#else /* MLX4_SRIOV */

#define sr_iov 0
#define probe_vf 0

#endif /* MLX4_SRIOV */

#else /* CONFIG_PCI_IOV */

#define sr_iov 0
#define probe_vf 0

#endif /* CONFIG_PCI_IOV */

int mlx4_log_num_mgm_entry_size = ilog2(MLX4_MGM_ENTRY_SIZE);
module_param_named(log_num_mgm_entry_size,
		   mlx4_log_num_mgm_entry_size, int, 0444);
MODULE_PARM_DESC(log_num_mgm_entry_size, "log mgm size, that defines the num"
					 " of qp per mcg, for example:"
					 " 10 gives 248.range: 9<="
					 " log_num_mgm_entry_size <= 12");

#define MAX_MSIX		64
#define MSIX_LEGACY_SZ		4
#define MIN_MSIX_P_PORT		5

static char mlx4_version[] __devinitdata =
	DRV_NAME ": Mellanox ConnectX core driver v"
	DRV_VERSION " (" DRV_RELDATE ")\n";

struct mutex drv_mutex;

static struct mlx4_profile default_profile = {
	.num_qp		= 1 << 18,
	.num_srq	= 1 << 16,
	.rdmarc_per_qp	= 1 << 4,
	.num_cq		= 1 << 16,
	.num_mcg	= 1 << 13,
	.num_mpt	= 1 << 19,
	.num_mtt	= 1 << 24,
};

static int log_num_mac = 2;
module_param_named(log_num_mac, log_num_mac, int, 0444);
MODULE_PARM_DESC(log_num_mac, "Log2 max number of MACs per ETH port (1-7)");

static int use_prio;
module_param_named(use_prio, use_prio, bool, 0444);
MODULE_PARM_DESC(use_prio, "Enable steering by VLAN priority on ETH ports "
		  "(0/1, default 0)");

static int fast_drop;
module_param_named(fast_drop, fast_drop, int, 0444);
MODULE_PARM_DESC(fast_drop,
		 "Enable fast packet drop when no recieve WQEs are posted");

static struct mlx4_profile mod_param_profile = { 0 };

module_param_named(log_num_qp, mod_param_profile.num_qp, int, 0444);
MODULE_PARM_DESC(log_num_qp, "log maximum number of QPs per HCA");

module_param_named(log_num_srq, mod_param_profile.num_srq, int, 0444);
MODULE_PARM_DESC(log_num_srq, "log maximum number of SRQs per HCA");

module_param_named(log_rdmarc_per_qp, mod_param_profile.rdmarc_per_qp, int, 0444);
MODULE_PARM_DESC(log_rdmarc_per_qp, "log number of RDMARC buffers per QP");

module_param_named(log_num_cq, mod_param_profile.num_cq, int, 0444);
MODULE_PARM_DESC(log_num_cq, "log maximum number of CQs per HCA");

module_param_named(log_num_mcg, mod_param_profile.num_mcg, int, 0444);
MODULE_PARM_DESC(log_num_mcg, "log maximum number of multicast groups per HCA");

module_param_named(log_num_mpt, mod_param_profile.num_mpt, int, 0444);
MODULE_PARM_DESC(log_num_mpt,
		"log maximum number of memory protection table entries per HCA");

module_param_named(log_num_mtt, mod_param_profile.num_mtt, int, 0444);
MODULE_PARM_DESC(log_num_mtt,
		 "log maximum number of memory translation table segments per HCA");

static int log_mtts_per_seg = ilog2(1);
module_param_named(log_mtts_per_seg, log_mtts_per_seg, int, 0444);
MODULE_PARM_DESC(log_mtts_per_seg, "Log2 number of MTT entries per segment (0-7)");

static void process_mod_param_profile(void)
{
	default_profile.num_qp = (mod_param_profile.num_qp ?
				  1 << mod_param_profile.num_qp :
				  default_profile.num_qp);
	default_profile.num_srq = (mod_param_profile.num_srq ?
				  1 << mod_param_profile.num_srq :
				  default_profile.num_srq);
	default_profile.rdmarc_per_qp = (mod_param_profile.rdmarc_per_qp ?
				  1 << mod_param_profile.rdmarc_per_qp :
				  default_profile.rdmarc_per_qp);
	default_profile.num_cq = (mod_param_profile.num_cq ?
				  1 << mod_param_profile.num_cq :
				  default_profile.num_cq);
	default_profile.num_mcg = (mod_param_profile.num_mcg ?
				  1 << mod_param_profile.num_mcg :
				  default_profile.num_mcg);
	default_profile.num_mpt = (mod_param_profile.num_mpt ?
				  1 << mod_param_profile.num_mpt :
				  default_profile.num_mpt);
	default_profile.num_mtt = (mod_param_profile.num_mtt ?
				  1 << mod_param_profile.num_mtt :
				  default_profile.num_mtt);
}

struct mlx4_port_config
{
	struct list_head list;
	enum mlx4_port_type port_type[MLX4_MAX_PORTS + 1];
	struct pci_dev *pdev;
};
static LIST_HEAD(config_list);

static void mlx4_config_cleanup(void)
{
	struct mlx4_port_config *config, *tmp;

	list_for_each_entry_safe(config, tmp, &config_list, list) {
		list_del(&config->list);
		kfree(config);
	}
}

void mlx4_set_iboe_counter(struct mlx4_dev *dev, int index, u8 port)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	priv->iboe_counter_index[port - 1] = index;
}
EXPORT_SYMBOL(mlx4_set_iboe_counter);

int mlx4_get_iboe_counter(struct mlx4_dev *dev, u8 port)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	return priv->iboe_counter_index[port - 1];
}
EXPORT_SYMBOL(mlx4_get_iboe_counter);

int mlx4_check_port_params(struct mlx4_dev *dev,
			   enum mlx4_port_type *port_type)
{
	int i;

	for (i = 0; i < dev->caps.num_ports - 1; i++) {
		if (port_type[i] != port_type[i + 1]) {
			if (!(dev->caps.flags & MLX4_DEV_CAP_FLAG_DPDP)) {
				mlx4_err(dev, "Only same port types supported "
					 "on this HCA, aborting.\n");
				return -EINVAL;
			}
			if (port_type[i] == MLX4_PORT_TYPE_ETH &&
			    port_type[i + 1] == MLX4_PORT_TYPE_IB)
				return -EINVAL;
		}
	}

	for (i = 0; i < dev->caps.num_ports; i++) {
		if (!(port_type[i] & dev->caps.supported_type[i+1])) {
			mlx4_err(dev, "Requested port type for port %d is not "
				      "supported on this HCA\n", i + 1);
			return -EINVAL;
		}
	}
	return 0;
}

void mlx4_set_port_mask(struct mlx4_dev *dev, struct mlx4_caps *caps, int function)
{
	int i;

	for (i = 1; i <= caps->num_ports; ++i) {
		if (mlx4_is_master(dev) && (dev->caps.pf_num > 1) &&
		    mlx4_priv(dev)->mfunc.master.slave_state[function].port_num != i)
			caps->port_mask[i] = 0;
		else
			caps->port_mask[i] = caps->port_type[i];
	}
}

static u8 get_counters_mode(u64 flags)
{
	switch (flags >> 48 & 3) {
	case 2:
	case 3:
		return MLX4_CUNTERS_EXT;
	case 1:
		return MLX4_CUNTERS_BASIC;
	default:
		return MLX4_CUNTERS_DISABLED;
	}
}

static int mlx4_dev_cap(struct mlx4_dev *dev, struct mlx4_dev_cap *dev_cap)
{
	int err;
	int i;

	err = mlx4_QUERY_DEV_CAP(dev, dev_cap);
	if (err) {
		mlx4_err(dev, "QUERY_DEV_CAP command failed, aborting.\n");
		return err;
	}

	if (dev_cap->min_page_sz > PAGE_SIZE) {
		mlx4_err(dev, "HCA minimum page size of %d bigger than "
			 "kernel PAGE_SIZE of %ld, aborting.\n",
			 dev_cap->min_page_sz, PAGE_SIZE);
		return -ENODEV;
	}
	if (dev_cap->num_ports > MLX4_MAX_PORTS) {
		mlx4_err(dev, "HCA has %d ports, but we only support %d, "
			 "aborting.\n",
			 dev_cap->num_ports, MLX4_MAX_PORTS);
		return -ENODEV;
	}

	if (dev_cap->uar_size > pci_resource_len(dev->pdev, 2)) {
		mlx4_err(dev, "HCA reported UAR size of 0x%x bigger than "
			 "PCI resource 2 size of 0x%llx, aborting.\n",
			 dev_cap->uar_size,
			 (unsigned long long) pci_resource_len(dev->pdev, 2));
		return -ENODEV;
	}

	if (enable_qinq && !dev_cap->qinq) {
		mlx4_warn(dev, "Ignoring setting of QinQ"
				"No HW capability\n");
	}

	dev->caps.pf_num = dev_cap->pf_num;
	dev->caps.num_ports	     = dev_cap->num_ports;
	for (i = 1; i <= dev->caps.num_ports; ++i) {
		dev->caps.vl_cap[i]	    = dev_cap->max_vl[i];
		dev->caps.ib_mtu_cap[i]	    = dev_cap->ib_mtu[i];
		dev->caps.gid_table_len[i]  = dev_cap->max_gids[i];
		dev->caps.pkey_table_len[i] = dev_cap->max_pkeys[i];
		dev->caps.port_width_cap[i] = dev_cap->max_port_width[i];
		dev->caps.eth_mtu_cap[i]    = dev_cap->eth_mtu[i];
		dev->caps.def_mac[i]        = dev_cap->def_mac[i];
		dev->caps.supported_type[i] = dev_cap->supported_port_types[i];
		dev->caps.suggested_type[i] = dev_cap->suggested_port[i];
		dev->caps.default_sense[i] = dev_cap->default_sense[i];
		dev->caps.trans_type[i]	    = dev_cap->trans_type[i];
		dev->caps.vendor_oui[i]     = dev_cap->vendor_oui[i];
		dev->caps.wavelength[i]     = dev_cap->wavelength[i];
		dev->caps.trans_code[i]     = dev_cap->trans_code[i];
	}

	dev->caps.uar_page_size	     = PAGE_SIZE;
	dev->caps.num_uars	     = dev_cap->uar_size / PAGE_SIZE;
	dev->caps.local_ca_ack_delay = dev_cap->local_ca_ack_delay;
	dev->caps.bf_reg_size	     = dev_cap->bf_reg_size;
	dev->caps.bf_regs_per_page   = dev_cap->bf_regs_per_page;
	dev->caps.max_sq_sg	     = dev_cap->max_sq_sg;
	dev->caps.max_rq_sg	     = dev_cap->max_rq_sg;
	dev->caps.max_wqes	     = dev_cap->max_qp_sz;
	dev->caps.max_qp_init_rdma   = dev_cap->max_requester_per_qp;
	dev->caps.max_srq_wqes	     = dev_cap->max_srq_sz;
	dev->caps.max_srq_sge	     = dev_cap->max_rq_sg - 1;
	dev->caps.reserved_srqs	     = dev_cap->reserved_srqs;
	dev->caps.max_sq_desc_sz     = dev_cap->max_sq_desc_sz;
	dev->caps.max_rq_desc_sz     = dev_cap->max_rq_desc_sz;
	dev->caps.num_qp_per_mgm     = mlx4_get_qp_per_mgm(dev);
	/*
	 * Subtract 1 from the limit because we need to allocate a
	 * spare CQE so the HCA HW can tell the difference between an
	 * empty CQ and a full CQ.
	 */
	dev->caps.max_cqes	     = dev_cap->max_cq_sz - 1;
	dev->caps.reserved_cqs	     = dev_cap->reserved_cqs;
	dev->caps.reserved_eqs	     = dev_cap->reserved_eqs;
	dev->caps.mtts_per_seg	     = 1 << log_mtts_per_seg;
	if (mlx4_is_mfunc(dev))
		dev->caps.mtts_per_seg = 1 << ilog2(MLX4_MTT_ENTRY_PER_SEG);
	dev->caps.reserved_mtts	     = DIV_ROUND_UP(dev_cap->reserved_mtts,
						    dev->caps.mtts_per_seg);
	dev->caps.reserved_mrws	     = dev_cap->reserved_mrws;

	/* The first 128 UARs are used for EQ doorbells */
	dev->caps.reserved_uars	     = max_t(int, 128, dev_cap->reserved_uars);
	dev->caps.reserved_pds	     = dev_cap->reserved_pds;
	dev->caps.mtt_entry_sz	     = dev->caps.mtts_per_seg * dev_cap->mtt_entry_sz;
	dev->caps.max_msg_sz         = dev_cap->max_msg_sz;
	dev->caps.page_size_cap	     = ~(u32) (dev_cap->min_page_sz - 1);
	dev->caps.flags		     = dev_cap->flags;
	dev->caps.bmme_flags	     = dev_cap->bmme_flags;
	dev->caps.reserved_lkey	     = dev_cap->reserved_lkey;
	dev->caps.stat_rate_support  = dev_cap->stat_rate_support;
	dev->caps.udp_rss	     = dev_cap->udp_rss;
	dev->caps.loopback_support   = dev_cap->loopback_support;
	dev->caps.vep_uc_steering    = dev_cap->vep_uc_steering;
	dev->caps.vep_mc_steering    = dev_cap->vep_mc_steering;
	if (high_rate_steer && !mlx4_is_mfunc(dev)) {
		dev->caps.vep_uc_steering = 0;
		dev->caps.vep_mc_steering = 0;
	}
	dev->caps.wol                = dev_cap->wol;
	dev->caps.max_gso_sz	     = dev_cap->max_gso_sz;
	dev->caps.reserved_xrcds     = (dev->caps.flags & MLX4_DEV_CAP_FLAG_XRC) ?
		dev_cap->reserved_xrcds : 0;
	dev->caps.max_xrcds	     = (dev->caps.flags & MLX4_DEV_CAP_FLAG_XRC) ?
		dev_cap->max_xrcds : 0;

	/* Sense port always allowed on supported devices for ConnectX1 and 2 */
	if (dev->rev_id == 0xa0 || dev->rev_id == 0xb0)
		dev->caps.flags |= MLX4_DEV_CAP_SENSE_SUPPORT;

	dev->caps.log_num_macs  = log_num_mac;
	dev->caps.log_num_prios = use_prio ? 3 : 0;
	dev->caps.fast_drop	= fast_drop ? dev_cap->fast_drop : 0;
	dev->caps.qinq          = dev_cap->qinq && enable_qinq;

	for (i = 1; i <= dev->caps.num_ports; ++i) {
		dev->caps.port_type[i] = MLX4_PORT_TYPE_NONE;
		/*
		 * Port type is defaulted to Ethernet in 1 of 2 cases:
		 * 1. Ethernet is the only supported type.
		 * 2. Ethernet is supported and suggested type is also Ethernet
		 * Otherwise port type is IB by default
		 */
		if (dev->caps.supported_type[i]) {
			if (!(dev->caps.supported_type[i] & MLX4_PORT_TYPE_ETH))
				dev->caps.port_type[i] = MLX4_PORT_TYPE_IB;
			else
				dev->caps.port_type[i] = MLX4_PORT_TYPE_ETH;
		}

		if (dev->caps.log_num_macs > dev_cap->log_max_macs[i]) {
			dev->caps.log_num_macs = dev_cap->log_max_macs[i];
			mlx4_warn(dev, "Requested number of MACs is too much "
				  "for port %d, reducing to %d.\n",
				  i, 1 << dev->caps.log_num_macs);
		}
		dev->caps.log_num_vlans = dev_cap->log_max_vlans[i];
	}

	dev->caps.counters_mode = get_counters_mode(dev_cap->flags);
	dev->caps.max_basic_counters = 1 << ilog2(dev_cap->max_basic_counters);
	dev->caps.max_ext_counters = 1 << ilog2(dev_cap->max_ext_counters);

	dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW] = dev_cap->reserved_qps;
	dev->caps.reserved_qps_cnt[MLX4_QP_REGION_ETH_ADDR] =
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FC_ADDR] =
		(1 << dev->caps.log_num_macs) *
		(1 << dev->caps.log_num_vlans) *
		(1 << dev->caps.log_num_prios) *
		dev->caps.num_ports;

	dev->caps.reserved_qps = dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW] +
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_ETH_ADDR] +
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FC_ADDR];

	dev->caps.sync_qp = dev_cap->sync_qp;
	/* CX3 is capable of extending the CQE\EQE from 32 to 64 bytes */
	dev->caps.cqe_size   = (dev_cap->flags & (1ull << 62)) ? 64 : 32;
	dev->caps.eqe_size   = (dev_cap->flags & (1ull << 61)) ? 64 : 32;
	dev->caps.eqe_factor = (dev->caps.eqe_size == 64) ? 1 : 0;

	/* Master function demultiplexes mads */
	dev->caps.sqp_demux = MLX4_MAX_NUM_SLAVES;
	dev->caps.clp_ver = dev_cap->clp_ver;
	return 0;
}

int mlx4_slave_cap(struct mlx4_dev *dev)
{
	int err;
	u32 page_size;

	err = mlx4_QUERY_SLAVE_CAP(dev, &dev->caps);
	if (err)
		return err;

	page_size = ~dev->caps.page_size_cap + 1;
	mlx4_warn(dev, "HCA minimum page size:%d\n", page_size);
	if (page_size > PAGE_SIZE) {
		mlx4_err(dev, "HCA minimum page size of %d bigger than "
			 "kernel PAGE_SIZE of %ld, aborting.\n",
			 page_size, PAGE_SIZE);
		return -ENODEV;
	}

	/* TODO: relax this assumption */
	if (dev->caps.uar_page_size != PAGE_SIZE) {
		mlx4_err(dev, "UAR size:%d != kernel PAGE_SIZE of %ld\n",
			 dev->caps.uar_page_size, PAGE_SIZE);
		return -ENODEV;
	}

	if (dev->caps.num_ports > MLX4_MAX_PORTS) {
		mlx4_err(dev, "HCA has %d ports, but we only support %d, "
			 "aborting.\n", dev->caps.num_ports, MLX4_MAX_PORTS);
		return -ENODEV;
	}

	if (dev->caps.uar_page_size * (dev->caps.num_uars -
				       dev->caps.reserved_uars) >
				       pci_resource_len(dev->pdev, 2)) {
		mlx4_err(dev, "HCA reported UAR region size of 0x%x bigger than "
			 "PCI resource 2 size of 0x%llx, aborting.\n",
			 dev->caps.uar_page_size * dev->caps.num_uars,
			 (unsigned long long) pci_resource_len(dev->pdev, 2));
		return -ENODEV;
	}

	/* Adjust eq number */
	if (dev->caps.num_eqs - dev->caps.reserved_eqs > num_possible_cpus() + 1)
		dev->caps.num_eqs = dev->caps.reserved_eqs + num_possible_cpus() + 1;

#if 0
	mlx4_warn(dev, "sqp_demux:%d\n", dev->caps.sqp_demux);
	mlx4_warn(dev, "num_uars:%d reserved_uars:%d uar region:0x%x bar2:0x%llx\n",
					  dev->caps.num_uars, dev->caps.reserved_uars,
					  dev->caps.uar_page_size * dev->caps.num_uars,
					  pci_resource_len(dev->pdev, 2));
	mlx4_warn(dev, "num_eqs:%d reserved_eqs:%d\n", dev->caps.num_eqs,
						       dev->caps.reserved_eqs);
	mlx4_warn(dev, "num_pds:%d reserved_pds:%d slave_pd_shift:%d pd_base:%d\n",
							dev->caps.num_pds,
							dev->caps.reserved_pds,
							dev->caps.slave_pd_shift,
							dev->caps.pd_base);
#endif
	return 0;
}

static int mlx4_load_fw(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;

	priv->fw.fw_icm = mlx4_alloc_icm(dev, priv->fw.fw_pages,
					 GFP_HIGHUSER | __GFP_NOWARN, 0);
	if (!priv->fw.fw_icm) {
		mlx4_err(dev, "Couldn't allocate FW area, aborting.\n");
		return -ENOMEM;
	}

	err = mlx4_MAP_FA(dev, priv->fw.fw_icm);
	if (err) {
		mlx4_err(dev, "MAP_FA command failed, aborting.\n");
		goto err_free;
	}

	err = mlx4_RUN_FW(dev);
	if (err) {
		mlx4_err(dev, "RUN_FW command failed, aborting.\n");
		goto err_unmap_fa;
	}

	return 0;

err_unmap_fa:
	mlx4_UNMAP_FA(dev);

err_free:
	mlx4_free_icm(dev, priv->fw.fw_icm, 0);
	return err;
}

static int mlx4_init_cmpt_table(struct mlx4_dev *dev, u64 cmpt_base,
				int cmpt_entry_sz)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;
	int num_eqs;

	err = mlx4_init_icm_table(dev, &priv->qp_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_QP *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err)
		goto err;

	err = mlx4_init_icm_table(dev, &priv->srq_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_SRQ *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, dev->caps.num_srqs,
				  dev->caps.reserved_srqs, 0, 0);
	if (err)
		goto err_qp;

	err = mlx4_init_icm_table(dev, &priv->cq_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_CQ *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, dev->caps.num_cqs,
				  dev->caps.reserved_cqs, 0, 0);
	if (err)
		goto err_srq;

	num_eqs = mlx4_is_master(dev) ? 512 : dev->caps.num_eqs;
	err = mlx4_init_icm_table(dev, &priv->eq_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_EQ *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, num_eqs, num_eqs, 0, 0);
	if (err)
		goto err_cq;

	return 0;

err_cq:
	mlx4_cleanup_icm_table(dev, &priv->cq_table.cmpt_table);

err_srq:
	mlx4_cleanup_icm_table(dev, &priv->srq_table.cmpt_table);

err_qp:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.cmpt_table);

err:
	return err;
}

static int mlx4_init_icm(struct mlx4_dev *dev, struct mlx4_dev_cap *dev_cap,
			 struct mlx4_init_hca_param *init_hca, u64 icm_size)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	u64 aux_pages;
	int num_eqs;
	int err;

	err = mlx4_SET_ICM_SIZE(dev, icm_size, &aux_pages);
	if (err) {
		mlx4_err(dev, "SET_ICM_SIZE command failed, aborting.\n");
		return err;
	}

	mlx4_dbg(dev, "%lld KB of HCA context requires %lld KB aux memory.\n",
		 (unsigned long long) icm_size >> 10,
		 (unsigned long long) aux_pages << 2);

	priv->fw.aux_icm = mlx4_alloc_icm(dev, aux_pages,
					  GFP_HIGHUSER | __GFP_NOWARN, 0);
	if (!priv->fw.aux_icm) {
		mlx4_err(dev, "Couldn't allocate aux memory, aborting.\n");
		return -ENOMEM;
	}

	err = mlx4_MAP_ICM_AUX(dev, priv->fw.aux_icm);
	if (err) {
		mlx4_err(dev, "MAP_ICM_AUX command failed, aborting.\n");
		goto err_free_aux;
	}

	err = mlx4_init_cmpt_table(dev, init_hca->cmpt_base, dev_cap->cmpt_entry_sz);
	if (err) {
		mlx4_err(dev, "Failed to map cMPT context memory, aborting.\n");
		goto err_unmap_aux;
	}


	num_eqs = mlx4_is_master(dev) ? 512 : dev->caps.num_eqs;
	err = mlx4_init_icm_table(dev, &priv->eq_table.table,
				  init_hca->eqc_base, dev_cap->eqc_entry_sz,
				  num_eqs, num_eqs, 0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map EQ context memory, aborting.\n");
		goto err_unmap_cmpt;
	}

	/*
	 * Reserved MTT entries must be aligned up to a cacheline
	 * boundary, since the FW will write to them, while the driver
	 * writes to all other MTT entries. (The variable
	 * dev->caps.mtt_entry_sz below is really the MTT segment
	 * size, not the raw entry size)
	 */
	dev->caps.reserved_mtts =
		ALIGN(dev->caps.reserved_mtts * dev->caps.mtt_entry_sz,
		      dma_get_cache_alignment()) / dev->caps.mtt_entry_sz;

	err = mlx4_init_icm_table(dev, &priv->mr_table.mtt_table,
				  init_hca->mtt_base,
				  dev->caps.mtt_entry_sz,
				  dev->caps.num_mtt_segs,
				  dev->caps.reserved_mtts, 1, 0);
	if (err) {
		mlx4_err(dev, "Failed to map MTT context memory, aborting.\n");
		goto err_unmap_eq;
	}

	err = mlx4_init_icm_table(dev, &priv->mr_table.dmpt_table,
				  init_hca->dmpt_base,
				  dev_cap->dmpt_entry_sz,
				  dev->caps.num_mpts,
				  dev->caps.reserved_mrws, 1, 1);
	if (err) {
		mlx4_err(dev, "Failed to map dMPT context memory, aborting.\n");
		goto err_unmap_mtt;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.qp_table,
				  init_hca->qpc_base,
				  dev_cap->qpc_entry_sz,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map QP context memory, aborting.\n");
		goto err_unmap_dmpt;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.auxc_table,
				  init_hca->auxc_base,
				  dev_cap->aux_entry_sz,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map AUXC context memory, aborting.\n");
		goto err_unmap_qp;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.altc_table,
				  init_hca->altc_base,
				  dev_cap->altc_entry_sz,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map ALTC context memory, aborting.\n");
		goto err_unmap_auxc;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.rdmarc_table,
				  init_hca->rdmarc_base,
				  dev_cap->rdmarc_entry_sz << priv->qp_table.rdmarc_shift,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map RDMARC context memory, aborting\n");
		goto err_unmap_altc;
	}

	err = mlx4_init_icm_table(dev, &priv->cq_table.table,
				  init_hca->cqc_base,
				  dev_cap->cqc_entry_sz,
				  dev->caps.num_cqs,
				  dev->caps.reserved_cqs, 0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map CQ context memory, aborting.\n");
		goto err_unmap_rdmarc;
	}

	err = mlx4_init_icm_table(dev, &priv->srq_table.table,
				  init_hca->srqc_base,
				  dev_cap->srq_entry_sz,
				  dev->caps.num_srqs,
				  dev->caps.reserved_srqs, 0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map SRQ context memory, aborting.\n");
		goto err_unmap_cq;
	}

	/*
	 * It's not strictly required, but for simplicity just map the
	 * whole multicast group table now.  The table isn't very big
	 * and it's a lot easier than trying to track ref counts.
	 */
	err = mlx4_init_icm_table(dev, &priv->mcg_table.table,
				  init_hca->mc_base,
				  mlx4_get_mgm_entry_size(dev),
				  dev->caps.num_mgms + dev->caps.num_amgms,
				  dev->caps.num_mgms + dev->caps.num_amgms,
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map MCG context memory, aborting.\n");
		goto err_unmap_srq;
	}

	return 0;

err_unmap_srq:
	mlx4_cleanup_icm_table(dev, &priv->srq_table.table);

err_unmap_cq:
	mlx4_cleanup_icm_table(dev, &priv->cq_table.table);

err_unmap_rdmarc:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.rdmarc_table);

err_unmap_altc:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.altc_table);

err_unmap_auxc:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.auxc_table);

err_unmap_qp:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.qp_table);

err_unmap_dmpt:
	mlx4_cleanup_icm_table(dev, &priv->mr_table.dmpt_table);

err_unmap_mtt:
	mlx4_cleanup_icm_table(dev, &priv->mr_table.mtt_table);

err_unmap_eq:
	mlx4_cleanup_icm_table(dev, &priv->eq_table.table);

err_unmap_cmpt:
	mlx4_cleanup_icm_table(dev, &priv->eq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->cq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->srq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.cmpt_table);

err_unmap_aux:
	mlx4_UNMAP_ICM_AUX(dev);

err_free_aux:
	mlx4_free_icm(dev, priv->fw.aux_icm, 0);

	return err;
}

static void mlx4_free_icms(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	mlx4_cleanup_icm_table(dev, &priv->mcg_table.table);
	mlx4_cleanup_icm_table(dev, &priv->srq_table.table);
	mlx4_cleanup_icm_table(dev, &priv->cq_table.table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.rdmarc_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.altc_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.auxc_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.qp_table);
	mlx4_cleanup_icm_table(dev, &priv->mr_table.dmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->mr_table.mtt_table);
	mlx4_cleanup_icm_table(dev, &priv->eq_table.table);
	mlx4_cleanup_icm_table(dev, &priv->eq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->cq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->srq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.cmpt_table);

	mlx4_UNMAP_ICM_AUX(dev);
	mlx4_free_icm(dev, priv->fw.aux_icm, 0);
}

static int map_bf_area(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	resource_size_t bf_start;
	resource_size_t bf_len;
	int err = 0;

	bf_start = pci_resource_start(dev->pdev, 2) + (dev->caps.num_uars << PAGE_SHIFT);
	bf_len = pci_resource_len(dev->pdev, 2) - (dev->caps.num_uars << PAGE_SHIFT);
	priv->bf_mapping = io_mapping_create_wc(bf_start, bf_len);
	if (!priv->bf_mapping)
		err = -ENOMEM;

	return err;
}

static void unmap_bf_area(struct mlx4_dev *dev)
{
	if (mlx4_priv(dev)->bf_mapping)
		io_mapping_free(mlx4_priv(dev)->bf_mapping);
}

static void mlx4_slave_exit(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	down(&priv->cmd.slave_sem);
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_RESET, 0, MLX4_COMM_TIME))
		mlx4_warn(dev, "Failed to close slave function.\n");
	up(&priv->cmd.slave_sem);
}

static void mlx4_close_hca(struct mlx4_dev *dev)
{
	if (mlx4_is_slave(dev))
		mlx4_slave_exit(dev);
	else {
		unmap_bf_area(dev);
		mlx4_CLOSE_HCA(dev, 0);
		mlx4_free_icms(dev);
		mlx4_UNMAP_FA(dev);
		mlx4_free_icm(dev, mlx4_priv(dev)->fw.fw_icm, 0);
	}
}

static int mlx4_init_slave(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	u64 dma = (u64) priv->mfunc.vhcr_dma;

	down(&priv->cmd.slave_sem);
	priv->cmd.max_cmds = 1;
	mlx4_warn(dev, "Sending reset\n");
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_RESET, 0, MLX4_COMM_TIME))
		goto err;
	mlx4_warn(dev, "Sending vhcr0\n");
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_VHCR0, dma >> 48,
						    MLX4_COMM_TIME))
		goto err;
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_VHCR1, dma >> 32,
						    MLX4_COMM_TIME))
		goto err;
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_VHCR2, dma >> 16,
						    MLX4_COMM_TIME))
		goto err;
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_VHCR_EN, dma, MLX4_COMM_TIME))
		goto err;
	up(&priv->cmd.slave_sem);
	return 0;

err:
	mlx4_comm_cmd(dev, MLX4_COMM_CMD_RESET, 0, 0);
	up(&priv->cmd.slave_sem);
	return -EIO;
}

static int mlx4_init_hca(struct mlx4_dev *dev)
{
	struct mlx4_priv	  *priv = mlx4_priv(dev);
	struct mlx4_adapter	   adapter;
	struct mlx4_dev_cap	   dev_cap;
	struct mlx4_mod_stat_cfg   mlx4_cfg;
	struct mlx4_profile	   profile;
	struct mlx4_init_hca_param init_hca;
	struct mlx4_port_config	  *config;
	u64 icm_size;
	int err;
	int i;

	if (!mlx4_is_slave(dev)) {
		err = mlx4_QUERY_FW(dev);
		if (err) {
			if (err == -EACCES)
				mlx4_info(dev, "non-primary physical function, skipping.\n");
			else
				mlx4_err(dev, "QUERY_FW command failed, aborting.\n");
			return err;
		}

		err = mlx4_load_fw(dev);
		if (err) {
			mlx4_err(dev, "Failed to start FW, aborting.\n");
			return err;
		}

		mlx4_cfg.log_pg_sz_m = 1;
		mlx4_cfg.log_pg_sz = 0;
		err = mlx4_MOD_STAT_CFG(dev, &mlx4_cfg);
		if (err)
			mlx4_warn(dev, "Failed to override log_pg_sz parameter\n");

		err = mlx4_dev_cap(dev, &dev_cap);
		if (err) {
			mlx4_err(dev, "QUERY_DEV_CAP command failed, aborting.\n");
			goto err_stop_fw;
		}

		process_mod_param_profile();
		profile = default_profile;

		list_for_each_entry(config, &config_list, list) {
			if (config->pdev == dev->pdev) {
				for (i = 1; i <= dev->caps.num_ports; i++) {
					dev->caps.possible_type[i] = config->port_type[i];
					if (config->port_type[i] != MLX4_PORT_TYPE_AUTO)
						dev->caps.port_type[i] = config->port_type[i];
				}
			}
		}

		icm_size = mlx4_make_profile(dev, &profile, &dev_cap, &init_hca);
		if ((long long) icm_size < 0) {
			err = icm_size;
			goto err_stop_fw;
		}

		if (map_bf_area(dev))
		mlx4_dbg(dev, "Kernel support for blue flame is not available for kernels < 2.6.28\n");

		init_hca.log_uar_sz = ilog2(dev->caps.num_uars);

		err = mlx4_init_icm(dev, &dev_cap, &init_hca, icm_size);
		if (err)
			goto err_stop_fw;

		err = mlx4_INIT_HCA(dev, &init_hca);
		if (err) {
			mlx4_err(dev, "INIT_HCA command failed, aborting.\n");
			goto err_free_icm;
		}
	} else {
		err = mlx4_init_slave(dev);
		if (err) {
			mlx4_err(dev, "Failed to initialize slave\n");
			return err;
		}

		err = mlx4_slave_cap(dev);
		if (err) {
			mlx4_err(dev, "Failed to obtain slave caps\n");
			goto err_close;
		}
	}

	if (!mlx4_is_mfunc(dev))
		mlx4_set_port_mask(dev, &dev->caps, dev->caps.function);

	err = mlx4_QUERY_ADAPTER(dev, &adapter);
	if (err) {
		mlx4_err(dev, "QUERY_ADAPTER command failed, aborting.\n");
		goto err_close;
	}

	priv->eq_table.inta_pin = adapter.inta_pin;
	memcpy(dev->board_id, adapter.board_id, sizeof dev->board_id);

	return 0;

err_close:
	mlx4_CLOSE_HCA(dev, 0);

err_free_icm:
	if (!mlx4_is_slave(dev))
		mlx4_free_icms(dev);

err_stop_fw:
	if (!mlx4_is_slave(dev)) {
		unmap_bf_area(dev);
		mlx4_UNMAP_FA(dev);
		mlx4_free_icm(dev, priv->fw.fw_icm, 0);
	}
	return err;
}

static int mlx4_init_counters_table(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;
	int nent;

	switch (dev->caps.counters_mode) {
	case MLX4_CUNTERS_BASIC:
		nent = dev->caps.max_basic_counters;
		break;
	case MLX4_CUNTERS_EXT:
		nent = dev->caps.max_ext_counters;
		break;
	default:
		return -ENOENT;
	}
	err = mlx4_bitmap_init(&priv->counters_bitmap, nent, nent - 1, 0, 0);
	if (err)
		return err;

	return 0;
}

static void mlx4_cleanup_counters_table(struct mlx4_dev *dev)
{
	switch (dev->caps.counters_mode) {
	case MLX4_CUNTERS_BASIC:
	case MLX4_CUNTERS_EXT:
		mlx4_bitmap_cleanup(&mlx4_priv(dev)->counters_bitmap);
		break;
	default:
		break;
	}
}

int mlx4_counter_alloc(struct mlx4_dev *dev, u32 *idx)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	switch (dev->caps.counters_mode) {
	case MLX4_CUNTERS_BASIC:
	case MLX4_CUNTERS_EXT:
		*idx = mlx4_bitmap_alloc(&priv->counters_bitmap);
		if (*idx == -1)
			return -ENOMEM;
		return 0;
	default:
		return -ENOMEM;
	}
}
EXPORT_SYMBOL_GPL(mlx4_counter_alloc);

void mlx4_counter_free(struct mlx4_dev *dev, u32 idx)
{
	switch (dev->caps.counters_mode) {
	case MLX4_CUNTERS_BASIC:
	case MLX4_CUNTERS_EXT:
		mlx4_bitmap_free(&mlx4_priv(dev)->counters_bitmap, idx);
		return;
	default:
		return;
	}
}
EXPORT_SYMBOL_GPL(mlx4_counter_free);

static int mlx4_setup_hca(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;
	int port;
	u64 ext_port_default_caps;
	__be32 ib_port_default_caps;

	err = mlx4_init_uar_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "user access region table, aborting.\n");
		return err;
	}

	err = mlx4_uar_alloc(dev, &priv->driver_uar);
	if (err) {
		mlx4_err(dev, "Failed to allocate driver access region, "
			 "aborting.\n");
		goto err_uar_table_free;
	}

	priv->kar = ioremap(priv->driver_uar.pfn << PAGE_SHIFT, PAGE_SIZE);
	if (!priv->kar) {
		mlx4_err(dev, "Couldn't map kernel access region, "
			 "aborting.\n");
		err = -ENOMEM;
		goto err_uar_free;
	}

	err = mlx4_init_pd_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "protection domain table, aborting.\n");
		goto err_kar_unmap;
	}

	err = mlx4_init_xrcd_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize extended "
			 "reliably connected domain table, aborting.\n");
		goto err_pd_table_free;
	}

	err = mlx4_init_mr_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "memory region table, aborting.\n");
		goto err_xrcd_table_free;
	}

	err = mlx4_init_mcg_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "multicast group table, aborting.\n");
		goto err_mr_table_free;
	}

	err = mlx4_init_eq_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "event queue table, aborting.\n");
		goto err_mcg_table_free;
	}

	err = mlx4_cmd_use_events(dev);
	if (err) {
		mlx4_err(dev, "Failed to switch to event-driven "
			      "firmware commands, aborting.\n");
		goto err_eq_table_free;
	}

	err = mlx4_NOP(dev);
	if (err) {
		if (dev->flags & MLX4_FLAG_MSI_X) {
			mlx4_warn(dev, "NOP command failed to generate MSI-X "
				  "interrupt IRQ %d).\n",
				  priv->eq_table.eq[dev->caps.num_comp_vectors].irq);
			mlx4_warn(dev, "Trying again without MSI-X.\n");
		} else {
			mlx4_err(dev, "NOP command failed to generate interrupt "
				 "(IRQ %d), aborting.\n",
				 priv->eq_table.eq[dev->caps.num_comp_vectors].irq);
			mlx4_err(dev, "BIOS or ACPI interrupt routing problem?\n");
		}

		goto err_cmd_poll;
	}

	mlx4_dbg(dev, "NOP command IRQ test passed\n");

	err = mlx4_init_cq_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "completion queue table, aborting.\n");
		goto err_cmd_poll;
	}

	err = mlx4_init_srq_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "shared receive queue table, aborting.\n");
		goto err_cq_table_free;
	}

	err = mlx4_init_qp_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "queue pair table, aborting.\n");
		goto err_srq_table_free;
	}


	err = mlx4_init_counters_table(dev);
	if (err && err != -ENOENT) {
		mlx4_err(dev, "Failed to initialize counters table, aborting.\n");
		goto err_qp_table_free;
	}

	if (!mlx4_is_slave(dev)) {
		for (port = 1; port <= dev->caps.num_ports; port++) {
			ib_port_default_caps = 0;
			err = mlx4_get_port_ib_caps(dev, port, &ib_port_default_caps);
			if (err)
				mlx4_warn(dev, "failed to get port %d default "
					  "ib capabilities (%d). Continuing with "
					  "caps = 0\n", port, err);
			dev->caps.ib_port_def_cap[port] = ib_port_default_caps;

		ext_port_default_caps = 0;
		err = mlx4_get_ext_port_caps(dev, port, &ext_port_default_caps);
		if (err)
			mlx4_warn(dev, "failed to get port %d extended "
				  "port capabilities support (%d). Assuming "
				  "not supported\n", port, err);
		dev->caps.ext_port_cap[port] = ext_port_default_caps;

			err = mlx4_SET_PORT(dev, port);
			if (err) {
				mlx4_err(dev, "Failed to set port %d, aborting\n",
					port);
				goto err_counters_table_free;
			}
		}
	}

	return 0;

err_counters_table_free:
	mlx4_cleanup_counters_table(dev);

err_qp_table_free:
	mlx4_cleanup_qp_table(dev);

err_srq_table_free:
	mlx4_cleanup_srq_table(dev);

err_cq_table_free:
	mlx4_cleanup_cq_table(dev);

err_cmd_poll:
	mlx4_cmd_use_polling(dev);

err_eq_table_free:
	mlx4_cleanup_eq_table(dev);

err_mcg_table_free:
	mlx4_cleanup_mcg_table(dev);

err_mr_table_free:
	mlx4_cleanup_mr_table(dev);

err_xrcd_table_free:
	mlx4_cleanup_xrcd_table(dev);

err_pd_table_free:
	mlx4_cleanup_pd_table(dev);

err_kar_unmap:
	iounmap(priv->kar);

err_uar_free:
	mlx4_uar_free(dev, &priv->driver_uar);

err_uar_table_free:
	mlx4_cleanup_uar_table(dev);
	return err;
}

static void mlx4_enable_msi_x(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct msix_entry *entries;
	int nreq = min_t(int, dev->caps.num_ports *
			 min_t(int, num_possible_cpus() + 1, MAX_MSIX_P_PORT)
				+ MSIX_LEGACY_SZ, MAX_MSIX);
	int err;
	int i;

	if (msi_x) {
		/* In multifunction mode each function gets 2 msi-X vectors
		 * one for data path completions anf the other for asynch events
		 * or command completions */
		if (mlx4_is_mfunc(dev)) {
			nreq = 4;
		} else {
			nreq = min_t(int, dev->caps.num_eqs -
				     dev->caps.reserved_eqs, nreq);
		}

		entries = kcalloc(nreq, sizeof *entries, GFP_KERNEL);
		if (!entries)
			goto no_msi;

		for (i = 0; i < nreq; ++i)
			entries[i].entry = i;

	retry:
		err = pci_enable_msix(dev->pdev, entries, nreq);
		if (err) {
			/* Try again if at least 2 vectors are available */
			if (err > 1) {
				mlx4_info(dev, "Requested %d vectors, "
					  "but only %d MSI-X vectors available, "
					  "trying again\n", nreq, err);
				nreq = err;
				goto retry;
			}
			kfree(entries);
			goto no_msi;
		}

		if (nreq <
		    MSIX_LEGACY_SZ + dev->caps.num_ports * MIN_MSIX_P_PORT) {
			/*Working in legacy mode , all EQ's shared*/
			dev->caps.poolsz           = 0;
			dev->caps.num_comp_vectors = nreq - 1;
		} else {
			dev->caps.poolsz           = nreq - MSIX_LEGACY_SZ;
			dev->caps.num_comp_vectors = MSIX_LEGACY_SZ - 1;
		}
		for (i = 0; i < nreq; ++i)
			priv->eq_table.eq[i].irq = entries[i].vector;

		dev->flags |= MLX4_FLAG_MSI_X;

		kfree(entries);
		return;
	}

no_msi:
	dev->caps.num_comp_vectors = 1;
	dev->caps.poolsz	   = 0;

	for (i = 0; i < 2; ++i)
		priv->eq_table.eq[i].irq = dev->pdev->irq;
}

static int mlx4_init_port_info(struct mlx4_dev *dev, int port)
{
	struct mlx4_port_info *info = &mlx4_priv(dev)->port[port];
	int err = 0;

	info->dev = dev;
	info->port = port;
	if (!mlx4_is_slave(dev)) {
		INIT_RADIX_TREE(&info->mac_tree, GFP_KERNEL);
		mlx4_init_mac_table(dev, &info->mac_table);
		mlx4_init_vlan_table(dev, &info->vlan_table);
		info->base_qpn = dev->caps.reserved_qps_base[MLX4_QP_REGION_ETH_ADDR] +
			(port - 1) * (1 << log_num_mac);
	}

	return err;
}

static void mlx4_cleanup_port_info(struct mlx4_port_info *info)
{
	if (info->port < 0)
		return;
}

static int mlx4_init_steering(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int num_entries = max(dev->caps.num_ports, dev->caps.pf_num);
	int i, j;

	priv->steer = kzalloc(sizeof(struct mlx4_steer) * num_entries, GFP_KERNEL);
	if (!priv->steer)
		return -ENOMEM;

	for (i = 0; i < num_entries; i++) {
		for (j = 0; j < MLX4_NUM_STEERS; j++) {
			INIT_LIST_HEAD(&priv->steer[i].promisc_qps[j]);
			INIT_LIST_HEAD(&priv->steer[i].steer_entries[j]);
		}
		INIT_LIST_HEAD(&priv->steer[i].high_prios);
	}
	return 0;
}

static void mlx4_clear_steering(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_steer_index *entry, *tmp_entry;
	struct mlx4_promisc_qp *pqp, *tmp_pqp;
	int num_entries = max(dev->caps.num_ports, dev->caps.pf_num);
	int i, j;

	for (i = 0; i < num_entries; i++) {
		for (j = 0; j < MLX4_NUM_STEERS; j++) {
			list_for_each_entry_safe(pqp, tmp_pqp,
						 &priv->steer[i].promisc_qps[j],
						 list) {
				list_del(&pqp->list);
				kfree(pqp);
			}
			list_for_each_entry_safe(entry, tmp_entry,
						 &priv->steer[i].steer_entries[j],
						 list) {
				list_del(&entry->list);
				list_for_each_entry_safe(pqp, tmp_pqp,
							 &entry->duplicates,
							 list) {
					list_del(&pqp->list);
					kfree(pqp);
				}
				kfree(entry);
			}
		}
	}
	kfree(priv->steer);
}

static int __mlx4_init_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct mlx4_priv *priv;
	struct mlx4_dev *dev;
	int err;
	int port;
	int i;

	printk(KERN_INFO PFX "Initializing %s\n", pci_name(pdev));

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable PCI device, "
			"aborting.\n");
		return err;
	}

	/*
	 * Check for BARs.  We expect 0: 1MB
	 */
	if ((((id == NULL) || !(id->driver_data & MLX4_VF)) &&
	     !(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) ||
	    pci_resource_len(pdev, 0) != 1 << 20) {
		dev_err(&pdev->dev, "Missing DCS, aborting.\n");
		err = -ENODEV;
		goto err_disable_pdev;
	}
	if (!(pci_resource_flags(pdev, 2) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "Missing UAR, aborting.\n");
		err = -ENODEV;
		goto err_disable_pdev;
	}

	err = pci_request_region(pdev, 0, DRV_NAME);
	if (err) {
		dev_err(&pdev->dev, "Cannot request control region, aborting.\n");
		goto err_disable_pdev;
	}

	err = pci_request_region(pdev, 2, DRV_NAME);
	if (err) {
		dev_err(&pdev->dev, "Cannot request UAR region, aborting.\n");
		goto err_release_bar0;
	}

	pci_set_master(pdev);

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		dev_warn(&pdev->dev, "Warning: couldn't set 64-bit PCI DMA mask.\n");
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "Can't set PCI DMA mask, aborting.\n");
			goto err_release_bar2;
		}
	}
	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		dev_warn(&pdev->dev, "Warning: couldn't set 64-bit "
			 "consistent PCI DMA mask.\n");
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "Can't set consistent PCI DMA mask, "
				"aborting.\n");
			goto err_release_bar2;
		}
	}

	priv = kzalloc(sizeof *priv, GFP_KERNEL);
	if (!priv) {
		dev_err(&pdev->dev, "Device struct alloc failed, "
			"aborting.\n");
		err = -ENOMEM;
		goto err_release_bar2;
	}

	dev       = &priv->dev;
	dev->pdev = pdev;
	INIT_LIST_HEAD(&priv->ctx_list);
	spin_lock_init(&priv->ctx_lock);

	mutex_init(&priv->port_mutex);
	mutex_init(&priv->port_ops_mutex);

	INIT_LIST_HEAD(&priv->pgdir_list);
	mutex_init(&priv->pgdir_mutex);
	for (i = 0; i < MLX4_MAX_PORTS; ++i)
		priv->iboe_counter_index[i] = -1;

	INIT_LIST_HEAD(&priv->bf_list);
	mutex_init(&priv->bf_mutex);

	atomic_set(&priv->opreq_count, 0);
	priv->opreq_queue = create_singlethread_workqueue("mlx4_opreq");
	if (!priv->opreq_queue) {
		mlx4_err(dev, "Failed to create workqueue for FW tasks");
		err = -ENOMEM;
		goto err_free_dev;
	}
	INIT_WORK(&priv->opreq_task, mlx4_opreq_action);

	pci_read_config_byte(pdev, PCI_REVISION_ID, &dev->rev_id);

	/* Detect if this device is a virtual function */
	if (id && id->driver_data & MLX4_VF) {
		/* When acting as pf, we normally skip vfs unless explicitly
		 * requested to probe them. */
		if (sr_iov && PCI_FUNC(pdev->devfn) > probe_vf) {
			mlx4_warn(dev, "Skipping virtual function:%d\n",
						PCI_FUNC(pdev->devfn));
			err = -ENODEV;
			goto err_workqueue;
		}
		mlx4_warn(dev, "Detected virtual function - running in slave mode\n");
		dev->flags |= MLX4_FLAG_SLAVE;
	}

	/* We reset the device and enable SRIOV only for physical devices */
	if (!mlx4_is_slave(dev)) {
		/* Claim ownership on the device,
		 * if already taken, act as slave*/
		err = mlx4_get_ownership(dev);
		if (err) {
			if (err < 0)
				goto err_workqueue;
			else {
				err = 0;
				dev->flags |= MLX4_FLAG_SLAVE;
				goto slave_start;
			}
		}

		/*
		 * Now reset the HCA before we touch the PCI capabilities or
		 * attempt a firmware command, since a boot ROM may have left
		 * the HCA in an undefined state.
		 */
		err = mlx4_reset(dev);
		if (err) {
			mlx4_err(dev, "Failed to reset HCA, aborting.\n");
			goto err_rel_own;
		}
		if (sr_iov) {
			mlx4_warn(dev, "Enabling sriov with:%d vfs\n", sr_iov);
			if (pci_enable_sriov(pdev, sr_iov)) {
				mlx4_err(dev, "Failed to enable sriov, aborting.\n");
				goto err_rel_own;
			}
			mlx4_warn(dev, "Running in master mode\n");
			dev->flags |= MLX4_FLAG_SRIOV | MLX4_FLAG_MASTER;
		}
	}

slave_start:
	err = mlx4_cmd_init(dev);
	if (err) {
		mlx4_err(dev, "Failed to init command interface, aborting.\n");
		goto err_sriov;
	}

	/* In slave functions, the communication channel must be initialized before
	 * posting commands */
	if (mlx4_is_slave(dev)) {
		err = mlx4_multi_func_init(dev);
		if (err) {
			mlx4_err(dev, "Failed to init slave mfunc interface, aborting.\n");
			goto err_cmd;
		}
	}

	err = mlx4_init_hca(dev);
	if (err) {
		if (err == -EACCES) {
			/* Not primary Physical function
			 * Running in slave mode */
			mlx4_cmd_cleanup(dev);
			dev->flags |= MLX4_FLAG_SLAVE;
			dev->flags &= ~MLX4_FLAG_MASTER;
			goto slave_start;
		} else
			goto err_cmd;
	}

	/* In master functions, the communication channel must be initialized after obtaining
	 * its address from fw */
	if (mlx4_is_master(dev)) {
		dev->num_slaves = MLX4_MAX_NUM_SLAVES;
		err = mlx4_multi_func_init(dev);
		if (err) {
			mlx4_err(dev, "Failed to init master mfunc interface, aborting.\n");
			goto err_close;
		}
	}

	err = mlx4_alloc_eq_table(dev);
	if (err)
		goto err_close;

	priv->msix_ctl.pool_bm = 0;
	mutex_init(&priv->msix_ctl.pool_lock);

	mlx4_enable_msi_x(dev);
	if (mlx4_is_slave(dev) && !(dev->flags & MLX4_FLAG_MSI_X)) {
		err = -ENOSYS;
		mlx4_err(dev, "INTx is not supported in slave mode, aborting.\n");
		goto err_free_eq;
	}

	if (!mlx4_is_slave(dev)) {
		err = mlx4_init_steering(dev);
		if (err)
			goto err_free_eq;
	}

	err = mlx4_setup_hca(dev);
	if (err == -EBUSY && (dev->flags & MLX4_FLAG_MSI_X) && !mlx4_is_slave(dev)) {
		dev->flags &= ~MLX4_FLAG_MSI_X;
		dev->caps.num_comp_vectors = 1;
		dev->caps.poolsz	   = 0;
		pci_disable_msix(pdev);
		err = mlx4_setup_hca(dev);
	}

	if (err)
		goto err_steer;

	for (port = 1; port <= dev->caps.num_ports; port++) {
		err = mlx4_init_port_info(dev, port);
		if (err)
			goto err_port;
	}

	err = mlx4_register_device(dev);
	if (err)
		goto err_port;

	pci_set_drvdata(pdev, dev);

	return 0;

err_port:
	for (--port; port >= 1; --port)
		mlx4_cleanup_port_info(&priv->port[port]);

	mlx4_cleanup_counters_table(dev);
	mlx4_cleanup_mcg_table(dev);
	mlx4_cleanup_qp_table(dev);
	mlx4_cleanup_srq_table(dev);
	mlx4_cleanup_cq_table(dev);
	mlx4_cmd_use_polling(dev);
	mlx4_cleanup_eq_table(dev);
	mlx4_cleanup_mr_table(dev);
	mlx4_cleanup_xrcd_table(dev);
	mlx4_cleanup_pd_table(dev);
	mlx4_cleanup_uar_table(dev);

err_steer:
	if (!mlx4_is_slave(dev))
		mlx4_clear_steering(dev);

err_free_eq:
	mlx4_free_eq_table(dev);

err_close:
	if (dev->flags & MLX4_FLAG_MSI_X)
		pci_disable_msix(pdev);

	mlx4_close_hca(dev);

err_cmd:
	mlx4_cmd_cleanup(dev);

err_sriov:
	if (mlx4_is_mfunc(dev))
		mlx4_multi_func_cleanup(dev);
	if (sr_iov && (dev->flags & MLX4_FLAG_SRIOV))
		pci_disable_sriov(pdev);

err_rel_own:
	if (!mlx4_is_slave(dev))
		mlx4_free_ownership(dev);
err_workqueue:
	destroy_workqueue(priv->opreq_queue);

err_free_dev:
	kfree(priv);

err_release_bar2:
	pci_release_region(pdev, 2);

err_release_bar0:
	pci_release_region(pdev, 0);

err_disable_pdev:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static int __devinit mlx4_init_one(struct pci_dev *pdev,
				   const struct pci_device_id *id)
{
	static int mlx4_version_printed;

	if (!mlx4_version_printed) {
		printk(KERN_INFO "%s", mlx4_version);
		++mlx4_version_printed;
	}

	return __mlx4_init_one(pdev, id);
}

static void mlx4_remove_one(struct pci_dev *pdev)
{
	struct mlx4_dev  *dev  = pci_get_drvdata(pdev);
	struct mlx4_priv *priv = mlx4_priv(dev);
	int p;

	if (dev) {
		mlx4_unregister_device(dev);

		for (p = 1; p <= dev->caps.num_ports; p++) {
			mlx4_cleanup_port_info(&priv->port[p]);
			mlx4_CLOSE_PORT(dev, p);
		}
		if (mlx4_is_master(dev)) {
			mlx4_free_resource_tracker(dev);

		if (priv->init_port_ref[p] != 0) {
				mlx4_warn(dev, "port %d was not properly closed\n",
						p);
			}
		}

		mlx4_cleanup_counters_table(dev);
		mlx4_cleanup_mcg_table(dev);
		mlx4_cleanup_qp_table(dev);
		mlx4_cleanup_srq_table(dev);
		mlx4_cleanup_cq_table(dev);
		mlx4_cmd_use_polling(dev);
		mlx4_cleanup_eq_table(dev);
		mlx4_cleanup_mr_table(dev);
		mlx4_cleanup_xrcd_table(dev);
		mlx4_cleanup_pd_table(dev);

		iounmap(priv->kar);
		mlx4_uar_free(dev, &priv->driver_uar);
		mlx4_cleanup_uar_table(dev);
		if (!mlx4_is_slave(dev))
			mlx4_clear_steering(dev);
		mlx4_free_eq_table(dev);
		mlx4_close_hca(dev);
		if (mlx4_is_mfunc(dev))
			mlx4_multi_func_cleanup(dev);
		mlx4_cmd_cleanup(dev);

		if (dev->flags & MLX4_FLAG_MSI_X)
			pci_disable_msix(pdev);
		if (sr_iov && (dev->flags & MLX4_FLAG_SRIOV)) {
			mlx4_warn(dev, "Disabling sriov\n");
			pci_disable_sriov(pdev);
		}

		destroy_workqueue(priv->opreq_queue);
		if (!mlx4_is_slave(dev))
			mlx4_free_ownership(dev);
		kfree(priv);
		pci_release_region(pdev, 2);
		pci_release_region(pdev, 0);
		pci_disable_device(pdev);
		pci_set_drvdata(pdev, NULL);
	}
}

int mlx4_restart_one(struct pci_dev *pdev)
{
	mlx4_remove_one(pdev);
	return __mlx4_init_one(pdev, NULL);
}

static struct pci_device_id mlx4_pci_table[] = {
	{ MLX4_VDEVICE(MELLANOX, 0x6340, 0) }, /* MT25408 "Hermon" SDR */
	{ MLX4_VDEVICE(MELLANOX, 0x6341, MLX4_VF) }, /* MT25408 "Hermon" SDR VF */
	{ MLX4_VDEVICE(MELLANOX, 0x634a, 0) }, /* MT25408 "Hermon" DDR */
	{ MLX4_VDEVICE(MELLANOX, 0x634b, MLX4_VF) }, /* MT25408 "Hermon" DDR VF */
	{ MLX4_VDEVICE(MELLANOX, 0x6354, 0) }, /* MT25408 "Hermon" QDR */
	{ MLX4_VDEVICE(MELLANOX, 0x6732, 0) }, /* MT25408 "Hermon" DDR PCIe gen2 */
	{ MLX4_VDEVICE(MELLANOX, 0x6733, MLX4_VF) }, /* MT25408 "Hermon" DDR PCIe gen2 VF */
	{ MLX4_VDEVICE(MELLANOX, 0x673c, 0) }, /* MT25408 "Hermon" QDR PCIe gen2 */
	{ MLX4_VDEVICE(MELLANOX, 0x673d, MLX4_VF) }, /* MT25408 "Hermon" QDR PCIe gen2 VF */
	{ MLX4_VDEVICE(MELLANOX, 0x6368, 0) }, /* MT25408 "Hermon" EN 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x6369, MLX4_VF) }, /* MT25408 "Hermon" EN 10GigE VF */
	{ MLX4_VDEVICE(MELLANOX, 0x6750, 0) }, /* MT25408 "Hermon" EN 10GigE PCIe gen2 */
	{ MLX4_VDEVICE(MELLANOX, 0x6751, MLX4_VF) }, /* MT25408 "Hermon" EN 10GigE PCIe gen2 VF */
	{ MLX4_VDEVICE(MELLANOX, 0x6372, 0) }, /* MT25458 ConnectX EN 10GBASE-T 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x6373, MLX4_VF) }, /* MT25458 ConnectX EN 10GBASE-T 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x675a, 0) }, /* MT25458 ConnectX EN 10GBASE-T+Gen2 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x675b, MLX4_VF) }, /* MT25458 ConnectX EN 10GBASE-T+Gen2 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x6764, 0) }, /* MT26468 ConnectX EN 10GigE PCIe gen2*/
	{ MLX4_VDEVICE(MELLANOX, 0x6765, MLX4_VF) }, /* MT26468 ConnectX EN 10GigE PCIe gen2 VF*/
	{ MLX4_VDEVICE(MELLANOX, 0x6746, 0) }, /* MT26438 ConnectX VPI PCIe 2.0 5GT/s - IB QDR / 10GigE Virt+ */
	{ MLX4_VDEVICE(MELLANOX, 0x6747, MLX4_VF) }, /* MT26438 ConnectX VPI PCIe 2.0 5GT/s - IB QDR / 10GigE Virt+ VF*/
	{ MLX4_VDEVICE(MELLANOX, 0x676e, 0) }, /* MT26478 ConnectX EN 40GigE PCIe 2.0 5GT/s */
	{ MLX4_VDEVICE(MELLANOX, 0x676f, MLX4_VF) }, /* MT26478 ConnectX EN 40GigE PCIe 2.0 5GT/s VF*/
	{ MLX4_VDEVICE(MELLANOX, 0x6778, 0) }, /* MT26488 ConnectX VPI PCIe 2.0 5GT/s - IB DDR / 10GigE Virt+ */
	{ MLX4_VDEVICE(MELLANOX, 0x6779, MLX4_VF) }, /* MT26488 ConnectX VPI PCIe 2.0 5GT/s - IB DDR / 10GigE Virt+ VF*/
	{ PCI_VDEVICE(MELLANOX, 0x1000) },
	{ PCI_VDEVICE(MELLANOX, 0x1001) },
	{ PCI_VDEVICE(MELLANOX, 0x1002) },
	{ PCI_VDEVICE(MELLANOX, 0x1003) },
	{ PCI_VDEVICE(MELLANOX, 0x1004) },
	{ PCI_VDEVICE(MELLANOX, 0x1005) },
	{ PCI_VDEVICE(MELLANOX, 0x1006) },
	{ PCI_VDEVICE(MELLANOX, 0x1007) },
	{ PCI_VDEVICE(MELLANOX, 0x1008) },
	{ PCI_VDEVICE(MELLANOX, 0x1009) },
	{ PCI_VDEVICE(MELLANOX, 0x100a) },
	{ PCI_VDEVICE(MELLANOX, 0x100b) },
	{ PCI_VDEVICE(MELLANOX, 0x100c) },
	{ PCI_VDEVICE(MELLANOX, 0x100d) },
	{ PCI_VDEVICE(MELLANOX, 0x100e) },
	{ PCI_VDEVICE(MELLANOX, 0x100f) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, mlx4_pci_table);

static int suspend(struct pci_dev *pdev, pm_message_t state)
{
	mlx4_remove_one(pdev);

	return 0;
}

static int resume(struct pci_dev *pdev)
{
	return __mlx4_init_one(pdev, NULL);
}

static struct pci_driver mlx4_driver = {
	.name		= DRV_NAME,
	.id_table	= mlx4_pci_table,
	.probe		= mlx4_init_one,
	.remove		= __devexit_p(mlx4_remove_one),
	.suspend	= suspend,
	.resume		= resume,
};

static int __init mlx4_verify_params(void)
{
	if ((log_num_mac < 0) || (log_num_mac > 7)) {
		printk(KERN_WARNING "mlx4_core: bad num_mac: %d\n", log_num_mac);
		return -1;
	}

	if ((log_mtts_per_seg < 0) || (log_mtts_per_seg > 7)) {
		printk(KERN_WARNING "mlx4_core: bad log_mtts_per_seg: %d\n", log_mtts_per_seg);
		return -1;
	}

	if (mod_param_profile.num_qp && mod_param_profile.num_qp < 12) {
		printk(KERN_WARNING "mlx4_core: too low log_num_qp: %d\n", mod_param_profile.num_qp);
		return -1;
	}

	if (mod_param_profile.num_srq && mod_param_profile.num_srq < 10) {
		printk(KERN_WARNING "mlx4_core: too low log_num_srq: %d\n", mod_param_profile.num_srq);
		return -1;
	}

	if (mod_param_profile.num_cq && mod_param_profile.num_cq < 10) {
		printk(KERN_WARNING "mlx4_core: too low log_num_cq: %d\n", mod_param_profile.num_cq);
		return -1;
	}

	if (mod_param_profile.num_mpt && mod_param_profile.num_mpt < 10) {
		printk(KERN_WARNING "mlx4_core: too low log_num_mpt: %d\n", mod_param_profile.num_mpt);
		return -1;
	}

	if (mod_param_profile.num_mtt && mod_param_profile.num_mtt < 15) {
		printk(KERN_WARNING "mlx4_core: too low log_num_mtt: %d\n", mod_param_profile.num_mtt);
		return -1;
	}

	return 0;
}

static int __init mlx4_init(void)
{
	int ret;

	mutex_init(&drv_mutex);

	if (mlx4_verify_params())
		return -EINVAL;

	mlx4_catas_init();

	mlx4_wq = create_singlethread_workqueue("mlx4");
	if (!mlx4_wq)
		return -ENOMEM;

	ret = pci_register_driver(&mlx4_driver);
	return ret < 0 ? ret : 0;
}

static void __exit mlx4_cleanup(void)
{
	mutex_lock(&drv_mutex);
	mlx4_config_cleanup();
	pci_unregister_driver(&mlx4_driver);
	mutex_unlock(&drv_mutex);
	destroy_workqueue(mlx4_wq);
}

module_init(mlx4_init);
module_exit(mlx4_cleanup);
