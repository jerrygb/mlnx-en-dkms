/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2005, 2006, 2007 Cisco Systems, Inc.  All rights reserved.
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

#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <asm/io.h>

#include "mlx4.h"
#include "fw.h"

/* resource tracker functions*/
static inline int verify_rt_resource_typ(int resource_type)
{
	return ((resource_type < MLX4_NUM_OF_RESOURCE_TYPE) && (resource_type >= 0)) ? 0 : -1 ;
}

static inline int verify_rt_slave_id(struct mlx4_dev *dev, int slave_id)
{
	return ((slave_id < dev->num_slaves) && (slave_id >= 0)) ? 0 : -1 ;
}

/* For Debug uses */
char *ResourceType(enum mlx4_resource rt)
{
	switch (rt) {
	case RES_QP: return "RES_QP";
	case RES_CQ: return "RES_CQ";
	case RES_SRQ: return "RES_SRQ";
	case RES_MPT: return "RES_MPT";
	case RES_MTT: return "RES_MTT";
	case RES_MAC: return  "RES_MAC";
	case RES_VLAN: return "RES_VLAN";
	case RES_MCAST: return "RES_MCAST";
	default: return "";
	};
}

void dump_resources(struct mlx4_dev *dev, int slave_id, enum mlx4_resource res_type)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_tracked_resource *tracked_res;
	mlx4_dbg(dev, "\n*************************************\n"
		      "Dump resources:%d for Salve:%d \n",
		  res_type, slave_id);
	list_for_each_entry(tracked_res, &priv->mfunc.master.res_tracker.res_list[slave_id], list) {
		if (res_type == tracked_res->res_type)
			mlx4_dbg(dev, "* resource id: %d\n", tracked_res->resource_id);
	}
	mlx4_dbg(dev, "\n*************************************\n");
}

int mlx4_init_resource_tracker(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int i;

	priv->mfunc.master.res_tracker.res_list = kzalloc(dev->num_slaves *
							   sizeof (struct list_head), GFP_KERNEL);
	if (!priv->mfunc.master.res_tracker.res_list)
		return -ENOMEM;

	for (i = 0 ; i < dev->num_slaves; i++)
		INIT_LIST_HEAD(&priv->mfunc.master.res_tracker.res_list[i]);

	mlx4_dbg(dev, "Started init_resource_tracker: %ld slaves \n", dev->num_slaves);
	for (i = 0 ; i < MLX4_NUM_OF_RESOURCE_TYPE; i++)
		INIT_RADIX_TREE(&priv->mfunc.master.res_tracker.res_tree[i],
	 GFP_ATOMIC|__GFP_NOWARN);

	spin_lock_init(&priv->mfunc.master.res_tracker.lock);
	return 0 ;
}

void mlx4_free_resource_tracker(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int i;
	if (priv->mfunc.master.res_tracker.res_list) {
		for (i = 0 ; i < dev->num_slaves; i++)
			mlx4_delete_all_resources_for_slave(dev, i);

		kfree(priv->mfunc.master.res_tracker.res_list);
	}
	priv->mfunc.master.res_tracker.res_list = NULL;
}


int mlx4_get_slave_from_resource_id(struct mlx4_dev *dev, enum mlx4_resource resource_type,
				     int resource_id, int *slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_tracked_resource *rt;

	if (verify_rt_resource_typ(resource_type)) {
			mlx4_warn(dev, "mlx4_get_slave_from_resource_id,"
				  "res_type(%d) is not valid\n",
				   resource_type);
			return -EINVAL;
	}

	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
	rt = radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[resource_type],
			       resource_id);
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
	if (NULL == rt) {
		/*
		mlx4_dbg(dev, "mlx4_get_slave_from_resource_id radix_tree_lookup "
			 "(res_type:%d) FAILED for resource_id: %d\n",
				 resource_type, resource_id);
		*/
		return -ENOENT;
	}
	*slave = rt->slave_id;
	return 0 ;
}

/*
There are resources that allocated in 2 steps, the first is the reservation,
the second is the allocation.
In order to track after the state of the resource the structure needs to
save the reservation status,
it should be one of the next list:
	RES_INIT
	RES_RESERVED
	RES_ALLOCATED
	RES_ALLOCATED_AFTER_RESERVATION
The tegular resources (the kind that has one step of allocation will get RES_INIT
when they tracked (created).
the rest will have the relevant steps.)
*/
int update_resource_reservation_status(struct mlx4_dev *dev, int resource_type,
				       int slave_id, int resource_id,
				       enum mlx4_resource_state state)
{
	int ret = 0;
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_tracked_resource *tracked_res;

	if ((verify_rt_resource_typ(resource_type)) || verify_rt_slave_id(dev, slave_id))
		return -EINVAL;

	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);

	tracked_res = radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[resource_type],
					 resource_id);
	if (!tracked_res) {
		mlx4_err(dev, "Failed to find resource type: %d id: %d state: %d\n",
			  resource_type, resource_id, state);
		ret =  -ENOENT;
		goto exit;
	}
	set_bit(state, &tracked_res->state) ;

exit:
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
	return ret ;
}

int mlx4_add_resource_for_slave(struct mlx4_dev *dev, enum mlx4_resource resource_type,
				 int slave_id, int resource_id, unsigned long state)
{
	int ret = 0;
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_tracked_resource *tracked_res;
	struct mlx4_tracked_resource *qp_tracked_res;
	int tmp_slave_id;
	mlx4_dbg(dev, "mlx4_add_resource_for_slave: slave:%d, res:%d res_id:%d\n",
		  slave_id, resource_type, resource_id);
	if ((verify_rt_resource_typ(resource_type)) || verify_rt_slave_id(dev, slave_id))
		return -EINVAL;

	/* if the resource is qp or mtt it allready was created in the reservationstage,
	 so don't need to allocat it, only to change the status of the resrevation.
	*/
	if (RES_ALLOCATED_AFTER_RESERVATION == state) {
		ret = update_resource_reservation_status(dev, resource_type, slave_id,
							  resource_id, state);
		/*Only for this state we return here.*/
		return ret ;
	}

	/*Sanity check that the object does not exist*/
	ret = mlx4_get_slave_from_resource_id(dev, resource_type, resource_id,
					       &tmp_slave_id);
	if (0 == ret) {
		if (RES_QP == resource_type) {
			/*check if it is the case where the master reserverd qp
			 for the slave, and now the slave allocates it.*/
			spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
			/*check the status first.*/
			qp_tracked_res =
				radix_tree_lookup(
					&priv->mfunc.master.res_tracker.res_tree[resource_type],
					 resource_id
					);
			spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
			if (qp_tracked_res) {
			/*check the state:*/
				if (test_bit(RES_ALLOCATED_WITH_MASTER_RESERVATION,
					      &qp_tracked_res->state)) {
					ret = update_resource_reservation_status(dev,
										 resource_type,
										 slave_id,
										 resource_id,
										 state);
					mlx4_dbg(dev, "Resource(%d:%d) was created"
						 "for slave:%d by master\n",
						 resource_type, resource_id, slave_id);
					return ret;
				}
			}
		}
		mlx4_err(dev, "mlx4_add_resource_for_slave Adding already exists object,"
			 " slave:%d res_type:"
			" %d res_id:%d\n", slave_id, resource_type, resource_id);
		return -EEXIST;
	}
	tracked_res = kzalloc(sizeof (struct mlx4_tracked_resource), GFP_KERNEL);
	if (!tracked_res)
		return -ENOMEM;

	tracked_res->slave_id = slave_id ;
	tracked_res->res_type = resource_type ;
	tracked_res->resource_id = resource_id ;
	set_bit(state, &tracked_res->state) ;

	/*if it is qp create list for the mcg */
	if ((RES_QP == resource_type))
		INIT_LIST_HEAD(&tracked_res->specific_data.mcg_list);

	/* add it to the specific tree and to the list */
	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
	ret = radix_tree_insert(&priv->mfunc.master.res_tracker.res_tree[resource_type],
				 resource_id, tracked_res);
	if (ret) {
		/*-EEXIST or -ENOMEM */
		mlx4_dbg(dev, "mlx4_add_resource_for_slave: Failed to add resource"
			 " slave:%d, res:%d res_id:%d\n",
			  slave_id, resource_type, resource_id);
		kfree(tracked_res);
		goto exit;
	}
	list_add(&tracked_res->list, &priv->mfunc.master.res_tracker.res_list[slave_id]);
exit:
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
	return ret ;
}


int mlx4_add_mpt_resource_for_slave(struct mlx4_dev *dev,
				    enum mlx4_resource resource_type, int slave_id,
				    int resource_id, unsigned long state)
{
	return mlx4_add_resource_for_slave(dev, resource_type, slave_id,
					   (resource_id & (dev->caps.num_mpts - 1)),
					    state);
}
/* The function cleans the hw resources that were allocated for this resource,
   Assume that calling this function only in cases that the slave is going down
   and have open resources allocated by it.
*/
void mlx4_clean_specific_hw_resource(struct mlx4_dev *dev,
				      struct mlx4_tracked_resource *tracked_res)
{
	switch (tracked_res->res_type) {
	case RES_QP: {
			struct mlx_tracked_qp_mcg *tracked_mcg;
			struct mlx_tracked_qp_mcg *tmp_tracked_mcg;
			struct mlx4_qp qp; /* dummy for calling attach/detach */
			qp.qpn = tracked_res->resource_id;
			if (test_bit(RES_ALLOCATED_AFTER_RESERVATION, &tracked_res->state)) {
					mlx4_qp_free_icm(dev, tracked_res->resource_id);
				/* free all the mcg that the qp attached to*/
				list_for_each_entry_safe(tracked_mcg,
							  tmp_tracked_mcg,
							  &tracked_res->specific_data.mcg_list,
							  list) {
					mlx4_qp_detach_common(dev, &qp, tracked_mcg->gid,
							      tracked_mcg->prot, MLX4_MC_STEER, 0);
				}
			} else {
				/*If the master reserved no need to free reservation*/
				if (!test_bit(RES_ALLOCATED_WITH_MASTER_RESERVATION,
					       &tracked_res->state))
					mlx4_qp_release_range(dev, tracked_res->resource_id, 1);
			}
			break;
		}
	case RES_MPT:
		if (test_bit(RES_ALLOCATED_AFTER_RESERVATION, &tracked_res->state)) {
			mlx4_mr_free_icm(dev, tracked_res->resource_id);
		} else {
			mlx4_mr_release(dev, tracked_res->resource_id);
		}
		break;
	case RES_CQ:
		mlx4_cq_free_icm(dev, tracked_res->resource_id);
		break;
	case RES_SRQ:
		mlx4_srq_free_icm(dev, tracked_res->resource_id);
		break;
	case RES_MTT:
		mlx4_free_mtt_range(dev, tracked_res->resource_id,
				     tracked_res->specific_data.order);
		break;
	case RES_MAC:
		mlx4_unregister_mac(dev, tracked_res->specific_data.port,
				     tracked_res->resource_id) ;
		break;
	case RES_VLAN: {
			/*clear all the bits (vlans) of this slave*/
			struct mlx4_vlan_fltr vlan_fltr ;
			memset(&vlan_fltr, 0, sizeof(struct mlx4_vlan_fltr));
			mlx4_common_set_vlan_fltr(dev, tracked_res->slave_id,
						  tracked_res->specific_data.port, &vlan_fltr);
		}
		break;
	default:
		break;
	}
}

/* The function removes resources from the resource_tracking database only.
(not cleaning the from the hw)*/
void mlx4_delete_resource_for_slave(struct mlx4_dev *dev, enum mlx4_resource resource_type,
				    int slave_id, int resource_id)
{
	struct mlx4_tracked_resource *tracked_res = NULL ;
	struct mlx4_priv *priv = mlx4_priv(dev);
	int ret = 0 ;

	if ((verify_rt_resource_typ(resource_type)) || verify_rt_slave_id(dev, slave_id)) {
		mlx4_err(dev, "mlx4_delete_resource_for_slave, error input,"
			      " slave:%d res_type: %d res_id:%d\n",
			 slave_id, resource_type, resource_id);
		return ;
	}

	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
	/*check the status first.*/
	tracked_res = radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[resource_type],
					 resource_id);
	if (!tracked_res) {
		ret =  -ENOENT;
		goto exit;
	}
	/* if we are in qp or mtt the resource is not deleted till the release of
	   the reservation so only needs to change the status of the allocation
	   to became false
	*/
	if (test_bit(RES_ALLOCATED_AFTER_RESERVATION, &tracked_res->state)) {
		clear_bit(RES_ALLOCATED_AFTER_RESERVATION, &tracked_res->state);
		goto exit;
	}

	mlx4_dbg(dev, "mlx4_delete_resource_for_slave slave:%d res_type: %d res_id:%d\n",
		 slave_id, resource_type, resource_id);

	tracked_res = radix_tree_delete(&priv->mfunc.master.res_tracker.res_tree[resource_type],
					 resource_id);
	if (!tracked_res) {
		ret =  -ENOENT;
		goto exit;
	}
	list_del(&tracked_res->list);
	kfree(tracked_res);

exit:
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
	if (ret) {
		mlx4_err(dev, "mlx4_delete_resource_for_slave,"
			      " error deleting, slave:%d res_type: %d res_id:%d"
			      " return: %d\n",
			 slave_id, resource_type, resource_id, ret);
	}
}

void mlx4_delete_specific_res_type_for_slave(struct mlx4_dev *dev, int slave_id,
					     enum mlx4_resource resource_type)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_tracked_resource *tracked_res;
	struct mlx4_tracked_resource *tmp_rt;
	mlx4_dbg(dev, "mlx4_delete_specific_res_type_for_slave: Go over"
		      " slave:%d res_type: %d \n",
		  slave_id, resource_type);
/*TODO: replace the list head to avoid race on the the same list.*/
	list_for_each_entry_safe(tracked_res, tmp_rt, &priv->mfunc.master.res_tracker.res_list[slave_id], list) {
		mlx4_dbg(dev, "mlx4_delete_all_resources_for_slave: Go over slave:%d"
			      " id: %d \n", tracked_res->slave_id,
			 tracked_res->resource_id);
		if (tracked_res->res_type == resource_type) {
			/* clean the hw*/
			mlx4_clean_specific_hw_resource(dev, tracked_res);
			/*clean the resource_tracker*/
			mlx4_delete_resource_for_slave(dev, tracked_res->res_type,
						       tracked_res->slave_id, tracked_res->resource_id);
		}
	}
}

/* The function is calling when you want to clean all resources that were occupied for specific slave.
   The function does 2 things:
				1. cleans the resources from the hw.
				2. cleans the resource tracker db.
	Pay attention: the order of the releasing is like in the ibvers, e.g :
		QP->SRQ->CQ-> MTT-> MPT
*/
void mlx4_delete_all_resources_for_slave(struct mlx4_dev *dev, int slave_id)
{
	mlx4_dbg(dev, "1. mlx4_delete_all_resources_for_slave:%d\n", slave_id);
	if (verify_rt_slave_id(dev, slave_id)) {
		mlx4_err(dev, "mlx4_delete_all_resources_for_slave: error input,"
			      " slave:%d \n", slave_id);
		return;
	}
	/*VLAN*/
	mlx4_delete_specific_res_type_for_slave(dev, slave_id, RES_VLAN);
	/* MAC */
	mlx4_delete_specific_res_type_for_slave(dev, slave_id, RES_MAC);
	/* QP: allocation */
	/*dump_resources(dev, slave_id, RES_QP);*/
	mlx4_delete_specific_res_type_for_slave(dev, slave_id, RES_QP);
	/*QP: reservation*/
	mlx4_delete_specific_res_type_for_slave(dev, slave_id, RES_QP);
	/*SRQ*/
	mlx4_delete_specific_res_type_for_slave(dev, slave_id, RES_SRQ);
	/*CQ*/
	mlx4_delete_specific_res_type_for_slave(dev, slave_id, RES_CQ);
	/*MTT*/
	mlx4_delete_specific_res_type_for_slave(dev, slave_id, RES_MTT);
	/*MPT : allocation*/
	mlx4_delete_specific_res_type_for_slave(dev, slave_id, RES_MPT);
	/*MPT: reservation*/
	mlx4_delete_specific_res_type_for_slave(dev, slave_id, RES_MPT);

}

int mlx4_add_range_resource_for_slave(struct mlx4_dev *dev, enum mlx4_resource resource_type,
				       int slave_id, int from, int cnt)
{
	int i;
	int ret = 0;
	for (i = from; i < (from + cnt); i++) {
		ret |= mlx4_add_resource_for_slave(dev, resource_type, slave_id, i, RES_INIT);
	}
	return ret ;
}

void mlx4_delete_range_resource_for_slave(struct mlx4_dev *dev,
					  enum mlx4_resource resource_type, int slave_id, int from, int cnt)
{
	int i;
	for (i = from; i < (from + cnt); i++) {
		mlx4_delete_resource_for_slave(dev, resource_type, slave_id, i);
	}
}

int mlx4_add_mtt_resource_for_slave(struct mlx4_dev *dev,
				    int slave_id, int resource_id,
				    unsigned long state, int order)
{
	int ret = 0 ;
	struct mlx4_tracked_resource *tracked_res;
	struct mlx4_priv *priv = mlx4_priv(dev);

	ret = mlx4_add_resource_for_slave(dev, RES_MTT, slave_id,
					   resource_id,
					    state);
	if (ret) {
		mlx4_info(dev, "ERROR: mlx4_add_mtt_resource_for_slave failed: ret = %d \n",
			ret);
		return ret;
	}
	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
	tracked_res = radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[RES_MTT], resource_id);
	if (!tracked_res) {
		ret =  -ENOENT;
		goto exit;
	}
	tracked_res->specific_data.order = order ;
exit:
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
	return ret ;
}

int mlx4_add_mcg_to_tracked_qp(struct mlx4_dev *dev, int qpn, u8* gid, enum mlx4_protocol prot)
{
	struct mlx_tracked_qp_mcg *new_qp_in_mcg ;
	struct mlx4_tracked_resource *tracked_res;
	int ret = 0 ;
	struct mlx4_priv *priv = mlx4_priv(dev);

	new_qp_in_mcg = kzalloc(sizeof (struct mlx_tracked_qp_mcg), GFP_KERNEL);
	if (!new_qp_in_mcg)
		return -ENOMEM;

	memcpy(new_qp_in_mcg->gid, gid, GID_SIZE);
	new_qp_in_mcg->prot = prot;
	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
	tracked_res = radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[RES_QP], qpn);
	if (!tracked_res) {
		ret =  -ENOENT;
		kfree(new_qp_in_mcg);
		goto exit;
	}
	mlx4_dbg(dev, "mlx4_add_mcg_to_tracked_qp: added new mcg to qpn: %d \n", qpn);
	list_add(&new_qp_in_mcg->list, &tracked_res->specific_data.mcg_list);

exit:
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
	return ret ;
}

int mlx4_remove_mcg_from_tracked_qp(struct mlx4_dev *dev, int qpn, u8* gid)
{
	struct mlx4_tracked_resource *tracked_res;
	struct mlx_tracked_qp_mcg *tracked_mcg;
	struct mlx_tracked_qp_mcg *tmp_tracked_mcg;
	int ret = -ENXIO ;
	struct mlx4_priv *priv = mlx4_priv(dev);

	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
	tracked_res = radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[RES_QP],
					 qpn);
	if (!tracked_res) {
		ret =  -ENOENT;
		goto exit;
	}
	mlx4_dbg(dev, "mlx4_remove_mcg_from_tracked_qp: delete"
		      " mcg from qpn: %d \n", qpn);
	list_for_each_entry_safe(tracked_mcg, tmp_tracked_mcg,
				  &tracked_res->specific_data.mcg_list, list) {
		if (!memcmp(tracked_mcg->gid, gid, GID_SIZE)) {
			list_del(&tracked_mcg->list);
			kfree(tracked_mcg);
			tracked_mcg = NULL;
			ret = 0 ;
			break;
		}
	}

exit:
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
	return ret ;
}

int mlx4_add_port_to_tracked_mac(struct mlx4_dev *dev, int qpn, u8 port)
{
	struct mlx4_tracked_resource *tracked_res;
	int ret = 0 ;
	struct mlx4_priv *priv = mlx4_priv(dev);

	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
	tracked_res = radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[RES_MAC], qpn);
	if (!tracked_res) {
		ret =  -ENOENT;
		goto exit;
	}
	mlx4_dbg(dev, "mlx4_add_port_to_tracked_macmlx4_add_mcg_to_tracked_qp:"
		      " added port:%d in key(qpn): %d \n",
		 port, qpn);

	tracked_res->specific_data.port = port ;

exit:
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
	return ret ;
}

/* 	The function assumes that there is only one filter per slave
	so, it tries first to remove the resource if already exists,
	and after that add new resource,
	and to this resource attaches the (one and only)new filter.*/
int mlx4_add_vlan_fltr_to_tracked_slave(struct mlx4_dev *dev, int slave_id,  int port)
{
	struct mlx4_tracked_resource *tracked_res;
	int ret = 0 ;
	struct mlx4_priv *priv = mlx4_priv(dev);
	bool vlan_exists = false;

	if (verify_rt_slave_id(dev, slave_id))
		return -EINVAL;

	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
	if (radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[RES_VLAN], slave_id))
		vlan_exists = true;
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);

	if (vlan_exists)
		mlx4_delete_resource_for_slave(dev, RES_VLAN, slave_id, slave_id);

	ret = mlx4_add_resource_for_slave(dev, RES_VLAN, slave_id,
					  slave_id/*the slave is also the key*/, RES_INIT);
	if (0 != ret) {
		mlx4_err(dev, "mlx4_add_vlan_fltr_to_tracked_slave: Failed to "
			      "add new resource key(slave_id): %d \n", slave_id);
		return ret;
	}

	spin_lock_irq(&priv->mfunc.master.res_tracker.lock);
	tracked_res = radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[RES_VLAN], slave_id);
	if (!tracked_res) {
		ret =  -ENOENT;
		goto exit;
	}
	mlx4_dbg(dev, "mlx4_add_vlan_fltr_to_tracked_slave: added filter"
		      "  key(slave_id): %d \n", slave_id);
	tracked_res->specific_data.port = port ;

exit:
	spin_unlock_irq(&priv->mfunc.master.res_tracker.lock);
	return ret ;
}

int verify_resource_belong_to_slave(struct mlx4_dev *dev, int slave,
				    enum mlx4_resource resource_type, int resource_id)
{
	int slave_from_db = -1;
	int ret;
	ret =  mlx4_get_slave_from_resource_id(dev, resource_type, resource_id, &slave_from_db) ;
	if ((0 == ret) && (slave_from_db == slave)) {
		mlx4_dbg(dev, "Verify resource:%d from type: %d,"
			      " belong to slave: %d\n",
			  resource_id, resource_type, slave);
		return 0 ;
	}

	mlx4_err(dev, "Verify resource:%d from type: %d,"
		      " DOES NOT belong to slave: %d\n",
		  resource_id, resource_type, slave);
	return -ENOENT;
}

int mlx4_verify_mpt_index(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
						  struct mlx4_cmd_mailbox *inbox)
{
	u32 bit_mask;
	/*dump_resources(dev, slave, RES_MPT); */
	bit_mask = calculate_bitmap_mask(dev, RES_MPT);
	return verify_resource_belong_to_slave(dev, slave, RES_MPT,
					       (vhcr->in_modifier & bit_mask));
}

int mlx4_verify_cq_index(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
						  struct mlx4_cmd_mailbox *inbox)
{
	return verify_resource_belong_to_slave(dev, slave, RES_CQ, vhcr->in_modifier);
}

int mlx4_verify_srq_index(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
						  struct mlx4_cmd_mailbox *inbox)
{
	return verify_resource_belong_to_slave(dev, slave, RES_SRQ, vhcr->in_modifier);
}

int mlx4_verify_qp_index(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
			struct mlx4_cmd_mailbox *inbox)
{
	dump_resources(dev, slave, RES_QP);
	return verify_resource_belong_to_slave(dev, slave, RES_QP, (vhcr->in_modifier &
						0xffffff/*(dev->caps.num_qps - 1)*/));
}

int mlx4_verify_srq_aram(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
			struct mlx4_cmd_mailbox *inbox)
{
	if (test_bit(31, (const unsigned long *)&vhcr->in_modifier)) /*RQ*/
		return verify_resource_belong_to_slave(dev, slave, RES_QP,
			(vhcr->in_modifier & 0xffffff/*(dev->caps.num_qps - 1)*/));
	/*SRQ*/
	return verify_resource_belong_to_slave(dev, slave, RES_SRQ,
					       (vhcr->in_modifier & 0xffffff));
}
/*
	The function checks which slave can asks for each resource,
	currently the relevant resources are QP and MTT, where there are 2 stages of allocation
	The reservation and the icm_allocation
*/
int mlx4_verify_resource_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
						  struct mlx4_cmd_mailbox *inbox)
{
	u32 param1 = *((u32 *) &vhcr->in_param);
	u32 param2 = *(((u32 *) &vhcr->in_param) + 1);
	int i ;
	int ret = 0 ;
	switch (vhcr->in_modifier) {
	case RES_QP:
		switch (vhcr->op_modifier) {
		case ICM_RESERVE:
			if (vhcr->op == MLX4_CMD_ALLOC_RES) {
				/*nothing to do*/
				return 0;
			}
			/*check this is its qp that it wants to free */
			for (i = 0 ; i < param2; i++) {
				ret = verify_resource_belong_to_slave(dev,
								       slave,
								       RES_QP,
								       param1 + i);
				if (ret)
					return ret;
			}
			return 0 ;
		case ICM_ALLOC:
			/*check this is its qp*/
			return verify_resource_belong_to_slave(dev, slave, RES_QP, param1);
		default:
			mlx4_err(dev, "mlx4_verify_resource_wrapper:(QP) Got unknown"
				"op_modifier:%d for slave:%d.\n",
				vhcr->op_modifier, slave);
			break;
		}
		break;
	case RES_MPT:
		switch (vhcr->op_modifier) {
		case ICM_RESERVE:
			if (vhcr->op == MLX4_CMD_ALLOC_RES) {
				/*nothing to do*/
				return 0;
			}
			/*check this is its mpt*/
			return verify_resource_belong_to_slave(dev,
							       slave,
							       RES_MPT,
							       param1 & calculate_bitmap_mask(dev, RES_MPT));

		case ICM_ALLOC:
			/*check this is its mpt*/
			return verify_resource_belong_to_slave(dev,
							       slave,
							       RES_MPT,
							       param1 & calculate_bitmap_mask(dev, RES_MPT));

		default:
			mlx4_err(dev, "mlx4_verify_resource_wrapper:(MPT) Got unknown"
				"op_modifier:%d for slave:%d.\n",
				vhcr->op_modifier, slave);
			break;
		}
		break;
	default:
		break;
	}
	return 0;
}
/*Ruturns the mask according to specific bitmap allocator*/
u32 calculate_bitmap_mask(struct mlx4_dev *dev, enum mlx4_resource resource_type)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	u32 ret = ~0;
	switch (resource_type) {
	case RES_QP:
		/*ret = priv->qp_table.bitmap.max + priv->qp_table.bitmap.reserved_top - 1 ;*/
		ret = (dev->caps.num_qps - 1);
		break;
	case RES_MPT:
		ret = priv->mr_table.mpt_bitmap.max + priv->mr_table.mpt_bitmap.reserved_top - 1 ;
		break;
	default:
		mlx4_warn(dev, "calculate_bitmap_mask: Unknown type, check it...\n");
		break;
	}
	return ret;
}

