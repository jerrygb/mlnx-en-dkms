#ifndef __BACKPORT_LINUX_IF_VLAN_H_TO_2_6_37__
#define __BACKPORT_LINUX_IF_VLAN_H_TO_2_6_37__

#include_next <linux/if_vlan.h>

#define VLAN_GROUP_ARRAY_LEN          4096

static inline struct net_device *vlan_group_get_device(struct vlan_group *vg,
						      u16 vlan_id)
{
	struct net_device **array;
	array = vg->vlan_devices_arrays[vlan_id / VLAN_GROUP_ARRAY_PART_LEN];
	return array ? array[vlan_id % VLAN_GROUP_ARRAY_PART_LEN] : NULL;
}

static inline void vlan_group_set_device(struct vlan_group *vg,
					u16 vlan_id,
					struct net_device *dev)
{
	struct net_device **array;
	if (!vg)
		return;
	array = vg->vlan_devices_arrays[vlan_id / VLAN_GROUP_ARRAY_PART_LEN];
	array[vlan_id % VLAN_GROUP_ARRAY_PART_LEN] = dev;
}

#endif
