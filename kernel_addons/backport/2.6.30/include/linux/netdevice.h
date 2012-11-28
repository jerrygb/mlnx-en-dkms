#ifndef BACKPORT_LINUX_NETDEVICE_TO_2_6_38
#define BACKPORT_LINUX_NETDEVICE_TO_2_6_38

#include_next <linux/netdevice.h>

static inline int netif_is_bond_slave(struct net_device *dev)
{
        return dev->flags & IFF_SLAVE && dev->priv_flags & IFF_BONDING;
}

#endif
