#ifndef __BACKPORT_LINUX_NETDEVICE_H_TO_2_6_25__
#define __BACKPORT_LINUX_NETDEVICE_H_TO_2_6_25__

#include_next <linux/netdevice.h>

static inline
struct net *dev_net(const struct net_device *dev)
{
#ifdef CONFIG_NET_NS
        return dev->nd_net;
#else
        return &init_net;
#endif
}

static inline int netif_is_bond_slave(struct net_device *dev)
{
        return dev->flags & IFF_SLAVE && dev->priv_flags & IFF_BONDING;
}

#endif /* __BACKPORT_LINUX_NETDEVICE_H_TO_2_6_25__ */
