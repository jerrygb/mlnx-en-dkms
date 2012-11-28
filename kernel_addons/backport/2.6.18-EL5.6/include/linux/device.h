#ifndef __BACKPORT_LINUX_DEVICE_H_TO_2_6_25__
#define __BACKPORT_LINUX_DEVICE_H_TO_2_6_25__

#include_next <linux/device.h>


static inline int dev_to_node(struct device *dev)
{
	return -1;
}

#endif /* __BACKPORT_LINUX_DEVICE_H_TO_2_6_25__ */
