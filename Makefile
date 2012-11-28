EXTRA_CFLAGS += $(OPENIB_KERNEL_EXTRA_CFLAGS) \
		$(KERNEL_MEMTRACK_CFLAGS) \
		$(KERNEL_SYSTUNE_CFLAGS) \
		-I$(CWD)/include \
		-I$(CWD)/drivers/net/mlx4 \

obj-$(CONFIG_MLX4_CORE)         += drivers/net/mlx4/
obj-$(CONFIG_MEMTRACK)          += drivers/net/debug/
obj-m				+= drivers/infiniband/hw/mlx4/
