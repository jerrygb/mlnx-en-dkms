# $Id: Makefile 9120 2006-08-28 13:01:07Z vlad $

PHONY += all kernel install_kernel install clean clean_kernel
	
all:
.PHONY: $(PHONY)

.DELETE_ON_ERROR:

include ./config.mk

DEPMOD  = /sbin/depmod
INSTALL_MOD_DIR ?= $(shell test -f /etc/SuSE-release && echo updates || echo extra/mellanox-mlnx-en)

ifeq ($(CONFIG_MEMTRACK),m)
        export KERNEL_MEMTRACK_CFLAGS = -include $(CWD)/drivers/net/debug/mtrack.h
else
        export KERNEL_MEMTRACK_CFLAGS =
endif


all: kernel

install: install_kernel
install_kernel: install_modules

autoconf_h=$(shell /bin/ls -1 $(KSRC)/include/*/autoconf.h 2> /dev/null | head -1)
kconfig_h=$(shell /bin/ls -1 $(KSRC)/include/*/kconfig.h 2> /dev/null | head -1)

ifneq ($(kconfig_h),)
KCONFIG_H = -include $(kconfig_h)
endif

V ?= 1

#########################
#	make kernel	#
#########################
#NB: The LINUXINCLUDE value comes from main kernel Makefile
#    with local directories prepended. This eventually affects
#    CPPFLAGS in the kernel Makefile
kernel:
	@echo "Building kernel modules"
	@echo "Kernel version: $(KVERSION)"
	@echo "Modules directory: $(INSTALL_MOD_PATH)/lib/modules/$(KVERSION)/$(INSTALL_MOD_DIR)"
	@echo "Kernel sources: $(KSRC)"
	env CWD=$(CWD) BACKPORT_INCLUDES=$(BACKPORT_INCLUDES) \
		$(MAKE) -C $(KSRC) SUBDIRS="$(CWD)" \
		V=$(V) $(WITH_MAKE_PARAMS) \
		CONFIG_MEMTRACK=$(CONFIG_MEMTRACK) \
		CONFIG_MLX4_CORE=m \
		CONFIG_MLX4_EN=m \
		LINUXINCLUDE=' \
		-include $(autoconf_h) \
		-include $(CWD)/include/linux/autoconf.h \
		$(KCONFIG_H) \
		$(BACKPORT_INCLUDES) \
		$(KERNEL_MEMTRACK_CFLAGS) \
		$(SYSTUNE_INCLUDE) \
		$(MLNX_EN_EXTRA_CFLAGS) \
		-I$(CWD)/include \
		$$(if $$(CONFIG_XEN),-D__XEN_INTERFACE_VERSION__=$$(CONFIG_XEN_INTERFACE_VERSION)) \
		$$(if $$(CONFIG_XEN),-I$$(srctree)/arch/x86/include/mach-xen) \
		-I$$(srctree)/arch/$$(hdr-arch)/include \
		-Iinclude \
		$$(if $$(KBUILD_SRC),-Iinclude2 -I$$(srctree)/include) \
		-I$$(srctree)/arch/$$(SRCARCH)/include \
		' \
		modules


#########################
#	Install kernel	#
#########################
install_modules:
	@echo "Installing kernel modules"

	$(MAKE) -C $(KSRC) SUBDIRS="$(CWD)" \
		INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) \
		INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) \
		$(WITH_MAKE_PARAMS) modules_install;

	if [ ! -n "$(INSTALL_MOD_PATH)" ]; then $(DEPMOD) $(KVERSION);fi;

clean: clean_kernel

clean_kernel:
	$(MAKE) -C $(KSRC) SUBDIRS="$(CWD)" $(WITH_MAKE_PARAMS) clean

help:
	@echo
	@echo kernel: 		        build kernel modules
	@echo all: 		        build kernel modules
	@echo
	@echo install_kernel:	        install kernel modules under $(INSTALL_MOD_PATH)/lib/modules/$(KVERSION)/$(INSTALL_MOD_DIR)
	@echo install:	        	run install_kernel
	@echo
	@echo clean:	        	delete kernel modules binaries
	@echo clean_kernel:	        delete kernel modules binaries
	@echo
