#Controls the debug print level
DEBUG_PRINT=n
INFO_PRINT=n
DEBUG_DESC=n

#Enhance pkc kernel test performance, disable kernel test schedule and
#restriction number of c29x_fw enqueue and dequeue crypto
ENHANCE_KERNEL_TEST=n

GCOV_PROFILE := n

KERNEL_DIR ?=/lib/modules/$(shell uname -r)/build
CONFIG_FSL_C2X0_CRYPTO_DRV ?= m

ccflags-y := -I$(src)/host_driver -I$(src)/algs -I$(src)/crypto_dev -I$(src)/dcl -I$(src)/test
ccflags-y += -g -g3 -DDEV_PHYS_ADDR_64BIT -std=gnu90
ccflags-y += -Wall -Werror

ccflags-$(DEBUG_PRINT) += -DPRINT_DEBUG
ccflags-$(INFO_PRINT) += -DPRINT_INFO
ccflags-$(DEBUG_DESC) += -DDEBUG_DESC

ccflags-$(ENHANCE_KERNEL_TEST) += -DENHANCE_KERNEL_TEST

DRIVER_KOBJ = fsl_pkc_crypto_offload_drv
obj-$(CONFIG_FSL_C2X0_CRYPTO_DRV) := $(DRIVER_KOBJ).o
$(DRIVER_KOBJ)-objs := host_driver/fsl_c2x0_driver.o
$(DRIVER_KOBJ)-objs += host_driver/fsl_c2x0_crypto_layer.o
$(DRIVER_KOBJ)-objs += host_driver/memmgr.o
$(DRIVER_KOBJ)-objs += host_driver/sysfs.o
ifeq ("$(ARCH)","x86")
$(DRIVER_KOBJ)-objs += crypto/pkc.o
endif
$(DRIVER_KOBJ)-objs += algs/error.o
$(DRIVER_KOBJ)-objs += algs/algs.o
$(DRIVER_KOBJ)-objs += algs/rsa.o
$(DRIVER_KOBJ)-objs += algs/dsa.o
$(DRIVER_KOBJ)-objs += algs/dh.o
$(DRIVER_KOBJ)-objs += algs/desc_buffs.o
$(DRIVER_KOBJ)-objs += algs/rng_init.o

$(DRIVER_KOBJ)-objs += test/rsa_test.o
$(DRIVER_KOBJ)-objs += test/dsa_test.o
$(DRIVER_KOBJ)-objs += test/ecdsa_test.o
$(DRIVER_KOBJ)-objs += test/ecp_test.o
$(DRIVER_KOBJ)-objs += test/ecpbn_test.o
$(DRIVER_KOBJ)-objs += test/dh_test.o
$(DRIVER_KOBJ)-objs += test/ecdh_test.o
$(DRIVER_KOBJ)-objs += test/ecdh_keygen_test.o
$(DRIVER_KOBJ)-objs += test/test.o

.PHONY: build clean

build:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules

modules_install:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules_install

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) clean
