#Specifies type of EP
P4080_EP=n
C293_EP=y

#Controls the debug print level
DEBUG_PRINT=n
ERROR_PRINT=n
INFO_PRINT=n

#Enable HASH/SYMMETRIC offloading
CONFIG_FSL_C2X0_HASH_OFFLOAD=n
CONFIG_FSL_C2X0_HMAC_OFFLOAD=n
CONFIG_FSL_C2X0_SYMMETRIC_OFFLOAD=n

#Enable RNG offloading
RNG_OFFLOAD=n

#Specifies whether SEC DMA support to be enabled /disabled in the driver
#If enabled, then Host DMA support would be always disabled.
USE_SEC_DMA=y

#Specifies whether host DMA support to be enabled /disabled in the driver
USE_HOST_DMA=n

#Specifies whether driver/firmware is running high performance mode
HIGH_PERF_MODE=y

#Enhance pkc kernel test performance, disable kernel test schedule and
#restriction number of c29x_fw enqueue and dequeue crypto
ENHANCE_KERNEL_TEST=n

#Specify building host-driver to support Virtualization
VIRTIO_C2X0=n

# do not enable together SEC_DMA and HOST_DMA
ifeq ($(USE_SEC_DMA), y)
USE_HOST_DMA = n
endif

KERNEL_DIR ?=/lib/modules/$(shell uname -r)/build
CONFIG_FSL_C2X0_CRYPTO_DRV ?= m

ccflags-y := -I$(src)/host_driver -I$(src)/algs -I$(src)/crypto_dev -I$(src)/dcl -I$(src)/test
ccflags-y += -g -g3 -DDEV_PHYS_ADDR_64BIT
ccflags-y += -Wall -Werror

ccflags-$(P4080_EP) += -DP4080_EP
ccflags-$(C293_EP) += -DC293_EP

ccflags-$(DEBUG_PRINT) += -DDEV_PRINT_DBG -DPRINT_DEBUG
ccflags-$(ERROR_PRINT) += -DDEV_PRINT_ERR -DPRINT_ERROR
ccflags-$(INFO_PRINT) += -DPRINT_INFO

ccflags-$(HIGH_PERF_MODE) += -DHIGH_PERF
ccflags-$(VIRTIO_C2X0) += -DVIRTIO_C2X0
ccflags-$(CONFIG_FSL_C2X0_HASH_OFFLOAD) += -DHASH_OFFLOAD
ccflags-$(CONFIG_FSL_C2X0_HMAC_OFFLOAD) += -DHMAC_OFFLOAD
ccflags-$(CONFIG_FSL_C2X0_SYMMETRIC_OFFLOAD) += -DSYMMETRIC_OFFLOAD
ccflags-$(RNG_OFFLOAD) += -DRNG_OFFLOAD
ccflags-$(USE_SEC_DMA) += -DSEC_DMA
ccflags-$(USE_HOST_DMA) += -DUSE_HOST_DMA
ccflags-$(ENHANCE_KERNEL_TEST) += -DENHANCE_KERNEL_TEST

DRIVER_KOBJ = fsl_pkc_crypto_offload_drv
obj-$(CONFIG_FSL_C2X0_CRYPTO_DRV) := $(DRIVER_KOBJ).o
$(DRIVER_KOBJ)-objs := host_driver/fsl_c2x0_driver.o
$(DRIVER_KOBJ)-objs += host_driver/fsl_c2x0_crypto_layer.o
$(DRIVER_KOBJ)-objs += host_driver/memmgr.o
$(DRIVER_KOBJ)-objs += host_driver/command.o
$(DRIVER_KOBJ)-objs += host_driver/sysfs.o
ifneq ("$(ARCH)","powerpc")
$(DRIVER_KOBJ)-objs += crypto/pkc.o
endif
$(DRIVER_KOBJ)-objs += host_driver/dma.o
$(DRIVER_KOBJ)-objs += algs/algs.o
$(DRIVER_KOBJ)-objs += algs/rsa.o
$(DRIVER_KOBJ)-objs += algs/dsa.o
$(DRIVER_KOBJ)-objs += algs/dh.o
$(DRIVER_KOBJ)-objs += algs/desc_buffs.o
$(DRIVER_KOBJ)-objs += algs/rng_init.o
$(DRIVER_KOBJ)-objs += crypto_dev/algs_reg.o
ifeq ($(CONFIG_FSL_C2X0_HASH_OFFLOAD),y)
$(DRIVER_KOBJ)-objs += algs/hash.o
endif
ifeq ($(CONFIG_FSL_C2X0_SYMMETRIC_OFFLOAD),y)
$(DRIVER_KOBJ)-objs += algs/symmetric.o
endif
$(DRIVER_KOBJ)-objs += algs/rng.o

ifeq ($(VIRTIO_C2X0),n)
$(DRIVER_KOBJ)-objs += test/rsa_test.o
$(DRIVER_KOBJ)-objs += test/dsa_test.o
$(DRIVER_KOBJ)-objs += test/ecdsa_test.o
$(DRIVER_KOBJ)-objs += test/ecp_test.o
$(DRIVER_KOBJ)-objs += test/ecpbn_test.o
$(DRIVER_KOBJ)-objs += test/dh_test.o
$(DRIVER_KOBJ)-objs += test/ecdh_test.o
$(DRIVER_KOBJ)-objs += test/ecdh_keygen_test.o
$(DRIVER_KOBJ)-objs += test/test.o
endif

.PHONY: build

build:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
	$(CROSS_COMPILE)gcc  -Wall apps/cli/cli.c -o apps/cli/cli -static

modules_install:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

dist: clean
