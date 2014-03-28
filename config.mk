#Device configurations

#Specifies type of EP
P4080_EP=n
C293_EP=y

#Controls the debug print level
DEBUG_PRINT=n
ERROR_PRINT=n
INFO_PRINT=n

#Enable HASH/SYMMETRIC offloading
CONFIG_FSL_C2X0_HASH_OFFLOAD=n
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
