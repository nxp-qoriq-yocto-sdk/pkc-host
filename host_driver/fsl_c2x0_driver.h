/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of Freescale Semiconductor nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE)ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef FSL_PKC_DRIVER_H
#define FSL_PKC_DRIVER_H

#include <linux/crypto.h>

#include "sysfs.h"
#include "device.h"
#include "fsl_c2x0_crypto_layer.h"

/* General macros */
#define FSL_PCI_DEV_NAME				"fsl_crypto_"
/* Strlen of FSL_PCI_DEV_NAME + 1 for number of device + 1 for '\0' */
#define FSL_PCI_DEV_NAME_MAX_LEN	13
#define FSL_PCI_DEV_NODE_STD_PATH_LEN	16	/* /dev/fsl_crypto */

/* DMA macro's */
#define DMA_36BIT_MASK		0x0000000fffffffffULL
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0))
#define DMA_32BIT_MASK		0x00000000ffffffffULL
#endif

/* PCI Config space fields related macros */
#define MSI_CTRL_WORD_MMC_MASK	0xE	/* 1-3 bits */
#define MSI_CTRL_WORD_MMC_SHIFT	1

#define MSI_CTRL_WORD_MME_MASK	0x70	/* 4-6 bits */
#define MSI_CTRL_WORD_MME_SHIFT	4

/* PCI CONFIG SPACE REGISTERS OFFSET */
typedef enum pci_config_space_regs {
	PCI_BAR0_REGISTER = 0X10,
	PCI_BAR1_REGISTER = 0X14,
	PCI_MSI_CTRL_REGISTER = 0X8A,
	PCI_MSI_ADDR_LOW = 0X8C,
	PCI_MSI_ADDR_HIGH = 0X90,
	PCI_MSI_ADDR_DATA = 0X94
} pci_config_space_regs_t;

/*******************************************************************************
Description :	Holds the context pointer for interrupts
Fields      :	vector_no: vector number of the interrupt
		dev: Back reference to the device
		isr_bh_list: Head of the list of bh handlers for this interrupt
		list: Required to make the list of this structures.
*******************************************************************************/
typedef struct isr_ctx {
	uint32_t irq;
	struct c29x_dev *c_dev;
	/* List of Bhs for this ISR */
/*	LIST_HEAD(isr_bh_list); */
	uint32_t msi_addr_low;
	uint32_t msi_addr_high;
	/* Only 16bit MSI data */
	uint16_t msi_data;
	struct list_head list;
	struct list_head ring_list_head;
} isr_ctx_t;

/*******************************************************************************
Description :	Contains the PCI BAR information.
Fields      :	host_p_addr	: Physical address of the BAR.
		host_v_addr	: Kernel mapped virtual address.
		host_dma_addr	: DMA mapped address
		len		: Length of the BAR
*******************************************************************************/
struct pci_bar_info {
	/* the address of the PCI resource mapped into the kernel space */
	void *host_v_addr;
	/* physical and dma address where the PCI resource is located */
	phys_addr_t host_p_addr;
	dma_addr_t host_dma_addr;
	/* length in bytes of the PCI resource */
	resource_size_t len;
	/* address of the PCI resource as seen from the device point of view */
	dev_p_addr_t dev_p_addr;
};

/*******************************************************************************
Description:	Contains the interrupts information of the device
Fields	   :	intr_vectors_cnt: Number of intr vectors alloc for this device
		isr_ctx_list_head: Head of the linked list of isr contexts
*******************************************************************************/
typedef struct pci_intr_info {
	u16 intr_vectors_cnt;
	struct list_head isr_ctx_head;
} pci_intr_info_t;

struct c29x_dev {
	uint32_t dev_no;

	struct pci_dev *dev;
	const struct pci_device_id *id;

	char dev_name[FSL_PCI_DEV_NAME_MAX_LEN];
	char dev_node_path[FSL_PCI_DEV_NODE_STD_PATH_LEN +
			   FSL_PCI_DEV_NAME_MAX_LEN];

	struct pci_bar_info bars[MEM_TYPE_MAX];
	pci_intr_info_t intr_info;

	dev_sysfs_entries_t sysfs;
	void *sysfs_dir;

	struct list_head list;

	struct crypto_dev_config *config;
	struct driver_ob_mem ob_mem;
	uint32_t tot_req_mem_size;

	/* Pointer to the memory on the host side, structures the plain bytes.
	 * Represents the memory layout on the driver.
	 * This points to the base of the outbound memory.
	 */
	struct host_mem_layout *host_mem;

	/* Pointer to the device's handshake memory, this will be
	 * pointing to the inbound memory.
	 * This data structure helps in structured access of raw bytes
	 * in the device memory during the handshake.
	 */
	struct dev_handshake_mem *c_hs_mem;

	/* Pointer to the shadow ring counters memory */
	struct ring_counters_mem *r_s_c_cntrs;

	/* Structure defining the input pool */
	struct pool_info host_ip_pool;

	/* Ctx pool - Will be used during data path to allocate one
	 * of the available static contexts */
	ctx_pool_t *ctx_pool;

	uint8_t num_of_rps;
	fsl_h_rsrc_ring_pair_t *ring_pairs;

	/* Holds the count of number of crypto dev sessions */
	atomic_t crypto_dev_sess_cnt;

	atomic_t app_req_cnt;
	atomic_t app_resp_cnt;
};

struct bh_handler {
	int core_no;
	struct c29x_dev *c_dev;
	struct work_struct work;
	struct list_head ring_list_head;
};

struct alg_template {
	char name[CRYPTO_MAX_ALG_NAME];
	char driver_name[CRYPTO_MAX_ALG_NAME];
	char hmac_name[CRYPTO_MAX_ALG_NAME];
	char hmac_driver_name[CRYPTO_MAX_ALG_NAME];

	uint32_t blocksize;
	uint32_t type;
	struct pkc_alg pkc;

	uint32_t alg_type;
	uint32_t alg_op;
	uint32_t class1_alg_type;
	uint32_t class2_alg_type;
};

struct c29x_dev *get_crypto_dev(uint32_t no);
extern struct crypto_dev_config *get_dev_config(struct c29x_dev *c_dev);
extern int32_t parse_config_file(int8_t *config_file);

#endif
