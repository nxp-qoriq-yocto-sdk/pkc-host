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

#ifndef FSL_PKC_CRYPTO_LAYER_H
#define FSL_PKC_CRYPTO_LAYER_H

#include "memmgr.h"
#include "types.h"

extern int napi_poll_count;

/* times in milliseconds */
#define HS_TIMEOUT	500
#define HS_LOOP_BREAK	5

/* Identifies different states of the device */
typedef enum handshake_state {
	DEFAULT,
	FIRMWARE_UP = 10,
	FW_INIT_CONFIG_COMPLETE,
	FW_GET_SEC_INFO_COMPLETE,
	FW_INIT_RING_PAIR_COMPLETE,
	FW_INIT_MSI_INFO_COMPLETE,
	FW_INIT_IDX_MEM_COMPLETE,
	FW_INIT_COUNTERS_MEM_COMPLETE,
	FW_INIT_RNG,
	FW_RNG_COMPLETE
} handshake_state_t;

/* Identifies different commands to be sent to the firmware */
typedef enum fw_handshake_commands {
	FW_GET_SEC_INFO,
	FW_INIT_CONFIG,
	FW_INIT_RING_PAIR,
	FW_INIT_MSI_INFO,
	FW_INIT_IDX_MEM,
	FW_INIT_COUNTERS_MEM,
	FW_HS_COMPLETE,
	FW_WAIT_FOR_RNG,
	FW_RNG_DONE
} fw_handshake_commands_t;

/* Different types of memory on the device */
typedef enum crypto_dev_mem_type {
	MEM_TYPE_CONFIG,
	MEM_TYPE_SRAM,
	MEM_TYPE_MAX
} crypto_dev_mem_type_t;


struct host_handshake_mem {
	uint8_t state;
	uint8_t result;

	union resp_data {
		struct fw_up_data {
			uint32_t p_ib_mem_base_l;
			uint32_t p_ib_mem_base_h;
			uint32_t p_ob_mem_base_l;
			uint32_t p_ob_mem_base_h;
			uint32_t no_secs;
		} device;
		struct config_data {
			uint32_t r_s_c_cntrs;
		} config;
		struct ring_data {
			uint32_t req_r;
			uint32_t intr_ctrl_flag;
		} ring;
	} data;
};

struct dev_handshake_mem {
	uint32_t h_ob_mem_l;
	uint32_t h_ob_mem_h;

	uint8_t state;
	uint8_t data_len;

	union cmd_data {
		struct c_config_data {
			uint8_t num_of_rps;
			uint32_t r_s_cntrs;
		} config;
		struct c_ring_data {
			uint8_t rid;
			uint16_t msi_data;
			uint32_t depth;
			uint32_t resp_ring_offset;
			uint32_t msi_addr_l;
			uint32_t msi_addr_h;
		} ring;
	} data;
};

struct ring_idxs_mem {
	uint32_t w_index;
	uint32_t r_index;
};

struct ring_counters_mem {
	uint32_t jobs_added;
	uint32_t jobs_processed;
};

/**** RING PAIR RELATED DATA STRUCTURES ****/

/*******************************************************************************
Description : Identifies the request ring entry
Fields      : sec_desc        : DMA address of the sec addr valid in dev domain
*******************************************************************************/
struct req_ring_entry {
	dev_dma_addr_t sec_desc;
};

/*******************************************************************************
Description :	Identifies the response ring entry
Fields      :	sec_desc: DMA address of the sec addr valid in dev domain
		result	: Result word from sec engine
*******************************************************************************/
struct resp_ring_entry {
	dev_dma_addr_t sec_desc;
	volatile uint32_t result;
} __packed;

typedef struct fsl_h_rsrc_ring_pair {
	struct c29x_dev *c_dev;

	struct list_head isr_ctx_list_node;
	struct list_head bh_ctx_list_node;

	uint32_t *intr_ctrl_flag;
	struct buffer_pool *buf_pool;
	struct req_ring_entry *req_r;
	struct resp_ring_entry *resp_r;
	struct ring_idxs_mem *indexes;
	struct ring_counters_mem *counters;
	struct ring_counters_mem *r_s_cntrs;
	struct ring_counters_mem *shadow_counters;

	uint32_t depth;
	uint32_t core_no;
	uint32_t msi_addr_l;
	uint32_t msi_addr_h;
	uint16_t msi_data;

	spinlock_t ring_lock;
} fsl_h_rsrc_ring_pair_t;

/*******************************************************************************
Description :	Contains the structured layout of the driver mem - outbound mem
Fields      :	hs_mem	: Handshake memory - 64bytes
		request_rings_mem: Sequence of bytes for rings holding req ring
				mem and input buffer pool. Exact binding is
				updated in different data structure.
		idxs	: Memory of the ring pair indexes
		shadow_idxs: Memory of the shadow ring pair indexes
		counters: Memory of the counters per ring
		shadow_counters: Memory of the shadow counters per ring
*******************************************************************************/
struct host_mem_layout {
	struct host_handshake_mem hs_mem;
	struct resp_ring_entry *drv_resp_rings;
	struct ring_idxs_mem *idxs_mem;
	struct ring_counters_mem *cntrs_mem;
	struct ring_counters_mem *r_s_cntrs_mem;
	void *ip_pool;

};

struct driver_ob_mem {
	uint32_t hs_mem;
	uint32_t drv_resp_rings;
	uint32_t idxs_mem;
	uint32_t cntrs_mem;
	uint32_t r_s_cntrs_mem;
	uint32_t ip_pool;
};

typedef struct ctx_pool ctx_pool_t;

int32_t ring_enqueue(struct c29x_dev *c_dev, uint32_t jr_id,
			 dev_dma_addr_t sec_desc);

int32_t fsl_crypto_layer_add_device(struct c29x_dev *c_dev);
void cleanup_crypto_device(struct c29x_dev *c_dev);
int32_t handshake(struct c29x_dev *c_dev);
void rearrange_rings(struct c29x_dev *c_dev);
void distribute_rings(struct c29x_dev *c_dev);
void init_ip_pool(struct c29x_dev *c_dev);
int init_crypto_ctx_pool(struct c29x_dev *c_dev);
void init_handshake(struct c29x_dev *c_dev);
void init_ring_pairs(struct c29x_dev *c_dev);
void stop_device(struct c29x_dev *c_dev);
void start_device(struct c29x_dev *c_dev);
void response_ring_handler(struct work_struct *work);

extern int32_t rng_instantiation(struct c29x_dev *c_dev);

#endif
