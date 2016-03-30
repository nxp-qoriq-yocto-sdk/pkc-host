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

#include "common.h"
#include "device.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "command.h"
#include "algs.h"
#include "error.h"
#include "crypto_ctx.h"
#ifdef VIRTIO_C2X0
#include "hash.h"		/* hash */
#include "fsl_c2x0_virtio.h"
#endif

extern int32_t wt_cpu_mask;
extern struct bh_handler __percpu *per_core;

#define DEFAULT_HOST_OP_BUFFER_POOL_SIZE	(1*1024)
#define DEFAULT_FIRMWARE_RESP_RING_DEPTH	(128*4)
#define FIRMWARE_IP_BUFFER_POOL_SIZE		(512*1024)

#ifndef HIGH_PERF

#ifdef PRINT_DEBUG
static int32_t total_resp;
#endif

#ifdef MULTIPLE_RESP_RINGS
static void store_dev_ctx(void *buffer, uint8_t rid, uint32_t wi)
{
	dev_ctx_t *ctx = (dev_ctx_t *) (buffer - 32);
	ctx->rid = rid;
	iowrite32be(wi, (void *) &ctx->wi);
}
#endif

#endif

static uint32_t align(uint32_t addr, uint32_t size)
{
	size--;
	return (addr + size) & ~size;
}

static uint32_t cache_line_align(uint32_t addr)
{
	return align(addr, DEVICE_CACHE_LINE_SIZE);
}

static uint32_t page_align(uint32_t addr)
{
	return align(addr, PAGE_SIZE);
}

void distribute_rings(fsl_crypto_dev_t *dev, struct crypto_dev_config *config)
{
	fsl_h_rsrc_ring_pair_t *rp;
	uint32_t core_no = 0;
	uint16_t isr_count = 0;
	uint32_t i;
	struct list_head *isr_ctx_list_head;
	uint32_t total_cores = num_online_cpus();
	uint16_t total_isrs = dev->priv_dev->intr_info.intr_vectors_cnt;
	struct bh_handler *instance;
	isr_ctx_t *isr_ctx;

	isr_ctx_list_head = &(dev->priv_dev->intr_info.isr_ctx_list_head);

	print_debug("Total cores: %d\n", total_cores);
	isr_ctx = list_entry(isr_ctx_list_head->next, isr_ctx_t, list);

	INIT_LIST_HEAD(&(isr_ctx->ring_list_head));

	/* Affine the ring to CPU & ISR */
	for (i = 0; i < config->num_of_rings; i++) {
		while (!(wt_cpu_mask & (1 << core_no)))
			core_no = (core_no + 1) % total_cores;

		print_debug("Ring no: %d Core no: %d\n", i, core_no);
		instance = per_cpu_ptr(per_core, core_no);

		rp = &(dev->ring_pairs[i]);
		rp->core_no = core_no;

		config->ring[i].msi_addr_l = isr_ctx->msi_addr_low;
		config->ring[i].msi_addr_h = isr_ctx->msi_addr_high;
		config->ring[i].msi_data = isr_ctx->msi_data;

		/* Adding the ring to the ISR */
		list_add(&(rp->isr_ctx_list_node), &(isr_ctx->ring_list_head));
		list_add(&(rp->bh_ctx_list_node), &(instance->ring_list_head));

		if ((++isr_count) % total_isrs) {
			isr_ctx = list_entry(isr_ctx->list.next, isr_ctx_t, list);
		} else {
			isr_ctx = list_entry(isr_ctx_list_head->next, isr_ctx_t,
						list);
		}

		print_debug("ISR COUNT: %d total num of isrs: %d\n",
			    isr_count, total_isrs);

		core_no = (core_no + 1) % total_cores;
	}
}

uint32_t round_to_power2(uint32_t n)
{
	uint32_t i = 1;
	while (i < n)
		i = i << 1;
	return i;
}

static void pow2_rp_len(struct crypto_dev_config *config)
{
	uint32_t i;
	/* Correct the ring depths to be power of 2 */
	for (i = 0; i < config->num_of_rings; i++) {
		config->ring[i].depth = round_to_power2(config->ring[i].depth);
	}
}

/* utilities to get/set ring flags */
uint8_t f_get_p(uint8_t flags)
{
	return (flags & APP_RING_PROP_PRIO_MASK) >> APP_RING_PROP_PRIO_SHIFT;
}

uint8_t f_get_a(uint8_t flags)
{
	return (flags & APP_RING_PROP_AFFINE_MASK) >> APP_RING_PROP_AFFINE_SHIFT;
}

uint8_t f_get_o(uint8_t flags)
{
	return (flags & APP_RING_PROP_ORDER_MASK) >> APP_RING_PROP_ORDER_SHIFT;
}

void f_set_p(uint8_t *flags, uint8_t priority)
{
	*flags &= ~APP_RING_PROP_PRIO_MASK;
	*flags |= priority << APP_RING_PROP_PRIO_SHIFT;
}

void f_set_a(uint8_t *flags, uint8_t affinity)
{
	*flags &= ~APP_RING_PROP_AFFINE_MASK;
	*flags |= affinity << APP_RING_PROP_AFFINE_SHIFT;
}

void f_set_o(uint8_t *flags, uint8_t order)
{
	*flags &= ~APP_RING_PROP_ORDER_MASK;
	*flags |= order << APP_RING_PROP_ORDER_SHIFT;
}

void rearrange_rings(fsl_crypto_dev_t *dev, struct crypto_dev_config *config)
{
	uint8_t i;

	pow2_rp_len(config);

	for (i = 0; i < config->num_of_rings; i++) {
		dev->ring_pairs[i].info = config->ring[i];
	}
	dev->num_of_rings = config->num_of_rings;
}

static uint32_t count_ring_slots(struct crypto_dev_config *config)
{
	uint32_t i, len = 0;

	for (i = 0; i < config->num_of_rings; i++) {
		len += config->ring[i].depth;
	}
	return len;
}

/*
 * Calculate outbound memory requirements.
 * ob_mem->h_mem will contain the memory map relative to address 0. It will be
 * translated relative to a pci mapped address by alloc_ob_mem
 */
static uint32_t calc_ob_mem_len(fsl_crypto_dev_t *dev,
				struct crypto_dev_config *config)
{
	uint32_t ob_mem_len = sizeof(struct host_mem_layout);
	uint32_t total_ring_slots;
	uint32_t fw_rr_size;

	/* Correct the ring depths to power of 2 */
	total_ring_slots = count_ring_slots(config);
	ob_mem_len = cache_line_align(ob_mem_len);
	dev->ob_mem.drv_resp_rings = ob_mem_len;
	ob_mem_len += total_ring_slots * sizeof(struct resp_ring_entry);

	/* For each rp we need a local memory for indexes */
	/* FIXME: we should probably allocate
	 * 		config->num_of_rings + NUM_OF_RESP_RINGS instead of
	 * 		config->num_of_rings + 1 */
	ob_mem_len = cache_line_align(ob_mem_len);
	dev->ob_mem.idxs_mem = ob_mem_len;
	ob_mem_len += (config->num_of_rings + 1) * (sizeof(struct ring_idxs_mem));

	ob_mem_len = cache_line_align(ob_mem_len);
	dev->ob_mem.cntrs_mem = ob_mem_len;
	ob_mem_len += (config->num_of_rings + 1) * sizeof(struct ring_counters_mem);

	ob_mem_len = cache_line_align(ob_mem_len);
	dev->ob_mem.r_s_cntrs_mem = ob_mem_len;
	ob_mem_len += (config->num_of_rings + 1) * sizeof(struct ring_counters_mem);

	/* We have to make sure that we align the output buffer pool to DMA */
	ob_mem_len = cache_line_align(ob_mem_len);
	dev->ob_mem.op_pool = ob_mem_len;
	ob_mem_len += DEFAULT_HOST_OP_BUFFER_POOL_SIZE;

	fw_rr_size = DEFAULT_FIRMWARE_RESP_RING_DEPTH * sizeof(struct resp_ring_entry);
	/* See if we can fit fw_resp_ring before the end of this page and if not
	 * put it in the next page */
	if ((PAGE_SIZE - (ob_mem_len % PAGE_SIZE)) < fw_rr_size) {
		ob_mem_len = page_align(ob_mem_len);
	}

	dev->ob_mem.fw_resp_ring = ob_mem_len;
	ob_mem_len += fw_rr_size;

	/* For IP Pool we need to make sure that we always
	 * get 32BYTE aligned address */
	ob_mem_len = cache_line_align(ob_mem_len);
	dev->ob_mem.ip_pool = ob_mem_len;
	ob_mem_len += FIRMWARE_IP_BUFFER_POOL_SIZE;

	/* Make the total mem requirement aligned to page size */
	ob_mem_len = page_align(ob_mem_len);

	dev->tot_req_mem_size = total_ring_slots * sizeof(struct req_ring_entry);

	return ob_mem_len;
}

/*
 * Allocate outbound memory
 * dev->host_mem will contain the driver's memory map
 */
int32_t alloc_ob_mem(fsl_crypto_dev_t *dev, struct crypto_dev_config *config)
{
	void *host_v_addr;
	struct pci_bar_info *mem;
	uint32_t ob_mem_len;

	/* First get the total ob mem required */
	ob_mem_len = calc_ob_mem_len(dev, config);
	mem = &(dev->priv_dev->bars[MEM_TYPE_DRIVER]);

	print_debug("alloc_ob_mem entered...\n");
	print_debug("Total ob mem returned: %d\n", ob_mem_len);

	host_v_addr = pci_alloc_consistent(dev->priv_dev->dev,
			ob_mem_len, &(mem->host_dma_addr));
	if (!host_v_addr) {
		print_error("Allocating ob mem failed...\n");
		return -ENOMEM;
	}

	mem->host_v_addr = host_v_addr;
	mem->host_p_addr = (phys_addr_t)0xdeadbeefdeadbeef;
	mem->len = ob_mem_len;

	print_debug("OB Mem address	: %p\n", mem->host_v_addr);
	print_debug("OB Mem dma address	: %pad\n", &(mem->host_dma_addr));

	/* The outbound pointers are locations where the device is supposed to
	 * write to. We calculate the addresses with the correct offset and
	 * then communicate them to the device in the handshake operation */
	dev->host_mem = host_v_addr;
	dev->host_mem->fw_resp_ring = host_v_addr + dev->ob_mem.fw_resp_ring;
	dev->host_mem->drv_resp_rings = host_v_addr + dev->ob_mem.drv_resp_rings;
	dev->host_mem->idxs_mem = host_v_addr + dev->ob_mem.idxs_mem;
	dev->host_mem->cntrs_mem = host_v_addr + dev->ob_mem.cntrs_mem;
	dev->host_mem->r_s_cntrs_mem = host_v_addr + dev->ob_mem.r_s_cntrs_mem;
	dev->host_mem->op_pool = host_v_addr + dev->ob_mem.op_pool;
	dev->host_mem->ip_pool = host_v_addr + dev->ob_mem.ip_pool;

	print_debug("====== OB MEM POINTERS =======\n");
	print_debug("Hmem		: %p\n", dev->host_mem);
	print_debug("H HS Mem		: %p\n", &(dev->host_mem->hs_mem));
	print_debug("Fw resp ring	: %p\n", dev->host_mem->fw_resp_ring);
	print_debug("Drv resp rings	: %p\n", dev->host_mem->drv_resp_rings);
	print_debug("Idxs mem	        : %p\n", dev->host_mem->idxs_mem);
	print_debug("cntrs mem          : %p\n", dev->host_mem->cntrs_mem);
	print_debug("S C R cntrs mem	: %p\n", dev->host_mem->r_s_cntrs_mem);
	print_debug("OP pool		: %p\n", dev->host_mem->op_pool);
	print_debug("IP pool		: %p\n", dev->host_mem->ip_pool);
	print_debug("Total req mem size : %d\n", dev->tot_req_mem_size);

	return 0;
}

void init_handshake(fsl_crypto_dev_t *dev)
{
	dma_addr_t ob_mem = dev->priv_dev->bars[MEM_TYPE_DRIVER].host_dma_addr;
	phys_addr_t msi_mem = dev->priv_dev->bars[MEM_TYPE_MSI].host_p_addr;

	/* Write our address to the firmware -
	 * It uses this to give it details when it is up */
	uint32_t l_val = (uint32_t) (ob_mem & PHYS_ADDR_L_32_BIT_MASK);
	uint32_t h_val = (ob_mem & PHYS_ADDR_H_32_BIT_MASK) >> 32;

	/* Reset driver handshake state so it loops until signaled by the
	 * device firmware */
	dev->host_mem->hs_mem.state = DEFAULT;

	print_debug("C HS mem addr: %p\n", &(dev->c_hs_mem->h_ob_mem_l));
	print_debug("Host ob mem addr	L: %0x	H: %0x\n", l_val, h_val);

	/* First phase of communication:
	 * When the device is started it will look for these addresses to get
	 * back to us: interrupt and host memory (at the base of which there is
	 * the host handshake area)
	 */
	iowrite32be(l_val, (void *) &dev->c_hs_mem->h_ob_mem_l);
	iowrite32be(h_val, (void *) &dev->c_hs_mem->h_ob_mem_h);

	/* Write MSI info the device */
	l_val = (uint32_t) (msi_mem & PHYS_ADDR_L_32_BIT_MASK);
	h_val = (msi_mem & PHYS_ADDR_H_32_BIT_MASK) >> 32;
	print_debug("MSI mem addr,	L: %0x	H: %x\n", l_val, h_val);

	iowrite32be(l_val, (void *) &dev->c_hs_mem->h_msi_mem_l);
	iowrite32be(h_val, (void *) &dev->c_hs_mem->h_msi_mem_h);
}

void init_fw_resp_ring(fsl_crypto_dev_t *dev)
{
	struct fw_resp_ring *fw_ring;
	uint8_t i;
	uint8_t id = dev->num_of_rings;
	/*int offset = 0;*/

	for (i = 0; i < NUM_OF_RESP_RINGS; i++) {
		fw_ring = &dev->fw_resp_rings[i];
		fw_ring->id = i;
		fw_ring->depth = DEFAULT_FIRMWARE_RESP_RING_DEPTH;
		fw_ring->v_addr = dev->host_mem->fw_resp_ring;
		fw_ring->p_addr = __pa(fw_ring->v_addr);

		/* We allocated "config->num_of_rings + 1" in alloc_ob_mem and
		 * id is the last one in this array of rings. But if
		 * NUM_OF_RESP_RINGS is not 1, we've got ourself a mess here */
		fw_ring->idxs = &(dev->host_mem->idxs_mem[id]);
		fw_ring->cntrs = &(dev->host_mem->cntrs_mem[id]);
		fw_ring->r_s_cntrs = &(dev->host_mem->r_s_cntrs_mem[id]);
		fw_ring->r_s_c_cntrs = NULL;

		/* FIXME: clean-up leftovers. It probably makes sense to actually
		 * use offset variable when NUM_OF_RESP_RINGS != 1
		offset += (DEFAULT_FIRMWARE_RESP_RING_DEPTH *
			   sizeof(struct resp_ring_entry));*/
	}
}

void init_ring_pairs(fsl_crypto_dev_t *dev)
{
	fsl_h_rsrc_ring_pair_t *rp;
	uint32_t i;
	/* all response ring entries start here. Each ring has rp->depth entries */
	struct resp_ring_entry *resp_r = dev->host_mem->drv_resp_rings;

	for (i = 0; i < dev->num_of_rings; i++) {
		rp = &(dev->ring_pairs[i]);

		rp->dev = dev;
		rp->depth = rp->info.depth;
		rp->num_of_sec_engines = 1;

		rp->buf_pool = &dev->host_ip_pool.buf_pool;
		rp->req_r = NULL;
		rp->resp_r = resp_r;
		resp_r += rp->depth;

		rp->intr_ctrl_flag = NULL;
		rp->indexes = &(dev->host_mem->idxs_mem[i]);
		rp->counters = &(dev->host_mem->cntrs_mem[i]);
		rp->r_s_cntrs = &(dev->host_mem->r_s_cntrs_mem[i]);
		rp->shadow_counters = NULL;

		INIT_LIST_HEAD(&(rp->isr_ctx_list_node));
		INIT_LIST_HEAD(&(rp->bh_ctx_list_node));

/* FIXME: It's not clear what is the use of sec_eng_sel, num_of_sec_engines and crypto_dev_sess:sec_eng */
		atomic_set(&(rp->sec_eng_sel), 0);
		spin_lock_init(&(rp->ring_lock));
	}

}

void send_hs_init_config(fsl_crypto_dev_t *dev)
{
	const char *str_state = "HS_INIT_CONFIG\n";
	struct c_config_data *config = &dev->c_hs_mem->data.config;

	set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
			(uint8_t *) str_state, strlen(str_state));

	iowrite8(HS_INIT_CONFIG, &dev->c_hs_mem->command);
	iowrite8(dev->num_of_rings, &config->num_of_rps);
	iowrite8(1, &config->max_pri);
	iowrite8(NUM_OF_RESP_RINGS, &config->num_of_fwresp_rings);
	iowrite32be(dev->tot_req_mem_size, &config->req_mem_size);
	iowrite32be(dev->ob_mem.fw_resp_ring, &config->fw_resp_ring);
	iowrite32be(dev->ob_mem.r_s_cntrs_mem, &config->r_s_cntrs);
	iowrite32be(DEFAULT_FIRMWARE_RESP_RING_DEPTH, &config->fw_resp_ring_depth);

	print_debug("HS_INIT_CONFIG Details\n");
	print_debug("Num of rps    : %d\n", dev->num_of_rings);
	print_debug("Req mem size  : %d\n", dev->tot_req_mem_size);
	print_debug("Fw resp ring  : %x\n", dev->ob_mem.fw_resp_ring);
	print_debug("R S counters  : %x\n", dev->ob_mem.r_s_cntrs_mem);
	print_debug("Sending FW_INIT_CONFIG command at addr: %p\n",
			&(dev->c_hs_mem->state));
	barrier();
	iowrite8(FW_INIT_CONFIG, &dev->c_hs_mem->state);
}

static void send_hs_command(uint8_t cmd, fsl_crypto_dev_t *dev, struct ring_info *ring)
{
	const char *str_state = NULL;
	uint32_t resp_r_offset;

	switch (cmd) {
	case HS_INIT_RING_PAIR:
		str_state = "HS_INIT_RING_PAIR\n";
		set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));

		resp_r_offset = (void *)dev->ring_pairs[ring->ring_id].resp_r -
				(void *)dev->host_mem;

		iowrite8(HS_INIT_RING_PAIR, &dev->c_hs_mem->command);
		iowrite8(ring->ring_id, &dev->c_hs_mem->data.ring.rid);
		iowrite8(ring->flags, &dev->c_hs_mem->data.ring.props);
		iowrite16be(ring->msi_data, &dev->c_hs_mem->data.ring.msi_data);
		iowrite32be(ring->depth, &dev->c_hs_mem->data.ring.depth);
		iowrite32be(resp_r_offset, &dev->c_hs_mem->data.ring.resp_ring_offset);
		iowrite32be(ring->msi_addr_l, &dev->c_hs_mem->data.ring.msi_addr_l);
		iowrite32be(ring->msi_addr_h, &dev->c_hs_mem->data.ring.msi_addr_h);

		print_debug("HS_INIT_RING_PAIR Details\n");
		print_debug("Rid: %d\n", ring->ring_id);
		print_debug("Depth: %d\n", ring->depth);
		print_debug("MSI Data: %x\n", ring->msi_data);
		print_debug("MSI Addr L: %x\n", ring->msi_addr_l);
		print_debug("MSI Addr H: %x\n", ring->msi_addr_h);

		barrier();
		iowrite8(FW_INIT_RING_PAIR, &dev->c_hs_mem->state);
		break;
	case HS_COMPLETE:
		str_state = "HS_COMPLETE\n";
		set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));
		set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));

		iowrite8(HS_COMPLETE, &dev->c_hs_mem->command);
		barrier();
		iowrite8(FW_HS_COMPLETE, &dev->c_hs_mem->state);
		break;
	case WAIT_FOR_RNG:
		str_state = "WAIT_FOR_RNG\n";
		set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));
		set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));

		iowrite8(WAIT_FOR_RNG, &dev->c_hs_mem->command);
		barrier();
		iowrite8(FW_WAIT_FOR_RNG, &dev->c_hs_mem->state);
		break;
	case RNG_DONE:
		str_state = "RNG_DONE\n";
		set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));
		set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
				(uint8_t *) str_state, strlen(str_state));

		iowrite8(RNG_DONE, &dev->c_hs_mem->command);
		barrier();
		iowrite8(FW_RNG_DONE, &dev->c_hs_mem->state);
		break;
	default:
		print_error("Invalid command: %d\n", cmd);
	}

	return;
}

void hs_firmware_up(fsl_crypto_dev_t *dev)
{
	char *str_state = "FIRMWARE_UP\n";
	struct fw_up_data *hsdev = &dev->host_mem->hs_mem.data.device;
	uint32_t p_ib_l;
	uint32_t p_ib_h;
	uint32_t p_ob_l;
	uint32_t p_ob_h;

	print_debug(" ----------- FIRMWARE_UP -----------\n");
	set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE, str_state,
			strlen(str_state));

	dev->host_mem->hs_mem.state = DEFAULT;

	p_ib_l = be32_to_cpu(hsdev->p_ib_mem_base_l);
	p_ib_h = be32_to_cpu(hsdev->p_ib_mem_base_h);
	p_ob_l = be32_to_cpu(hsdev->p_ob_mem_base_l);
	p_ob_h = be32_to_cpu(hsdev->p_ob_mem_base_h);

	dev->priv_dev->bars[MEM_TYPE_SRAM].dev_p_addr = (dev_p_addr_t) p_ib_h << 32;
	dev->priv_dev->bars[MEM_TYPE_SRAM].dev_p_addr |= p_ib_l;

	dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr = (dev_p_addr_t) p_ob_h << 32;
	dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr |= p_ob_l;

	print_debug("Device Shared Details\n");
	print_debug("Ib mem PhyAddr L: %0x, H: %0x\n", p_ib_l, p_ib_h);
	print_debug("Ob mem PhyAddr L: %0x, H: %0x\n", p_ob_l, p_ob_h);
	print_debug("Formed dev ib mem phys address: %llx\n",
			(uint64_t)dev->priv_dev->bars[MEM_TYPE_SRAM].dev_p_addr);
	print_debug("Formed dev ob mem phys address: %llx\n",
			(uint64_t)dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr);

	send_hs_init_config(dev);
}

void hs_fw_init_complete(fsl_crypto_dev_t *dev, struct crypto_dev_config *config, uint8_t rid)
{
	char *str_state = "FW_INIT_CONFIG_COMPLETE\n";
	struct config_data *hscfg = &dev->host_mem->hs_mem.data.config;
	void *ptr;
	uint32_t r_s_c_cntrs;
	uint32_t s_c_cntrs;
	uint32_t ip_pool;
	uint32_t resp_intr_ctrl_flag;
	int i;

	print_debug("--- FW_INIT_CONFIG_COMPLETE ---\n");
	set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE, str_state,
			strlen(str_state));

	dev->host_mem->hs_mem.state = DEFAULT;

	r_s_c_cntrs = be32_to_cpu(hscfg->r_s_c_cntrs);
	s_c_cntrs = be32_to_cpu(hscfg->s_c_cntrs);
	ip_pool = be32_to_cpu(hscfg->ip_pool);
	resp_intr_ctrl_flag = be32_to_cpu(hscfg->resp_intr_ctrl_flag);

	dev->r_s_c_cntrs = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + r_s_c_cntrs;
	dev->s_c_cntrs = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + s_c_cntrs;
	dev->dev_ip_pool.d_p_addr = dev->priv_dev->bars[MEM_TYPE_SRAM].dev_p_addr + ip_pool;
#ifdef USE_HOST_DMA
	dev->dev_ip_pool.host_map_p_addr = dev->priv_dev->bars[MEM_TYPE_SRAM].host_p_addr + ip_pool;
#endif
	dev->dev_ip_pool.h_v_addr = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + ip_pool;

	ptr = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + resp_intr_ctrl_flag;
	for (i = 0; i < NUM_OF_RESP_RINGS; i++) {
		/* FIXME: this assignment is wrong. There is an inconsistency about
		 * the total number of response rings. In some places it is simply
		 * assumed there is only one. In other places as in here more than
		 * one can be the case.
		 * Here, the addresses of intr_ctrl_flag are _not_ uint32_t away
		 * one from another. Instead they are distanced by fw_resp_ring
		 * away from each other (or probably driver_resp_ring in firmware ?)
		 * Even so, playing with pointers like this asks for trouble.
		 * And we might need more than one response ring for increased
		 * performance
		 */
		dev->fw_resp_rings[i].intr_ctrl_flag = ptr + (i * sizeof(uint32_t *));
		dev->fw_resp_rings[i].r_s_c_cntrs = &(dev->r_s_c_cntrs[dev->num_of_rings + i]);
		print_debug("FW Intrl Ctrl Flag: %p\n", dev->fw_resp_rings[i].intr_ctrl_flag);
	}

	print_debug(" ----- Details from firmware  -------\n");
	print_debug("SRAM H V ADDR: %p\n", dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr);
	print_debug("R S C CNTRS OFFSET: %x\n", r_s_c_cntrs);
	print_debug("S C CNTRS OFFSET: %x\n", s_c_cntrs);
	print_debug("-----------------------------------\n");
	print_debug("R S C Cntrs: %p\n", dev->r_s_c_cntrs);
	print_debug("S C Cntrs: %p\n", dev->s_c_cntrs);
	print_debug("FW Pool Dev P addr : %pa\n", &dev->dev_ip_pool.d_p_addr);
#ifdef USE_HOST_DMA
	print_debug("FW Pool host P addr: %pa\n", &(dev->dev_ip_pool.host_map_p_addr));
#endif
	print_debug("FW Pool host V addr: %p\n", dev->dev_ip_pool.h_v_addr);

	send_hs_command(HS_INIT_RING_PAIR, dev,	&(config->ring[rid]));
}

uint8_t hs_init_rp_complete(fsl_crypto_dev_t *dev, struct crypto_dev_config *config, uint8_t rid)
{
	char *str_state = "FW_INIT_RING_PAIR_COMPLETE\n";
	struct ring_data *hsring = &dev->host_mem->hs_mem.data.ring;
	uint32_t req_r;
	uint32_t intr_ctrl_flag;

	print_debug("---- FW_INIT_RING_PAIR_COMPLETE ----\n");
	set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE, str_state,
			strlen(str_state));

	dev->host_mem->hs_mem.state = DEFAULT;
	req_r = be32_to_cpu(hsring->req_r);
	intr_ctrl_flag = be32_to_cpu(hsring->intr_ctrl_flag);

	dev->ring_pairs[rid].shadow_counters = &(dev->r_s_c_cntrs[rid]);
	dev->ring_pairs[rid].req_r =dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + req_r;
	dev->ring_pairs[rid].intr_ctrl_flag = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr +
			intr_ctrl_flag;

	print_debug("Ring id: %d\n", rid);
	print_debug("Shadow cntrs: %p\n", dev->ring_pairs[rid].shadow_counters);
	print_debug("Req r: %p\n", dev->ring_pairs[rid].req_r);

	rid++;
	if (rid < dev->num_of_rings) {
		send_hs_command(HS_INIT_RING_PAIR, dev,	&(config->ring[rid]));
	} else {
		send_hs_command(HS_COMPLETE, dev, NULL);
	}

	return rid;
}

int32_t handshake(fsl_crypto_dev_t *dev, struct crypto_dev_config *config)
{
	uint8_t rid = 0;
	uint32_t timeoutcntr = 0;
	uint32_t no_secs;
#define LOOP_BREAK_TIMEOUT_MS		1000
#define LOOP_BREAK_TIMEOUT_JIFFIES	msecs_to_jiffies(LOOP_BREAK_TIMEOUT_MS)
#define HS_TIMEOUT_IN_MS		(50 * LOOP_BREAK_TIMEOUT_MS)

	while (true) {
		switch (dev->host_mem->hs_mem.state) {
		case FIRMWARE_UP:
			/* This is the first thing communicated by the firmware:
			 * The device is UP and converted the MSI and OB_MEM
			 * addresses into device space.
			 */
			hs_firmware_up(dev);
			break;
		case FW_INIT_CONFIG_COMPLETE:
			hs_fw_init_complete(dev, config, rid);
			break;
		case FW_INIT_RING_PAIR_COMPLETE:
			no_secs = be32_to_cpu(dev->host_mem->hs_mem.data.device.no_secs);
			if (f_get_a(config->ring[rid].flags) > no_secs) {
				print_error("Wrong Affinity for the ring: %d\n", rid);
				print_error("No of SECs are %d\n", no_secs);
				goto error;
			}
			rid = hs_init_rp_complete(dev, config, rid);
			break;
		case FW_INIT_RNG:
			send_hs_command(WAIT_FOR_RNG, dev, NULL);
			if (rng_instantiation(dev)) {
				print_error("RNG Instantiation Failed!\n");
				goto error;
			} else {
				send_hs_command(RNG_DONE, dev, NULL);
				goto exit;
			}
			break;
		case FW_RNG_COMPLETE:
			goto exit;

		case DEFAULT:
			if (!
			    (HS_TIMEOUT_IN_MS -
			     (timeoutcntr * LOOP_BREAK_TIMEOUT_MS))) {
				print_error("HS Timed out!!!!\n");
				goto error;
			}

			/* Schedule out so that loop does not hog CPU */
			++timeoutcntr;
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(LOOP_BREAK_TIMEOUT_JIFFIES);

			break;

		default:
			print_error("Invalid state: %d\n", dev->host_mem->hs_mem.state);
			goto error;
		}
	}
exit:
	set_sysfs_value(dev->priv_dev, FIRMWARE_STATE_SYSFILE,
			(uint8_t *) "FW READY\n", strlen("FW READY\n"));
	set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
			(uint8_t *) "DRIVER READY\n", strlen("DRIVER READY\n"));
	return 0;

error:
	return -1;

}

#ifdef CHECK_EP_BOOTUP
static void check_ep_bootup(fsl_crypto_dev_t *dev)
{
	unsigned char *ibaddr = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr;
	unsigned char *obaddr = dev->priv_dev->bars[MEM_TYPE_DRIVER].host_v_addr;

	char stdstr[] = "SUCCESS";
	char obstr[] = "0000000";
	int i = 0, bootup = 1;
	uint8_t val = 0;

	print_debug("======= check_ep_bootup =======\n");
	print_debug("IB Addr: %p, OB Addr: %p\n", ibaddr, obaddr);

	ibaddr += (512 * 1024);

	for (i = 0; i < sizeof(stdstr); i++) {
		val = ioread8((char *)ibaddr + i);
		if (stdstr[i] != val) {
			print_error
			    ("Invld byte at loc :%d, val : %0x, shld be :%0x\n",
			     i, val, stdstr[i]);
			bootup = 0;
		}
	}

	if (!bootup)
		print_error("!!! Bootup Failed.....\n");
	else
		print_debug("Bootup Successfull...\n");

	for (i = 0; i < 100; i++) {
		strncpy(obstr, obaddr, sizeof(stdstr));
		if (!strcmp(obstr, stdstr)) {
			print_debug("Got ittttt....\n");
			break;
		} else
			print_debug("Not yetttt...\n");

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(100));
	}
}
#endif

static void setup_ep(fsl_crypto_dev_t *dev)
{
	/* Note: reserved bits are written with zeros as per reference manual
	 *
	 * These are the addresses where L2 SRAM and platform cache will be
	 * mapped on the device. We configure them as a contiguous 1MB region
	 * which will hold the firmware and operand data */
	unsigned int l2_sram_start = 0xfff00000;
	unsigned int p_sram_start  = 0xfff80000;
	unsigned int val;

	/* CCSR base address is obtained from BAR0 device register */
	void *ccsr = dev->priv_dev->bars[MEM_TYPE_CONFIG].host_v_addr;

	/* disable L2 SRAM ECC error
	 * TODO: enable ECC by default for normal operation */
	val = ioread32be(ccsr + 0x20e44);
	iowrite32be(val | 0x0c,		ccsr + 0x20e44);

	/* Set L2 SRAM memory-mapped address and enable the whole 512KB block */
	iowrite32be(l2_sram_start,	ccsr + 0x20100); /* L2_Cache_L2SRBAR0 */
	iowrite32be(0,			ccsr + 0x20104); /* L2_Cache_L2SRBAREA0 */
	iowrite32be(0x80010000,		ccsr + 0x20000); /* L2_Cache_L2CTL */

	/* Set memory map for platform SRAM and PCIe. The window addresses are
	 * specified right shifted by 12 bits (the minimum window size is 4K)
	 *
	 * Set LAW for target platform SRAM, size 2^0x13 = 512KB */
	iowrite32be(p_sram_start >> 12,	ccsr + 0xc08); /* LAW_LAWBAR0 */
	iowrite32be(0x80a00012,		ccsr + 0xc10); /* LAW_LAWAR0 */

	/* Set LAW for target PCIe, size 2^0x22 = 16G, starting address 32G */
	iowrite32be(0x800000000 >> 12,	ccsr + 0xc28); /* LAW_LAWBAR1 */
	iowrite32be(0x80200021,		ccsr + 0xc30); /* LAW_LAWAR1 */

	/* Set PEX inbound and outbound window translations. These must match
	 * the LAWs defined earlier
	 *
	 * Set PEX inbound transactions to local memory
	 * Addresses in the window of size 2^0x14 = 1MB starting at 0 are
	 * translated with an offset of l2_sram_start in device space */
	iowrite32be(l2_sram_start >> 12, ccsr + 0xadc0); /* PEX_PEXITAR1 */
	iowrite32be(0,			ccsr + 0xadc8);  /* PEX_PEXIWBAR1 */
	iowrite32be(0xa0f55013,		ccsr + 0xadd0);  /* PEX_PEXIWAR1 */

	/* Set PEX outbound transactions from device to host
	 * Addresses in the window of size 2^0x22 = 16G starting at 32G
	 * go to host untranslated */
	iowrite32be(0,			ccsr + 0xac20); /* PEX_PEXOTAR1 */
	iowrite32be(0,			ccsr + 0xac24); /* PEX_PEXOTEAR1 */
	iowrite32be(0x800000000 >> 12,	ccsr + 0xac28); /* PEX_PEXOWBAR1 */
	iowrite32be(0x80044021,		ccsr + 0xac30); /* PEX_PEXOWAR1 */

	/* Read-back LAW register to guarantee visibility to all device blocks */
	val = ioread32be(ccsr + 0xc30); /* LAW_LAWAR1 */

	print_debug("======= setup_ep =======\n");
	print_debug("Ob mem dma_addr: %pa\n", &(dev->priv_dev->bars[MEM_TYPE_DRIVER].host_dma_addr));
	print_debug("Ob mem len: %pa\n", &dev->priv_dev->bars[MEM_TYPE_DRIVER].len);
	print_debug("BAR0 V Addr: %p\n", ccsr);
	print_debug("MSI mem: %pa\n", &(dev->priv_dev->bars[MEM_TYPE_MSI].host_p_addr));

	/* Dumping the registers set */
	print_debug(" ==== EP REGISTERS ====\n");
	print_debug("0X20100 :- %0x\n", ioread32be(ccsr + 0x20100));
	print_debug("0X20104 :- %0x\n", ioread32be(ccsr + 0x20104));
	print_debug("0X20000 :- %0x\n", ioread32be(ccsr + 0x20000));

	print_debug("0xc08  :- :%0x\n", ioread32be(ccsr + 0xc08));
	print_debug("0xc10  :- :%0x\n", ioread32be(ccsr + 0xc10));

	print_debug("0xc28  :- :%0x\n", ioread32be(ccsr + 0xc28));
	print_debug("0xc30  :- :%0x\n", ioread32be(ccsr + 0xc30));

	print_debug("0xadd0 :- :%0x\n", ioread32be(ccsr + 0xadd0));
	print_debug("0xadc0 :- :%0x\n", ioread32be(ccsr + 0xadc0));

	print_debug("0xac20 :- :%0x\n", ioread32be(ccsr + 0xac20));
	print_debug("0xac24 :- :%0x\n", ioread32be(ccsr + 0xac24));
	print_debug("0xac28 :- :%0x\n", ioread32be(ccsr + 0xac28));
	print_debug("0xac30 :- :%0x\n", ioread32be(ccsr + 0xac30));

	print_debug("0xac40 :- :%0x\n", ioread32be(ccsr + 0xac40));
	print_debug("0xac44 :- :%0x\n", ioread32be(ccsr + 0xac44));
	print_debug("0xac48 :- :%0x\n", ioread32be(ccsr + 0xac48));
	print_debug("0xac50 :- :%0x\n", ioread32be(ccsr + 0xac50));

	print_debug("=======================\n");
}

static int32_t load_firmware(fsl_crypto_dev_t *dev, uint8_t *fw_file_path)
{
	uint8_t byte;
	uint32_t i;
	void *fw_addr = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr +
				FIRMWARE_IMAGE_START_OFFSET;
	loff_t pos = 0;
	struct file *file = NULL;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	if (unlikely(NULL == fw_file_path)) {
		print_error("NULL arg\n");
		return -1;
	}

	print_debug("Firmware file path: %s\n", fw_file_path);

	file = filp_open((const char *)fw_file_path, O_RDWR, 0);
	if (IS_ERR(file)) {
		print_error("Firmware file path [%s] does not exist\n",
			    fw_file_path);
		return -1;
	}

	/* Read each byte from the file and write it to the SRAM fw area*/
	for (i = 0; i < FSL_FIRMWARE_SIZE; i++) {
		vfs_read(file, &byte, 1, &pos);
		iowrite8(byte, fw_addr + i);
	}

	filp_close(file, 0);
	set_fs(old_fs);

	return 0;
}

void init_op_pool(fsl_crypto_dev_t *dev)
{
	create_pool(&dev->op_pool.buf_pool, dev->host_mem->op_pool,
			DEFAULT_HOST_OP_BUFFER_POOL_SIZE);

	dev->op_pool.h_v_addr = dev->host_mem->op_pool;
	dev->op_pool.h_p_addr = __pa(dev->host_mem->op_pool);
}

void init_ip_pool(fsl_crypto_dev_t *dev)
{
	create_pool(&dev->host_ip_pool.buf_pool, dev->host_mem->ip_pool,
			FIRMWARE_IP_BUFFER_POOL_SIZE);

	dev->host_ip_pool.h_v_addr = dev->host_mem->ip_pool;
	dev->host_ip_pool.h_p_addr = __pa(dev->host_mem->ip_pool);
}

int init_crypto_ctx_pool(fsl_crypto_dev_t *dev)
{
	int i, id;
	ctx_pool_t *pool;

	pool = kzalloc(sizeof(ctx_pool_t) * NR_CTX_POOLS, GFP_KERNEL);
	if (!pool)
		return -ENOMEM;

	/* save the address of the first context pool */
	dev->ctx_pool = pool;

	for (id = 0; id < NR_CTX_POOLS; id++) {
		for (i = 0; i < NUM_OF_CTXS - 1; i++)
			pool->mem[i].next = &(pool->mem[i + 1]);

		pool->mem[i].next = NULL;
		pool->head = &pool->mem[0];
		spin_lock_init(&pool->ctx_lock);

		pool += 1;
	}
	return 0;
}

static int32_t ring_enqueue(fsl_crypto_dev_t *c_dev, uint32_t jr_id,
			    dev_dma_addr_t sec_desc)
{
	uint32_t wi = 0;
	uint32_t jobs_processed = 0;
#ifndef HIGH_PERF
	uint32_t app_req_cnt = 0;
#endif
	fsl_h_rsrc_ring_pair_t *rp = NULL;

#ifndef HIGH_PERF
#ifdef MULTIPLE_RESP_RINGS
	dev_dma_addr_t ctx_desc = 0;
	void *h_desc = 0;
#ifdef SEC_DMA
        dev_p_addr_t offset = c_dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;
#endif
#endif
#endif

	print_debug("Sec desc addr: %llx\n", sec_desc);
	print_debug("Enqueue job in ring: %d\n", jr_id);

	rp = &(c_dev->ring_pairs[jr_id]);

	/* Acquire the lock on current ring */
	spin_lock_bh(&rp->ring_lock);

	jobs_processed = be32_to_cpu(rp->r_s_cntrs->jobs_processed);

	if (rp->counters->jobs_added - jobs_processed >= rp->depth) {
		print_error("Ring: %d is full\n", jr_id);
		spin_unlock_bh(&(rp->ring_lock));
		return -1;
	}
#ifndef HIGH_PERF
#ifdef MULTIPLE_RESP_RINGS
	if (jr_id != 0) {
		ctx_desc = sec_desc & ~((uint64_t) 0x03);
#ifdef SEC_DMA
                if (ctx_desc < offset) {
#endif
                    h_desc = c_dev->dev_ip_pool.host_map_v_addr + (ctx_desc - c_dev->dev_ip_pool.dev_p_addr);
#ifdef SEC_DMA
                } else {
                    h_desc = c_dev->dev_ip_pool.host_map_v_addr + (ctx_desc - offset - c_dev->host_ip_pool.p_addr);
		}
#endif

		if (f_get_o(rp->info.flags)) {
			print_debug("Order bit is set: %d, Desc: %llx\n", rp->indexes->w_index, sec_desc);
			store_dev_ctx(h_desc, jr_id, rp->indexes->w_index + 1);
		} else{
			print_debug("Order bit is not set: %d, Desc: %0llx\n", rp->indexes->w_index, sec_desc);
			store_dev_ctx(h_desc, jr_id, 0);
		}
	}
#endif
#endif
	wi = rp->indexes->w_index;

	print_debug("Enqueuing at the index: %d\n", wi);
	print_debug("Enqueuing to the req r addr: %p\n", rp->req_r);
	print_debug("Writing at the addr	: %p\n", &(rp->req_r[wi].sec_desc));

	IOWRITE64BE(sec_desc, &rp->req_r[wi].sec_desc);

	rp->indexes->w_index = (wi + 1) % rp->depth;
	print_debug("Update W index: %d\n", rp->indexes->w_index);

	rp->counters->jobs_added += 1;
	print_debug("Updated jobs added: %d\n", rp->counters->jobs_added);
#ifndef HIGH_PERF
	if (jr_id) {
		app_req_cnt =  atomic_inc_return(&c_dev->app_req_cnt);
		set_sysfs_value(c_dev->priv_dev, STATS_REQ_COUNT_SYS_FILE,
				(uint8_t *) &(app_req_cnt),
				sizeof(app_req_cnt));
	}
#endif
	print_debug("Ring: %d	Shadow counter address	%p\n", jr_id,
		    &(rp->shadow_counters->jobs_added));
	rp->shadow_counters->jobs_added = be32_to_cpu(rp->counters->jobs_added);

	spin_unlock_bh(&(rp->ring_lock));
	return 0;
}

#define CRYPTO_INFO_STR_LENGTH 200
int prepare_crypto_cfg_info_string(struct crypto_dev_config *config,
		uint8_t *cryp_cfg_str)
{
	uint32_t i;
	uint8_t flags;
	int rem_len = CRYPTO_INFO_STR_LENGTH;
	int ret;

	ret = snprintf(cryp_cfg_str, rem_len,
			"Tot rings:%d\nrid,dpth,affin,prio,ord\n",
			config->num_of_rings);

	if ((ret < 0) || (ret >= rem_len))
		return ret;
	rem_len -= ret;
	cryp_cfg_str += ret;

	for (i = 0; i < config->num_of_rings; i++) {
		flags = config->ring[i].flags;
		ret = snprintf(cryp_cfg_str, rem_len, " %d,%4d,%d,%d,%d\n",
				i, config->ring[i].depth, f_get_a(flags),
				f_get_p(flags), f_get_o(flags));

		if ((ret < 0) || (ret >= rem_len))
			return ret;
		rem_len -= ret;
		cryp_cfg_str += ret;
	}
	return 0;
}


int32_t set_device_status_per_cpu(fsl_crypto_dev_t *c_dev, uint8_t set)
{
	uint32_t i = 0;
	per_dev_struct_t *dev_stat = NULL;
	for_each_online_cpu(i) {
		dev_stat = per_cpu_ptr(c_dev->dev_status, i);
		atomic_set(&(dev_stat->device_status), set);
	}
	return 0;
}

void stop_device(fsl_crypto_dev_t *dev)
{
	void *ccsr = dev->priv_dev->bars[MEM_TYPE_CONFIG].host_v_addr;
	uint32_t cpu0_en;

	/* Reset CPU core only if it is enabled. If the device is coming from
	 * a hard reset or cold boot the core will be in hold-off mode. We
	 * should not reset it in that state
	 */
	cpu0_en = ioread32be(ccsr + BRR_OFFSET) & BRR_RELEASE_CORE0;
	if (cpu0_en) {
		iowrite32be(1, ccsr + PIC_PIR);
		udelay(250);
	}
}

void start_device(fsl_crypto_dev_t *dev)
{
	void *ccsr = dev->priv_dev->bars[MEM_TYPE_CONFIG].host_v_addr;
	uint32_t cpu0_en;

	/* Enable CPU core and let it run the firmware: either release the
	 * hold-off mode or clear the CPU core reset register
	 */
	cpu0_en = ioread32be(ccsr + BRR_OFFSET) & BRR_RELEASE_CORE0;
	if (cpu0_en) {
		iowrite32be(0, ccsr + PIC_PIR);
	} else {
		iowrite32be(BRR_RELEASE_CORE0, ccsr + BRR_OFFSET);
	}

	udelay(250);
}

fsl_crypto_dev_t *fsl_crypto_layer_add_device(struct c29x_dev *fsl_pci_dev,
				  struct crypto_dev_config *config)
{
	uint8_t crypto_info_str[CRYPTO_INFO_STR_LENGTH];
	fsl_crypto_dev_t *c_dev;
	int err;

	/* some fields are assumed to be null when they are first used */
	c_dev = kzalloc(sizeof(fsl_crypto_dev_t), GFP_KERNEL);
	if (!c_dev)
		return NULL;

	c_dev->ring_pairs = kzalloc(sizeof(fsl_h_rsrc_ring_pair_t) *
				    config->num_of_rings, GFP_KERNEL);
	if (!c_dev->ring_pairs)
		goto rp_fail;

	c_dev->priv_dev = fsl_pci_dev;
	c_dev->config = config;

	/* HACK */
	fsl_pci_dev->crypto_dev = c_dev;

	atomic_set(&(c_dev->crypto_dev_sess_cnt), 0);

	c_dev->c_hs_mem = c_dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + HS_MEM_OFFSET;

	print_debug("IB mem addr: %p\n", c_dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr);
	print_debug("Device hs mem addr: %p\n", c_dev->c_hs_mem);

	/* Rearrange rings according to their priority */
	print_debug("Rearrange rings.....\n");
	rearrange_rings(c_dev, config);
	print_debug("Rearrange complete....\n");

	err = alloc_ob_mem(c_dev, config);
	if (err) {
		print_error("Ob mem alloc failed....\n");
		goto ob_mem_fail;
	}

	init_ip_pool(c_dev);
	init_op_pool(c_dev);

	err = init_crypto_ctx_pool(c_dev);
	if (err) {
		print_error("Failed to allocate context pool\n");
		goto ctx_pool_fail;
	}

	print_debug("Init fw resp ring....\n");
	init_fw_resp_ring(c_dev);
	print_debug("Init fw resp ring complete...\n");

	print_debug("Init ring  pair....\n");
	init_ring_pairs(c_dev);
	print_debug("Init ring pair complete...\n");

	print_debug("Distribute ring...\n");
	/* Distribute rings to cores and BHs */
	distribute_rings(c_dev, config);
	print_debug("Distribute ring complete...\n");

	stop_device(c_dev);

#ifdef C293_EP
	/* Set the EP registers correctly before booting... */
	setup_ep(c_dev);
#endif

	print_debug("Init Handshake....\n");
	init_handshake(c_dev);
	print_debug("Init Handshake complete...\n");

	err = load_firmware(c_dev, config->fw_file_path);
	if (err) {
		print_error("Firmware download failed\n");
		goto error;
	}

	start_device(c_dev);

#ifdef CHECK_EP_BOOTUP
	check_ep_bootup(c_dev);
#endif

	set_sysfs_value(fsl_pci_dev, DEVICE_STATE_SYSFILE, (uint8_t *) "HS Started\n",
			strlen("HS Started\n"));

	c_dev->dev_status = alloc_percpu(per_dev_struct_t);
	set_device_status_per_cpu(c_dev, 1);
	atomic_set(&(c_dev->active_jobs), 0);

	err = handshake(c_dev, config);
	if (err) {
		print_error("Handshake failed\n");
		goto error;
	}

	err = prepare_crypto_cfg_info_string(config, crypto_info_str);
	if (err) {
		print_error("Preparing crypto config info string failed\n");
		goto error;
	}
	set_sysfs_value(fsl_pci_dev, CRYPTO_INFO_SYS_FILE, (uint8_t *)crypto_info_str,
			strlen(crypto_info_str));

	printk(KERN_INFO "[FSL-CRYPTO-OFFLOAD-DRV] DevId:%d DEVICE IS UP\n",
	       c_dev->config->dev_no);

	return c_dev;

error:
	kfree(c_dev->ctx_pool);
ctx_pool_fail:
	pci_free_consistent(c_dev->priv_dev->dev,
			    c_dev->priv_dev->bars[MEM_TYPE_DRIVER].len,
			    c_dev->priv_dev->bars[MEM_TYPE_DRIVER].host_v_addr,
			    c_dev->priv_dev->bars[MEM_TYPE_DRIVER].host_dma_addr);
ob_mem_fail:
	kfree(c_dev->ring_pairs);
rp_fail:
	kfree(c_dev);
	return NULL;
}

void clear_ring_lists(void)
{
	uint32_t i;
	struct bh_handler *instance;
	struct list_head *pos, *next;

	for_each_online_cpu(i) {
		instance = per_cpu_ptr(per_core, i);

		list_for_each_safe(pos, next, &(instance->ring_list_head)) {
			list_del(pos);
		}
	}
}

void cleanup_crypto_device(fsl_crypto_dev_t *dev)
{
	if (NULL == dev)
		return;
#if 0
	int i = 0;
	for (i = 0; i < dev->num_of_rings; i++) {
		/* Delete all the links */
		list_del(&(dev->ring_pairs[i].isr_ctx_list_node));
		list_del(&(dev->ring_pairs[i].bh_ctx_list_node));
	}
#endif

	kfree(dev->ctx_pool);

	/* Free the pci alloc consistent mem */
	if (dev->priv_dev->bars[MEM_TYPE_DRIVER].host_v_addr) {
		pci_free_consistent(dev->priv_dev->dev,
				    dev->priv_dev->bars[MEM_TYPE_DRIVER].len,
				    dev->priv_dev->bars[MEM_TYPE_DRIVER].host_v_addr,
				    dev->priv_dev->bars[MEM_TYPE_DRIVER].host_dma_addr);
	}

	clear_ring_lists();
	kfree(dev->ring_pairs);
	kfree(dev);
}

int32_t app_ring_enqueue(fsl_crypto_dev_t *c_dev, uint32_t jr_id,
			 dev_dma_addr_t sec_desc)
{
	int32_t ret = 0;
#ifndef HIGH_PERF
	/* Check the block flag for the ring */
	if (0 != atomic_read(&(c_dev->ring_pairs[jr_id].block))) {
		print_debug("Block condition is set for the ring: %d\n", jr_id);
		return -1;
	}
#endif
	ret = ring_enqueue(c_dev, jr_id, sec_desc);

	return ret;
}

int32_t cmd_ring_enqueue(fsl_crypto_dev_t *c_dev, uint32_t jr_id,
			 dev_dma_addr_t sec_desc)
{
	print_debug("Command ring enqueue called...\n");
	return ring_enqueue(c_dev, jr_id, sec_desc);
}

void handle_response(fsl_crypto_dev_t *dev, uint64_t desc, int32_t res)
{
	dma_addr_t *h_desc;

	crypto_op_ctx_t *ctx0 = NULL;
#ifndef HIGH_PERF
	crypto_job_ctx_t *ctx1 = NULL;
#endif

#ifdef SEC_DMA
        dev_p_addr_t offset = dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;
#endif

#ifdef SEC_DMA
        if (desc < offset) {
#endif
            h_desc = dev->host_ip_pool.h_v_addr + (desc - dev->dev_ip_pool.d_p_addr);
#ifdef SEC_DMA
        } else {
            h_desc = dev->host_ip_pool.h_v_addr + (desc - offset - dev->host_ip_pool.h_p_addr);
        }
#endif

#ifndef HIGH_PERF
	if (get_flag(dev->host_ip_pool.pool, h_desc))
#endif
		ctx0 = (crypto_op_ctx_t *) get_priv_data(h_desc);
#ifndef HIGH_PERF
	else
		ctx1 = (crypto_job_ctx_t *) get_priv_data(h_desc);

	print_debug("Total Resp count: %d\n", ++total_resp);
	print_debug("[DEQ] Dev sec desc : %llx\n", desc);
	print_debug("[DEQ] H sec desc: %pa\n", &h_desc);
	print_debug("[DEQ] Ctx0 address: %p\n", ctx0);
	print_debug("[DEQ] Ctx1 address: %p\n", ctx1);
#endif

	if (ctx0) {
#ifdef SEC_DMA
                if (desc >= offset) {
                    unmap_crypto_mem(&ctx0->crypto_mem);
                }
#endif
		ctx0->op_done(ctx0, res);
        } else {
		print_debug("NULL Context!!\n");
	}

#ifndef HIGH_PERF
	if (ctx1) {
		crypto_op_done(dev, ctx1, res);
	}
#endif
	return;

}

#ifndef MULTIPLE_RESP_RINGS
void demux_fw_responses(fsl_crypto_dev_t *dev)
{
	uint32_t ri = 0;
	uint32_t count = 0;
	uint64_t desc = 0;
	int32_t res = 0;
	uint32_t jobs_added = 0;
	uint32_t app_resp_cnt = 0;
#define MAX_ERROR_STRING 400
	char outstr[MAX_ERROR_STRING];

	struct resp_ring_entry *resp_ring = dev->fw_resp_ring.v_addr;

	jobs_added = be32_to_cpu(dev->fw_resp_ring.r_s_cntrs->jobs_added);
	count = jobs_added - dev->fw_resp_ring.cntrs->jobs_processed;

	if (!count)
		goto CMD_RING_RESP;

	dev->fw_resp_ring.cntrs->jobs_processed += count;
	ri = dev->fw_resp_ring.idxs->r_index;

	app_resp_cnt = atomic_read(&dev->app_resp_cnt);


	while (count) {
#if 0
		/* Enqueue it to the dest ring */
		enqueue_to_dest_ring(dev, resp_ring[ri].sec_desc,
				     resp_ring[ri].result);
#endif
		res = be32_to_cpu(resp_ring[ri].result);
		desc = be64_to_cpu(resp_ring[ri].sec_desc);

		sec_jr_strstatus(outstr, res);

		if (res)
			print_error("Error from SEC: %s\n", outstr);

		ri = (ri + 1) % (dev->fw_resp_ring.depth);

		count--;

		print_debug("Read index: %d\n", ri);

		handle_response(dev, desc, res);
		print_debug("Handle response done...\n");

		atomic_inc_return(&dev->app_resp_cnt);
	}

	if(app_resp_cnt != atomic_read(&dev->app_resp_cnt))
	{
		app_resp_cnt = atomic_read(&dev->app_resp_cnt);
		set_sysfs_value(dev->priv_dev, STATS_RESP_COUNT_SYS_FILE,
			(uint8_t *) &(app_resp_cnt),
			sizeof(app_resp_cnt));
	}

	dev->fw_resp_ring.idxs->r_index = be32_to_cpu(ri);
	iowrite32be(dev->fw_resp_ring.cntrs->jobs_processed,
		&dev->fw_resp_ring.s_cntrs->resp_jobs_processed);

	*(dev->fw_resp_ring.intr_ctrl_flag) = 0;

CMD_RING_RESP:
/* Command ring response processing */
/*	printk(KERN_ERR "*** Jobs added.. :%d Jobs processed... :%d\n",
		dev->ring_pairs[0].s_c_counters->jobs_added ,
		dev->ring_pairs[0].counters->jobs_processed);*/

	if (dev->ring_pairs[0].s_c_counters->jobs_added -
	    dev->ring_pairs[0].counters->jobs_processed) {
		ri = dev->ring_pairs[0].indexes->r_index;

		desc = be64_to_cpu(dev->ring_pairs[0].resp_r[ri].sec_desc);

		print_debug("DEQUEUE RESP AT: %u RESP DESC: %llx  == [%p]",
		     ri, desc, &(dev->ring_pairs[0].resp_r[ri]));

		if (desc) {
			res = be32_to_cpu(dev->ring_pairs[0].resp_r[ri].result);
			process_cmd_response(dev, desc, res);
			ri = (ri + 1) % (dev->ring_pairs[0].depth);
			dev->ring_pairs[0].indexes->r_index = be32_to_cpu(ri);
			dev->ring_pairs[0].counters->jobs_processed += 1;

			iowrite32be(dev->ring_pairs[0].counters->jobs_processed,
				&dev->ring_pairs[0].shadow_counters->resp_jobs_processed);
		}
	}
	return;
}

#else

#define MAX_ERROR_STRING 400

/* FIXME: function argument dev is overwritten in the first loop */
void process_response(fsl_crypto_dev_t *dev, fsl_h_rsrc_ring_pair_t *ring_cursor)
{
	uint32_t pollcount;
	uint32_t jobs_added = 0;
	uint32_t resp_cnt = 0;
	uint32_t ri;
	uint64_t desc;
	int32_t res = 0;
	struct device *my_dev = &dev->priv_dev->dev->dev;
#ifndef HIGH_PERF
	uint32_t r_id;
	uint32_t app_resp_cnt = 0;
#endif

	pollcount = 0;

	while (pollcount++ < napi_poll_count) {
		jobs_added = be32_to_cpu(ring_cursor->r_s_cntrs->jobs_added);
		resp_cnt = jobs_added - ring_cursor->counters->jobs_processed;
		if (!resp_cnt)
			continue;

		dev = ring_cursor->dev;
#ifndef HIGH_PERF
		r_id = ring_cursor->info.ring_id;
#endif
		ri = ring_cursor->indexes->r_index;
		print_debug("RING ID: %d\n", ring_cursor->info.ring_id);
		print_debug("GOT INTERRUPT FROM DEV: %d\n", dev->config->dev_no);

		while (resp_cnt) {
			desc = be64_to_cpu(ring_cursor->resp_r[ri].sec_desc);
			res = be32_to_cpu(ring_cursor->resp_r[ri].result);
#ifndef HIGH_PERF
			if (r_id == 0) {
				print_debug("COMMAND RING GOT AN INTERRUPT\n");
				if (desc)
					process_cmd_response(dev, desc, res);
			} else
#endif
			{
				print_debug("APP RING GOT AN INTERRUPT\n");
				if (desc) {
					handle_response(dev, desc, res);
				} else {
					dev_err(my_dev, "INVALID DESC AT RI : %u\n", ri);
				}
				if (res) {
					sec_jr_strstatus(my_dev, res);
				}
#ifndef HIGH_PERF
				atomic_inc_return(&dev->app_resp_cnt);
#endif
			}
			ring_cursor->counters->jobs_processed += 1;
			iowrite32be(ring_cursor->counters->jobs_processed,
				&ring_cursor->shadow_counters->jobs_processed);

			ri = (ri + 1) % (ring_cursor->depth);
			ring_cursor->indexes->r_index = ri;
			--resp_cnt;
		}
	}
	/* Enable the intrs for this ring */
	*(ring_cursor->intr_ctrl_flag) = 0;
}

int32_t process_rings(fsl_crypto_dev_t *dev,
			 struct list_head *ring_list_head)
{
	fsl_h_rsrc_ring_pair_t *ring_cursor = NULL;

	print_debug("---------------- PROCESSING RESPONSE ------------------\n");

	list_for_each_entry(ring_cursor, ring_list_head, bh_ctx_list_node) {
		process_response(dev, ring_cursor);
	}

#ifndef HIGH_PERF
	/* UPDATE SYSFS ENTRY */
	app_resp_cnt = atomic_read(&dev->app_resp_cnt);
	set_sysfs_value(dev->priv_dev, STATS_RESP_COUNT_SYS_FILE,
			(uint8_t *) &(app_resp_cnt),
			sizeof(app_resp_cnt));
#endif
	print_debug("DONE PROCESSING RESPONSE\n");
	return 0;
}
#endif

/* Backward compatible functions for other algorithms */
static inline void *ip_buf_d_v_addr(fsl_crypto_dev_t *dev, void *h_v_addr)
{
	unsigned long offset = h_v_addr - dev->host_ip_pool.h_v_addr;
	return dev->dev_ip_pool.h_v_addr + offset;
}

struct cmd_ring_entry_desc *get_buffer(fsl_crypto_dev_t *c_dev, void *id,
		uint32_t len, uint8_t flag)
{
	void *addr;

	addr = alloc_buffer(id, len, flag);
	if (addr) {
		addr = ip_buf_d_v_addr(c_dev, addr);
	}

	return addr;
}

void put_buffer(fsl_crypto_dev_t *c_dev, struct buffer_pool *pool, void *addr)
{
	addr += c_dev->host_ip_pool.h_v_addr - c_dev->dev_ip_pool.h_v_addr;
	free_buffer(pool, addr);
}

#ifdef VIRTIO_C2X0
/* For debug purpose */
void print_sess_list()
{
	int cntr_sess = 0;
	struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL, *next_sess = NULL;

	list_for_each_entry_safe(hash_sess, next_sess,
				 &virtio_c2x0_hash_sess_list, list_entry) {
		cntr_sess++;
		printk(KERN_INFO "sessid[%lx], guest_id[%d]\n",
		       hash_sess->sess_id, hash_sess->guest_id);
	}
	printk(KERN_INFO "=================*******************===============\n");
	printk(KERN_INFO "No of hash_sess in list = %d\n", cntr_sess);
	printk(KERN_INFO "=================*******************===============\n");
}

void cleanup_virtio_pkc_buffers(struct pkc_request *req)
{
	if (NULL == req) {
		print_error("Trying to cleanup NULL pkc request\n");
		return;
	}
	switch (req->type) {
	case RSA_PUB:
		{
			if (req->req_u.rsa_pub_req.n)
				kfree(req->req_u.rsa_pub_req.n);
			if (req->req_u.rsa_pub_req.e)
				kfree(req->req_u.rsa_pub_req.e);
			if (req->req_u.rsa_pub_req.f)
				kfree(req->req_u.rsa_pub_req.f);
			if (req->req_u.rsa_pub_req.g)
				kfree(req->req_u.rsa_pub_req.g);
		}
		break;
	case RSA_PRIV_FORM1:
		{
			if (req->req_u.rsa_priv_f1.n)
				kfree(req->req_u.rsa_priv_f1.n);
			if (req->req_u.rsa_priv_f1.d)
				kfree(req->req_u.rsa_priv_f1.d);
			if (req->req_u.rsa_priv_f1.g)
				kfree(req->req_u.rsa_priv_f1.g);
			if (req->req_u.rsa_priv_f1.f)
				kfree(req->req_u.rsa_priv_f1.f);
		}
		break;
	case RSA_PRIV_FORM2:
		{
			if (req->req_u.rsa_priv_f2.p)
				kfree(req->req_u.rsa_priv_f2.p);
			if (req->req_u.rsa_priv_f2.q)
				kfree(req->req_u.rsa_priv_f2.q);
			if (req->req_u.rsa_priv_f2.d)
				kfree(req->req_u.rsa_priv_f2.d);
			if (req->req_u.rsa_priv_f2.g)
				kfree(req->req_u.rsa_priv_f2.g);
			if (req->req_u.rsa_priv_f2.f)
				kfree(req->req_u.rsa_priv_f2.f);
		}
		break;
	case RSA_PRIV_FORM3:
		{
			if (req->req_u.rsa_priv_f3.p)
				kfree(req->req_u.rsa_priv_f3.p);
			if (req->req_u.rsa_priv_f3.q)
				kfree(req->req_u.rsa_priv_f3.q);
			if (req->req_u.rsa_priv_f3.dp)
				kfree(req->req_u.rsa_priv_f3.dp);
			if (req->req_u.rsa_priv_f3.dq)
				kfree(req->req_u.rsa_priv_f3.dq);
			if (req->req_u.rsa_priv_f3.c)
				kfree(req->req_u.rsa_priv_f3.c);
			if (req->req_u.rsa_priv_f3.g)
				kfree(req->req_u.rsa_priv_f3.g);
			if (req->req_u.rsa_priv_f3.f)
				kfree(req->req_u.rsa_priv_f3.f);
		}
		break;
	case DSA_SIGN:
	case ECDSA_SIGN:
		{
			if (req->req_u.dsa_sign.q)
				kfree(req->req_u.dsa_sign.q);
			if (req->req_u.dsa_sign.r)
				kfree(req->req_u.dsa_sign.r);
			if (req->req_u.dsa_sign.g)
				kfree(req->req_u.dsa_sign.g);
			if (req->req_u.dsa_sign.priv_key)
				kfree(req->req_u.dsa_sign.priv_key);
			if (req->req_u.dsa_sign.m)
				kfree(req->req_u.dsa_sign.m);
			if (req->req_u.dsa_sign.c)
				kfree(req->req_u.dsa_sign.c);
			if (req->req_u.dsa_sign.d)
				kfree(req->req_u.dsa_sign.d);
			if (ECDSA_SIGN == req->type)
				if (req->req_u.dsa_sign.ab)
					kfree(req->req_u.dsa_sign.ab);
		}
		break;
	case DSA_VERIFY:
	case ECDSA_VERIFY:
		{
			if (req->req_u.dsa_verify.q)
				kfree(req->req_u.dsa_verify.q);
			if (req->req_u.dsa_verify.r)
				kfree(req->req_u.dsa_verify.r);
			if (req->req_u.dsa_verify.g)
				kfree(req->req_u.dsa_verify.g);
			if (req->req_u.dsa_verify.pub_key)
				kfree(req->req_u.dsa_verify.pub_key);
			if (req->req_u.dsa_verify.m)
				kfree(req->req_u.dsa_verify.m);
			if (req->req_u.dsa_verify.c)
				kfree(req->req_u.dsa_verify.c);
			if (req->req_u.dsa_verify.d)
				kfree(req->req_u.dsa_verify.d);
			if (ECDSA_VERIFY == req->type)
				if (req->req_u.dsa_verify.ab)
					kfree(req->req_u.dsa_verify.ab);
		}
		break;
	case DH_COMPUTE_KEY:
	case ECDH_COMPUTE_KEY:
		{
			if (req->req_u.dh_req.q)
				kfree(req->req_u.dh_req.q);
			if (req->req_u.dh_req.pub_key)
				kfree(req->req_u.dh_req.pub_key);
			if (req->req_u.dh_req.s)
				kfree(req->req_u.dh_req.s);
			if (req->req_u.dh_req.z)
				kfree(req->req_u.dh_req.z);
			if (ECDH_COMPUTE_KEY == req->type)
				if (req->req_u.dh_req.ab)
					kfree(req->req_u.dh_req.ab);
		}
		break;
	default:
		print_error("Invalid pkc_request_type %d\n", req->type);
		return;
	}
}

void process_virtio_job_response(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	switch (virtio_job->qemu_cmd.op) {
	case RSA:
		{
			struct pkc_request *req = virtio_job->ctx->req.pkc;
			struct pkc_request *q_req =
			    &virtio_job->qemu_cmd.u.pkc.pkc_req;

			switch (q_req->type) {
			case RSA_PUB:
				print_debug("RSA_PUB completion\n");

				ret = copy_to_user((void __user *)q_req->
						 req_u.rsa_pub_req.g,
						 (void *)req->req_u.rsa_pub_req.
						 g,
						 req->req_u.rsa_pub_req.g_len);
				if (ret != 0)
					print_debug("return value for RSA PUB of ouput copy_to_user = %d\n", ret);

				cleanup_virtio_pkc_buffers(req);
				break;

			case RSA_PRIV_FORM1:
				print_debug("RSA_FORM1 completion: Output f_len = %d\n",
						req->req_u.rsa_priv_f1.f_len);

				ret = copy_to_user((void __user *)q_req->req_u.
						 rsa_priv_f1.f,
						 (void *)req->req_u.
						 rsa_priv_f1.f,
						 req->req_u.rsa_priv_f1.f_len);

				if (ret != 0)
					print_debug("return value for RSA FORM 1 of ouput copy_to_user = %d\n", ret);

				cleanup_virtio_pkc_buffers(req);
				break;

			case RSA_PRIV_FORM2:
				print_debug("RSA_FORM2 completion : Output f_len = %d\n",
						req->req_u.rsa_priv_f2.f_len);

				ret = copy_to_user((void __user *)q_req->req_u.
						 rsa_priv_f2.f,
						 (void *)req->req_u.
						 rsa_priv_f2.f,
						 req->req_u.rsa_priv_f2.f_len);

				if (ret != 0)
					print_debug("return value for RSA FORM 2 of ouput copy_to_user = %d\n", ret);

				cleanup_virtio_pkc_buffers(req);
				break;

			case RSA_PRIV_FORM3:
				print_debug("RSA_FORM3 completion : Output f_len = %d\n",
						req->req_u.rsa_priv_f3.f_len);

				ret = copy_to_user((void __user *)q_req->req_u.
						 rsa_priv_f3.f,
						 (void *)req->req_u.
						 rsa_priv_f3.f,
						 req->req_u.rsa_priv_f3.f_len);

				if (ret != 0)
					print_debug("return value for RSA FORM 3 of ouput copy_to_user = %d\n", ret);

				cleanup_virtio_pkc_buffers(req);
				break;

			default:
				print_error("OP NOT handled\n");
				break;
			}

			if (req)
				kfree(req);
			break;
		}
	case DSA:{
			struct pkc_request *req = virtio_job->ctx->req.pkc;
			struct pkc_request *q_req =
			    &virtio_job->qemu_cmd.u.pkc.pkc_req;

			switch (q_req->type) {
			case DSA_SIGN:
			case ECDSA_SIGN:{
					print_debug("DSA/ECDSA_SIGN completion\n");
					ret = copy_to_user((void __user *)
							   q_req->
							   req_u.dsa_sign.c,
							   (void *)req->req_u.
							   dsa_sign.c,
							   req->req_u.dsa_sign.
							   d_len);

					if (ret != 0)
						print_debug("ret val DSASIGN c of ouput copy_to_user = %d\n", ret);

					ret = copy_to_user((void __user *)
							   q_req->req_u.
							   dsa_sign.d,
							   (void *)req->req_u.
							   dsa_sign.d,
							   req->req_u.dsa_sign.
							   d_len);

					if (ret != 0)
						print_debug("return value DSA SIGN 'd' of ouput copy_to_user = %d\n", ret);

					cleanup_virtio_pkc_buffers(req);
				}
				break;
			case DSA_VERIFY:
			case ECDSA_VERIFY:
				{
					print_debug("DSA/ECDSA_VERIFY completion\n");
					cleanup_virtio_pkc_buffers(req);
				}
				break;
			default:
				{
					print_error("OP NOT handled\n");
					break;
				}
			}
			if (req)
				kfree(req);
			break;
		}
	case DH:{
			struct pkc_request *req = virtio_job->ctx->req.pkc;
			struct pkc_request *q_req =
			    &virtio_job->qemu_cmd.u.pkc.pkc_req;

			switch (q_req->type) {
			case DH_COMPUTE_KEY:
			case ECDH_COMPUTE_KEY:
				{
					print_debug("DH/ECDH_COMPUTE completion\n");
					ret = copy_to_user((void __user *)
							   q_req->req_u.
							   dh_req.z,
							   (void *)req->req_u.
							   dh_req.z,
							   req->req_u.dh_req.
							   z_len);

					if (ret != 0)
						print_debug("return value DH/ ECDH z ouput copy_to_user = %d\n", ret);

					cleanup_virtio_pkc_buffers(req);
				}
				break;
			default:
				{
					print_error("OP NOT handled\n");
					break;
				}
			}
			if (req)
				kfree(req);
			break;
		}
#ifdef HASH_OFFLOAD
	case AHASH_DIGEST:
		{
			struct scatterlist *sg = NULL;
			uint8_t *buf = NULL;
			int i = 0;

			print_debug("AHASH_DIGEST completion\n");
			ret = copy_to_user((void __user *)
					   virtio_job->qemu_cmd.u.
					   hash.digest_req.result, (void *)
					   (virtio_job->ctx->req.ahash->result),
					   virtio_job->qemu_cmd.u.
					   hash.digest_req.digestsize);
			if (ret != 0)
				print_debug("return val AHASH_DIGEST ouput copy_to_user = %d\n", ret);

			sg = virtio_job->ctx->req.ahash->src;
			for (i = 0; i < virtio_job->qemu_cmd.u.hash.digest_req.sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				kfree(buf);

				sg = sg_next(sg);
				buf = NULL;
			}
			kfree(virtio_job->ctx->req.ahash->src);
			kfree(virtio_job->ctx->req.ahash->result);
			kfree(virtio_job->ctx->req.ahash);

			break;
		}
	case AHASH_UPDATE_CTX:
	case AHASH_UPDATE_NO_CTX:
	case AHASH_UPDATE_FIRST:
		{
			struct hash_state *state = NULL;
			struct scatterlist *sg = NULL;
			uint8_t *buf = NULL;
			int i = 0;

			print_debug("AHASH_UPDATE [%d] completion\n", virtio_job->qemu_cmd.op);

			state = ahash_request_ctx(virtio_job->ctx->req.ahash);
			ret = copy_to_user((void __user *)
					   virtio_job->qemu_cmd.u.
					   hash.update_req.ctx, (uint8_t *)
					   (state->ctx),
					   virtio_job->qemu_cmd.u.
					   hash.update_req.ctxlen);
			if (ret != 0)
				print_debug("return value AHASH_UPDATE ouput copy_to_user = %d\n", ret);

			sg = virtio_job->ctx->req.ahash->src;
			for (i = 0; i < virtio_job->qemu_cmd.u.hash.update_req.sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				kfree(buf);

				sg = sg_next(sg);
				buf = NULL;
			}
			kfree(virtio_job->ctx->req.ahash->src);
			kfree(virtio_job->ctx->req.ahash);
			break;
		}
	case AHASH_FINAL_CTX:
	case AHASH_FINAL_NO_CTX:
		{
			print_debug("AHASH_FINAL[%d] completion\n", virtio_job->qemu_cmd.op);

			ret = copy_to_user((void __user *)
					   virtio_job->qemu_cmd.u.
					   hash.final_req.result, (void *)
					   (virtio_job->ctx->req.ahash->result),
					   virtio_job->qemu_cmd.u.
					   hash.final_req.digestsize);
			if (ret != 0)
				print_debug("return value AHASH_FINAL ouput copy_to_user = %d\n", ret);

			kfree(virtio_job->ctx->req.ahash->result);
			kfree(virtio_job->ctx->req.ahash);
			break;
		}
	case AHASH_FINUP_CTX:
	case AHASH_FINUP_NO_CTX:
		{
			struct scatterlist *sg = NULL;
			uint8_t *buf = NULL;
			int i = 0;

			print_debug("AHASH_FINUP[%d] completion\n", virtio_job->qemu_cmd.op);

			ret = copy_to_user((void __user *)
					   virtio_job->qemu_cmd.u.
					   hash.finup_req.result, (void *)
					   (virtio_job->ctx->req.ahash->result),
					   virtio_job->qemu_cmd.u.
					   hash.finup_req.digestsize);
			if (ret != 0)
				print_debug("return value AHASH_FINUP ouput copy_to_user = %d\n", ret);

			sg = virtio_job->ctx->req.ahash->src;
			for (i = 0; i < virtio_job->qemu_cmd.u.hash.finup_req.sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				kfree(buf);

				sg = sg_next(sg);
				buf = NULL;
			}
			kfree(virtio_job->ctx->req.ahash->src);
			kfree(virtio_job->ctx->req.ahash->result);
			kfree(virtio_job->ctx->req.ahash);

			break;
		}
#endif
#ifdef SYMMETRIC_OFFLOAD
	case ABLK_ENCRYPT:
	case ABLK_DECRYPT:
		{
			struct scatterlist *sg = NULL;
			uint8_t *buf = NULL;
			int i = 0;

			print_debug("ABLK [%d] completion\n", virtio_job->qemu_cmd.op);

			sg = virtio_job->ctx->req.ablk->dst;
			for (i = 0; i < virtio_job->qemu_cmd.u.symm.cmd_req.dst_sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				ret = copy_to_user((void __user *)
						   virtio_job->qemu_cmd.u.
						   symm.cmd_req.dst[i], (void *)
						   buf,
						   virtio_job->qemu_cmd.u.
						   symm.cmd_req.dst_len[i]);
				if (ret != 0)
					print_debug("return value ABLK[%d] ouput copy_to_user = %d\n",
							virtio_job->qemu_cmd.op, ret);

				sg = sg_next(sg);
				kfree(buf);
				buf = NULL;
			}

			sg = virtio_job->ctx->req.ablk->src;
			for (i = 0; i < virtio_job->qemu_cmd.u.symm.cmd_req.src_sg_info.sg_count; i++) {
				buf = sg_virt(sg);
				kfree(buf);

				sg = sg_next(sg);
				buf = NULL;
			}

			kfree(virtio_job->qemu_cmd.u.symm.cmd_req.dst);
			kfree(virtio_job->qemu_cmd.u.symm.cmd_req.dst_len);
			kfree(virtio_job->qemu_cmd.u.symm.cmd_req.src);
			kfree(virtio_job->qemu_cmd.u.symm.cmd_req.src_len);
			kfree(virtio_job->ctx->req.ablk->src);
			kfree(virtio_job->ctx->req.ablk->dst);
			kfree(virtio_job->ctx->req.ablk->info);
			kfree(virtio_job->ctx->req.ablk);

			print_debug("ABLK [%d] completion Success\n", virtio_job->qemu_cmd.op);

			break;
		}
#endif

	default:
		{
			print_error("Unknow OP\n");
			break;
		}

	}
}


/*******************************************************************************
* Function     : process_virtio_dh_job
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Copying dh job request data from user space to kernel space and
*                processes the dh job for virtio
*
*******************************************************************************/

int32_t process_virtio_dh_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	struct pkc_request *req = NULL;
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	req =
	    (struct pkc_request *)kzalloc(sizeof(struct pkc_request),
					  GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p, qemu_cmd:%p\n", req, qemu_cmd);
		return -1;
	}

	req->type = qemu_cmd->u.pkc.pkc_req.type;
	req->curve_type = qemu_cmd->u.pkc.pkc_req.curve_type;
	print_debug("req->tye = %d\n", req->type);

	switch (req->type) {
	case DH_COMPUTE_KEY:
	case ECDH_COMPUTE_KEY:
		print_debug("DH COMPUTE_KEY\n");

		req->req_u.dh_req.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.q_len;
#ifdef SEC_DMA
                req->req_u.dh_req.q = kzalloc(req->req_u.dh_req.q_len,
                                              GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dh_req.q =
		    kzalloc(req->req_u.dh_req.q_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dh_req.q) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dh_req.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.dh_req.q,
				   req->req_u.dh_req.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dh_req.pub_key_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.pub_key_len;
#ifdef SEC_DMA
                req->req_u.dh_req.pub_key
                = kzalloc(req->req_u.dh_req.pub_key_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dh_req.pub_key =
		    kzalloc(req->req_u.dh_req.pub_key_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dh_req.pub_key) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dh_req.pub_key,
				   qemu_cmd->u.pkc.pkc_req.req_u.dh_req.pub_key,
				   req->req_u.dh_req.pub_key_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dh_req.s_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.s_len;
#ifdef SEC_DMA
                req->req_u.dh_req.s = kzalloc(req->req_u.dh_req.s_len,
                                              GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dh_req.s =
		    kzalloc(req->req_u.dh_req.s_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dh_req.s) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dh_req.s,
				   qemu_cmd->u.pkc.pkc_req.req_u.dh_req.s,
				   req->req_u.dh_req.s_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		if (ECDH_COMPUTE_KEY == req->type) {
			req->req_u.dh_req.ab_len =
			    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.ab_len;
#ifdef SEC_DMA
                        req->req_u.dh_req.ab = kzalloc(req->req_u.dh_req.ab_len,
                                                       GFP_KERNEL | GFP_DMA);
#else
			req->req_u.dh_req.ab =
			    kzalloc(req->req_u.dh_req.ab_len, GFP_KERNEL);
#endif
			if (NULL == req->req_u.dh_req.ab) {
				print_error("kzalloc failed\n");
				goto error;
			}
			ret =
			    copy_from_user(req->req_u.dh_req.ab,
					   qemu_cmd->u.pkc.pkc_req.req_u.dh_req.
					   ab, req->req_u.dh_req.ab_len);
			if (ret != 0) {
				print_error("Copy from user failed  = %d\n",
					    ret);
				goto error;
			}
		}

		req->req_u.dh_req.z_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dh_req.z_len;
		req->req_u.dh_req.z =
		    kzalloc(req->req_u.dh_req.z_len, GFP_KERNEL);
		if (NULL == req->req_u.dh_req.z) {
			print_error("kzalloc failed\n");
			goto error;
		}

		break;

	default:
		print_error
		    ("OP[%d];subop[%d:%d];"
			 "cmd_index[%d];guest_id[%d]"
			 "NOT handled\n",
		     qemu_cmd->op, qemu_cmd->u.pkc.pkc_req.type,
			 req->type,
		     qemu_cmd->cmd_index, qemu_cmd->guest_id);
		goto error_op;
	}

	ret = dh_op(req, virtio_job);
	if (-1 == ret) {
		print_error("failed to send DH[%d] job with %d ret\n",
			    req->type, ret);
		goto error;
	}

	return 0;

error:
	cleanup_virtio_pkc_buffers(req);
error_op:
	kfree(req);
	return -1;
}

/*******************************************************************************
* Function     : process_virtio_dsa_job
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Coping dsa job request data from user space to kernel space and
*                processes the dsa job for virtio
*
*******************************************************************************/
int32_t process_virtio_dsa_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	struct pkc_request *req = NULL;
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	req =
	    (struct pkc_request *)kzalloc(sizeof(struct pkc_request),
					  GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p, qemu_cmd:%p\n", req,
			    qemu_cmd);
		return -1;
	}

	req->type = qemu_cmd->u.pkc.pkc_req.type;
	req->curve_type = qemu_cmd->u.pkc.pkc_req.curve_type;
	print_debug("req->tye = %d\n", req->type);

	switch (req->type) {
	case DSA_SIGN:
	case ECDSA_SIGN:
		print_debug("DSA/ECDSA_SIGN\n");

		req->req_u.dsa_sign.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.q_len;
#ifdef SEC_DMA
		req->req_u.dsa_sign.q = kzalloc(req->req_u.dsa_sign.q_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_sign.q =
		    kzalloc(req->req_u.dsa_sign.q_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_sign.q) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.q,
				   req->req_u.dsa_sign.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_sign.r_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.r_len;
#ifdef SEC_DMA
		req->req_u.dsa_sign.r = kzalloc(req->req_u.dsa_sign.r_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_sign.r =
		    kzalloc(req->req_u.dsa_sign.r_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_sign.r) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.r,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.r,
				   req->req_u.dsa_sign.r_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_sign.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.g_len;
#ifdef SEC_DMA
		req->req_u.dsa_sign.g = kzalloc(req->req_u.dsa_sign.g_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_sign.g =
		    kzalloc(req->req_u.dsa_sign.g_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_sign.g) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.g,
				   req->req_u.dsa_sign.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_sign.priv_key_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.priv_key_len;
#ifdef SEC_DMA
		req->req_u.dsa_sign.priv_key = kzalloc(req->req_u.dsa_sign.priv_key_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_sign.priv_key =
		    kzalloc(req->req_u.dsa_sign.priv_key_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_sign.priv_key) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.priv_key,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.
				   priv_key, req->req_u.dsa_sign.priv_key_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_sign.m_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.m_len;
#ifdef SEC_DMA
		req->req_u.dsa_sign.m = kzalloc(req->req_u.dsa_sign.m_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_sign.m =
		    kzalloc(req->req_u.dsa_sign.m_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_sign.m) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_sign.m,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.m,
				   req->req_u.dsa_sign.m_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		if (ECDSA_SIGN == req->type) {
			req->req_u.dsa_sign.ab_len =
			    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.ab_len;
#ifdef SEC_DMA
			req->req_u.dsa_sign.ab
                        = kzalloc(req->req_u.dsa_sign.ab_len, GFP_KERNEL | GFP_DMA);
#else
			req->req_u.dsa_sign.ab =
			    kzalloc(req->req_u.dsa_sign.ab_len, GFP_KERNEL);
#endif
			if (NULL == req->req_u.dsa_sign.ab) {
				print_error("kzalloc failed\n");
				goto error;
			}
			ret =
			    copy_from_user(req->req_u.dsa_sign.ab,
					   qemu_cmd->u.pkc.pkc_req.req_u.
					   dsa_sign.ab,
					   req->req_u.dsa_sign.ab_len);
			if (ret != 0) {
				print_error("Copy from user failed  = %d\n",
					    ret);
				goto error;
			}
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.dsa_sign.d_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_sign.d_len;
		req->req_u.dsa_sign.c =
		    kzalloc(req->req_u.dsa_sign.d_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_sign.c) {
			print_error("kzalloc failed\n");
			goto error;
		}
		req->req_u.dsa_sign.d =
		    kzalloc(req->req_u.dsa_sign.d_len, GFP_KERNEL);
		if (NULL == req->req_u.dsa_sign.d) {
			print_error("kzalloc failed\n");
			goto error;
		}

		break;

	case DSA_VERIFY:
	case ECDSA_VERIFY:
		print_debug("DSA/ECDSA_VERIFY\n");

		req->req_u.dsa_verify.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.q_len;
#ifdef SEC_DMA
		req->req_u.dsa_verify.q = kzalloc(req->req_u.dsa_verify.q_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_verify.q =
		    kzalloc(req->req_u.dsa_verify.q_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_verify.q) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.q,
				   req->req_u.dsa_verify.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.r_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.r_len;
#ifdef SEC_DMA
		req->req_u.dsa_verify.r = kzalloc(req->req_u.dsa_verify.r_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_verify.r =
		    kzalloc(req->req_u.dsa_verify.r_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_verify.r) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.r,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.r,
				   req->req_u.dsa_verify.r_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.g_len;
#ifdef SEC_DMA
		req->req_u.dsa_verify.g = kzalloc(req->req_u.dsa_verify.g_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_verify.g =
		    kzalloc(req->req_u.dsa_verify.g_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_verify.g) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.g,
				   req->req_u.dsa_verify.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.pub_key_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.pub_key_len;
#ifdef SEC_DMA
		req->req_u.dsa_verify.pub_key = kzalloc(req->req_u.dsa_verify.pub_key_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_verify.pub_key =
		    kzalloc(req->req_u.dsa_verify.pub_key_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_verify.pub_key) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.pub_key,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.
				   pub_key, req->req_u.dsa_verify.pub_key_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.m_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.m_len;
#ifdef SEC_DMA
		req->req_u.dsa_verify.m = kzalloc(req->req_u.dsa_verify.m_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_verify.m =
		    kzalloc(req->req_u.dsa_verify.m_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_verify.m) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.m,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.m,
				   req->req_u.dsa_verify.m_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		if (ECDSA_VERIFY == req->type) {
			req->req_u.dsa_verify.ab_len =
			    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.ab_len;
#ifdef SEC_DMA
			req->req_u.dsa_verify.ab = kzalloc(req->req_u.dsa_verify.ab_len, GFP_KERNEL | GFP_DMA);
#else
			req->req_u.dsa_verify.ab =
			    kzalloc(req->req_u.dsa_verify.ab_len, GFP_KERNEL);
#endif
			if (NULL == req->req_u.dsa_verify.ab) {
				print_error("kzalloc failed\n");
				goto error;
			}
			ret =
			    copy_from_user(req->req_u.dsa_verify.ab,
					   qemu_cmd->u.pkc.pkc_req.req_u.
					   dsa_verify.ab,
					   req->req_u.dsa_verify.ab_len);
			if (ret != 0) {
				print_error("Copy from user failed  = %d\n",
					    ret);
				goto error;
			}
		}

#ifdef SEC_DMA
		req->req_u.dsa_verify.c = kzalloc(req->req_u.dsa_verify.q_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_verify.c =
		    kzalloc(req->req_u.dsa_verify.q_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_verify.c) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.c,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.c,
				   req->req_u.dsa_verify.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.dsa_verify.d_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.d_len;
#ifdef SEC_DMA
		req->req_u.dsa_verify.d = kzalloc(req->req_u.dsa_verify.d_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.dsa_verify.d =
		    kzalloc(req->req_u.dsa_verify.d_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.dsa_verify.d) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.dsa_verify.d,
				   qemu_cmd->u.pkc.pkc_req.req_u.dsa_verify.d,
				   req->req_u.dsa_verify.d_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		break;
	default:
		{
			print_error
			    ("OP[%d];subop[%d:%d];"
				 "cmd_index[%d];guest_id[%d] NOT handled\n",
			     qemu_cmd->op, qemu_cmd->u.pkc.pkc_req.type,
			     req->type, qemu_cmd->cmd_index,
			     qemu_cmd->guest_id);
			goto error_op;
		}
	}

	ret = dsa_op(req, virtio_job);
	if (-1 == ret) {
		print_error("failed to send DSA[%d] job with %d ret\n",
			    req->type, ret);
		goto error;
	}

	return 0;

error:
	cleanup_virtio_pkc_buffers(req);
error_op:
	kfree(req);
	return -1;
}

/*******************************************************************************
* Function     : process_virtio_rsa_job
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Coping rsa job request data from user space to kernel space and
*                processes the rsa job for virtio
*
*******************************************************************************/
int32_t process_virtio_rsa_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	struct pkc_request *req = NULL;
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	req =
	    (struct pkc_request *)kzalloc(sizeof(struct pkc_request),
					  GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p, qemu_cmd:%p\n", req,
			    qemu_cmd);
		return -1;
	}

	req->type = qemu_cmd->u.pkc.pkc_req.type;
	req->curve_type = qemu_cmd->u.pkc.pkc_req.curve_type;
	print_debug("req->tye = %d\n", req->type);

	switch (req->type) {
	case RSA_PUB:
		print_debug("RSA_PUB\n");

		req->req_u.rsa_pub_req.n_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.n_len;
#ifdef SEC_DMA
		req->req_u.rsa_pub_req.n = kzalloc(req->req_u.rsa_pub_req.n_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.rsa_pub_req.n =
		    kzalloc(req->req_u.rsa_pub_req.n_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.rsa_pub_req.n) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_pub_req.n,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.n,
				   req->req_u.rsa_pub_req.n_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_pub_req.e_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.e_len;
#ifdef SEC_DMA
		req->req_u.rsa_pub_req.e = kzalloc(req->req_u.rsa_pub_req.e_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.rsa_pub_req.e =
		    kzalloc(req->req_u.rsa_pub_req.e_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.rsa_pub_req.e) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_pub_req.e,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.e,
				   req->req_u.rsa_pub_req.e_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_pub_req.f_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.f_len;
#ifdef SEC_DMA
		req->req_u.rsa_pub_req.f = kzalloc(req->req_u.rsa_pub_req.f_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.rsa_pub_req.f =
		    kzalloc(req->req_u.rsa_pub_req.f_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.rsa_pub_req.f) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_pub_req.f,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.f,
				   req->req_u.rsa_pub_req.f_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.rsa_pub_req.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_pub_req.n_len;
		req->req_u.rsa_pub_req.g =
		    kzalloc(req->req_u.rsa_pub_req.g_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_pub_req.g) {
			print_error("kzalloc failed\n");
			goto error;
		}

		break;
	case RSA_PRIV_FORM1:

		print_debug("RSA_PRIV_FORM1\n");

		req->req_u.rsa_priv_f1.n_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.n_len;
		req->req_u.rsa_priv_f1.n =
		    kzalloc(req->req_u.rsa_priv_f1.n_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f1.n) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f1.n,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.n,
				   req->req_u.rsa_priv_f1.n_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f1.d_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.d_len;
		req->req_u.rsa_priv_f1.d =
		    kzalloc(req->req_u.rsa_priv_f1.d_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f1.d) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f1.d,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.d,
				   req->req_u.rsa_priv_f1.d_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.rsa_priv_f1.f_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.n_len;
		req->req_u.rsa_priv_f1.f =
		    kzalloc(req->req_u.rsa_priv_f1.f_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f1.f) {
			print_error("kzalloc failed\n");
			goto error;
		}

		req->req_u.rsa_priv_f1.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.g_len;
		req->req_u.rsa_priv_f1.g =
		    kzalloc(req->req_u.rsa_priv_f1.g_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f1.g) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f1.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f1.g,
				   req->req_u.rsa_priv_f1.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		break;

	case RSA_PRIV_FORM2:
		print_debug("RSA_PRIV_FORM2\n");

		req->req_u.rsa_priv_f2.p_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.p_len;
		req->req_u.rsa_priv_f2.p =
		    kzalloc(req->req_u.rsa_priv_f2.p_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.p) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f2.p,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.p,
				   req->req_u.rsa_priv_f2.p_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f2.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.q_len;
		req->req_u.rsa_priv_f2.q =
		    kzalloc(req->req_u.rsa_priv_f2.q_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.q) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f2.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.q,
				   req->req_u.rsa_priv_f2.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f2.d_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.d_len;
		req->req_u.rsa_priv_f2.d =
		    kzalloc(req->req_u.rsa_priv_f2.d_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.d) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f2.d,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.d,
				   req->req_u.rsa_priv_f2.d_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f2.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.g_len;
		req->req_u.rsa_priv_f2.g =
		    kzalloc(req->req_u.rsa_priv_f2.g_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.g) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f2.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.g,
				   req->req_u.rsa_priv_f2.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.rsa_priv_f2.f_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.n_len;
		req->req_u.rsa_priv_f2.f =
		    kzalloc(req->req_u.rsa_priv_f2.f_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f2.f) {
			print_error("kzalloc failed\n");
			goto error;
		}

		req->req_u.rsa_priv_f2.n_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f2.n_len;

		break;

	case RSA_PRIV_FORM3:
		print_debug("RSA_PRIV_FORM3\n");

		req->req_u.rsa_priv_f3.p_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.p_len;
#ifdef SEC_DMA
		req->req_u.rsa_priv_f3.p = kzalloc(req->req_u.rsa_priv_f3.p_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.rsa_priv_f3.p =
		    kzalloc(req->req_u.rsa_priv_f3.p_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.rsa_priv_f3.p) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.p,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.p,
				   req->req_u.rsa_priv_f3.p_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.q_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.q_len;
#ifdef SEC_DMA
		req->req_u.rsa_priv_f3.q = kzalloc(req->req_u.rsa_priv_f3.q_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.rsa_priv_f3.q =
		    kzalloc(req->req_u.rsa_priv_f3.q_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.rsa_priv_f3.q) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.q,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.q,
				   req->req_u.rsa_priv_f3.q_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.dp_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.dp_len;
#ifdef SEC_DMA
		req->req_u.rsa_priv_f3.dp = kzalloc(req->req_u.rsa_priv_f3.dp_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.rsa_priv_f3.dp =
		    kzalloc(req->req_u.rsa_priv_f3.dp_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.rsa_priv_f3.dp) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.dp,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.dp,
				   req->req_u.rsa_priv_f3.dp_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.dq_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.dq_len;
#ifdef SEC_DMA
		req->req_u.rsa_priv_f3.dq = kzalloc(req->req_u.rsa_priv_f3.dq_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.rsa_priv_f3.dq =
		    kzalloc(req->req_u.rsa_priv_f3.dq_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.rsa_priv_f3.dq) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.dq,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.dq,
				   req->req_u.rsa_priv_f3.dq_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.c_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.c_len;
#ifdef SEC_DMA
		req->req_u.rsa_priv_f3.c = kzalloc(req->req_u.rsa_priv_f3.c_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.rsa_priv_f3.c =
		    kzalloc(req->req_u.rsa_priv_f3.c_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.rsa_priv_f3.c) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.c,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.c,
				   req->req_u.rsa_priv_f3.c_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		req->req_u.rsa_priv_f3.g_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.g_len;
#ifdef SEC_DMA
		req->req_u.rsa_priv_f3.g = kzalloc(req->req_u.rsa_priv_f3.g_len, GFP_KERNEL | GFP_DMA);
#else
		req->req_u.rsa_priv_f3.g =
		    kzalloc(req->req_u.rsa_priv_f3.g_len, GFP_KERNEL);
#endif
		if (NULL == req->req_u.rsa_priv_f3.g) {
			print_error("kzalloc failed\n");
			goto error;
		}
		ret =
		    copy_from_user(req->req_u.rsa_priv_f3.g,
				   qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.g,
				   req->req_u.rsa_priv_f3.g_len);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto error;
		}

		/*  Allocating memory for o/p buffer  */
		req->req_u.rsa_priv_f3.f_len =
		    qemu_cmd->u.pkc.pkc_req.req_u.rsa_priv_f3.f_len;
		req->req_u.rsa_priv_f3.f =
		    kzalloc(req->req_u.rsa_priv_f3.f_len, GFP_KERNEL);
		if (NULL == req->req_u.rsa_priv_f3.f) {
			print_error("kzalloc failed\n");
			goto error;
		}

		break;
	default:
		print_error("OP[%d]; subop[%d:%d]; cmd_index[%d]; guest_id[%d] NOT handled\n",
		     qemu_cmd->op, qemu_cmd->u.pkc.pkc_req.type, req->type,
		     qemu_cmd->cmd_index, qemu_cmd->guest_id);
		goto error_op;
	}

	ret = rsa_op(req, virtio_job);
	if (-1 == ret) {
		print_error("failed to send RSA[%d] job with %d ret\n",
			    req->type, ret);
		goto error;
	}

	return 0;

error:
	cleanup_virtio_pkc_buffers(req);
error_op:
	kfree(req);
	return -1;
}

#ifdef HASH_OFFLOAD
int32_t process_virtio_hash_split_key_job(struct virtio_c2x0_job_ctx *
					  virtio_job)
{
	int32_t status = 0;
	int32_t ret = 0;
	uint8_t *key = NULL, *key_bkp = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	key =
	    (uint8_t *) kzalloc((qemu_cmd->u.hash).setkey_req.keylen,
				GFP_KERNEL);
	if (!key) {
		print_error("Alloc failed setkey_req: %p, qemu_cmd: %p\n",
			    key, qemu_cmd);
		return -1;
	}

	ret = copy_from_user(key, &(qemu_cmd->u.hash).setkey_req.key,
			     (qemu_cmd->u.hash).setkey_req.keylen);
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		kfree(key);
		return -1;
	}
	key_bkp = key;

	status = ahash_setkey(key, qemu_cmd);
	/*
	 * TODO :  ???
	 * How to send the status back
	 * Whether to send 0/-1 or to send whatever status returned by card
	 *
	 * Problem because returnj values other than 0/-1 NOT reflected in Host
	 * Soln -> Copy return value in qemu_cmd->host_status
	 * and send 0/-1 as ioctl return
	 */
	ret = copy_to_user(qemu_cmd->host_status, &status, sizeof(int32_t));
	if (ret > 0)
		print_error("Copy to user for status failed\n");

	kfree(key_bkp);
	if (status < 0)
		ret = -1;
	else
		ret = 0;
	return ret;
}

int32_t process_virtio_ahash_digest_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ahash_request *req = NULL;
	struct scatterlist *sg = NULL;
	uint8_t *buf = NULL;
	uint32_t buflen;
	uint8_t **src = NULL;
	uint32_t *src_len = NULL;
	int i = 0, max_filled_sgs = 0;

	if (0 == qemu_cmd->u.hash.digest_req.sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; sg_count = %d;nbytes = %d;\n",
				 __func__,
		       qemu_cmd->u.hash.digest_req.sg_info.sg_count,
		       qemu_cmd->u.hash.digest_req.sg_info.nbytes);
	}

	/*
	 * Allocating memory for scatterlist in ahash_request
	 */
	sg = kzalloc(sizeof(struct scatterlist) *
		     qemu_cmd->u.hash.digest_req.sg_info.sg_count, GFP_KERNEL);
#if 0
	if (!sg) {
		print_error("scatter gather memory allocation failed\n");
		return -1;
	}
#else
	if (unlikely(ZERO_OR_NULL_PTR(sg))) {
		print_error("sg[%p] is ZERO_SIZE_PTR\n", sg);
		kfree(sg);
		return -1;
	}
#endif

	/* VM's virtual addresses of each sg entry */
	src = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.hash.digest_req.sg_info.sg_count,
				   GFP_KERNEL);
	if (!src) {
		print_error("src alloc failed\n");
		goto failed_src;
	}
	ret = copy_from_user(src, qemu_cmd->u.hash.digest_req.src,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.hash.digest_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("src Copy from user failed  = %d\n", ret);
		goto failed_copy_src;
	}

	src_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.hash.digest_req.sg_info.
				       sg_count, GFP_KERNEL);
	if (!src_len) {
		print_error("srclen alloc failed\n");
		goto failed_srclen;
	}
	ret = copy_from_user(src_len, qemu_cmd->u.hash.digest_req.src_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.hash.digest_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("srclen Copy from user failed  = %d\n", ret);
		goto failed_copy_srclen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.hash.digest_req.sg_info.sg_count; i++) {
		buflen = src_len[i];
		buf = kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("buf alloc failed\n");
			goto failed_buf;
		}
		max_filled_sgs++;
		ret = copy_from_user(buf, src[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf;
		}
		sg_set_buf(&sg[i], (void *)buf, buflen);
	}

	/*
	 * Creating ahahs_request
	 */
	req =
	    (struct ahash_request *)kzalloc(sizeof(struct ahash_request),
					    GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req: %p,\n", req);
		goto failed_req;
	}

	req->nbytes = qemu_cmd->u.hash.digest_req.sg_info.nbytes;
	req->src = sg;

	req->result =
	    kzalloc(qemu_cmd->u.hash.digest_req.digestsize, GFP_KERNEL);
	if (!req->result) {
		print_error("result memory allocation failed\n");
		goto failed_result;
	}

	ret = ahash_digest(req, virtio_job);
	kfree(src_len);
	kfree(src);
	src = NULL;
	src_len = NULL;

	if (-1 != ret) {
		print_debug("AHASH_DIGEST[%d] job succesfully given to card: %d\n",
		     qemu_cmd->op, ret);
		return 0;
	}

	print_error("AHASH_DIGEST[%d] returns: %d\n", qemu_cmd->op, ret);

	kfree(req->result);
failed_result:
	kfree(req);
failed_req:
failed_buf:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_sgs; i++) {
			buf = sg_virt(&sg[i]);
			kfree(buf);
		}
	}
failed_copy_srclen:
	if (src_len)
		kfree(src_len);
failed_srclen:
failed_copy_src:
	if (src)
		kfree(src);
failed_src:
	kfree(sg);
	return -1;

}

int32_t process_virtio_ahash_update_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ahash_request *req = NULL;
	struct scatterlist *sg = NULL;
	struct hash_state *state = NULL;
	uint8_t *buf = NULL;
	uint32_t buflen;
	uint8_t **src = NULL;
	uint32_t *src_len = NULL;
	int i = 0, max_filled_sgs = 0;

	if (0 == qemu_cmd->u.hash.update_req.sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; sg_count = %d;nbytes = %d;\n",
				__func__,
			qemu_cmd->u.hash.update_req.sg_info.sg_count,
			qemu_cmd->u.hash.update_req.sg_info.nbytes);
	}

	/*
	 * Allocating memory for scatterlist in ahash_request
	 */
	sg = kzalloc(sizeof(struct scatterlist) *
		     qemu_cmd->u.hash.update_req.sg_info.sg_count, GFP_KERNEL);
#if 0
	if (!sg) {
		print_error("scatter gather memory allocation failed\n");
		return -1;
	}
#else
	if (unlikely(ZERO_OR_NULL_PTR(sg))) {
		print_error("sg[%p] is ZERO_SIZE_PTR\n", sg);
		kfree(sg);
		return -1;
	}
#endif

	/* VM's virtual addresses of each sg entry */
	src = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.hash.update_req.sg_info.sg_count,
				   GFP_KERNEL);
	if (!src) {
		print_error("src alloc failed\n");
		goto failed_src;
	}
	ret = copy_from_user(src, qemu_cmd->u.hash.update_req.src,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.hash.update_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_src;
	}

	src_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.hash.update_req.sg_info.
				       sg_count, GFP_KERNEL);
	if (!src_len) {
		print_error("src_len alloc failed\n");
		goto failed_srclen;
	}
	ret = copy_from_user(src_len, qemu_cmd->u.hash.update_req.src_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.hash.update_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_srclen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.hash.update_req.sg_info.sg_count; i++) {
		buflen = src_len[i];
		print_debug("sg[%d] len = %u\n", i, buflen);
		buf = kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("buf alloc failed\n");
			goto failed_buf;
		}
		max_filled_sgs++;
		ret = copy_from_user(buf, src[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_copy_buf;
		}

		sg_set_buf(&sg[i], (void *)buf, buflen);
		buf = NULL;
	}
	sg_mark_end(&sg[i - 1]);	/* TODO : Is it necessary ?? */

	/*
	 * Creating ahash_request
	 */
	req = (struct ahash_request *)kzalloc(sizeof(struct ahash_request) +
					    sizeof(struct hash_state),
					    GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p,\n", req);
		goto failed_req;
	}
	state = ahash_request_ctx(req);

	req->nbytes = qemu_cmd->u.hash.update_req.sg_info.nbytes;
	req->src = sg;
	ret = copy_from_user(state, qemu_cmd->u.hash.update_req.state,
			     sizeof(struct hash_state));
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_state;
		return -1;
	}

	/*
	 * Need to free up this locally state later
	 * Later, this state's ctx is copied as output to userspace
	 */
	if (AHASH_UPDATE_CTX == qemu_cmd->op)
		ret = ahash_update_ctx(req, virtio_job);
	else if (AHASH_UPDATE_NO_CTX == qemu_cmd->op)
		ret = ahash_update_no_ctx(req, virtio_job);
	else if (AHASH_UPDATE_FIRST == qemu_cmd->op)
		ret = ahash_update_first(req, virtio_job);

	kfree(src_len);
	kfree(src);
	src = NULL;
	src_len = NULL;

	if (-1 != ret) {
		print_debug("AHASH_UPDATE[%d] job succesfully given to card : %d\n",
				qemu_cmd->op, ret);
		return 0;
	}
	print_error("AHASH_UPDATE[%d] returns: %d\n", qemu_cmd->op, ret);

failed_copy_state:
	kfree(req);
failed_req:
failed_copy_buf:
failed_buf:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_sgs; i++) {
			buf = sg_virt(&sg[i]);
			kfree(buf);
		}
	}
failed_copy_srclen:
	if (src_len)
		kfree(src_len);
failed_srclen:
failed_copy_src:
	if (src)
		kfree(src);
failed_src:
	kfree(sg);
	return -1;
}

int32_t process_virtio_ahash_final_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ahash_request *req = NULL;
	struct hash_state *state = NULL;

	/*
	 * Creating ahash_request
	 */
	req =
	    (struct ahash_request *)kzalloc(sizeof(struct ahash_request) +
					    sizeof(struct hash_state),
					    GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p,\n", req);
		return -1;
	}

	state = ahash_request_ctx(req);
	ret = copy_from_user(state, qemu_cmd->u.hash.final_req.state,
			     sizeof(struct hash_state));
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_state;
	}

	req->result =
	    kzalloc(qemu_cmd->u.hash.final_req.digestsize, GFP_KERNEL);
	if (!req->result) {
		print_error("result memory allocation failed\n");
		goto failed_copy_state;
	}

	if (AHASH_FINAL_CTX == qemu_cmd->op)
		ret = ahash_final_ctx(req, virtio_job);
	else if (AHASH_FINAL_NO_CTX == qemu_cmd->op)
		ret = ahash_final_no_ctx(req, virtio_job);

	if (-1 != ret) {
		print_debug("AHASH_FINAL[%d] job succesfully given to card: %d\n",
		     qemu_cmd->op, ret);
		return 0;
	}
	print_error("AHASH_FINAL[%d] returns: %d\n", qemu_cmd->op, ret);

	kfree(req->result);
failed_copy_state:
	kfree(req);
	return -1;
}

int32_t process_virtio_ahash_finup_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ahash_request *req = NULL;
	struct hash_state *state = NULL;
	struct scatterlist *sg = NULL;
	uint8_t *buf = NULL;
	uint32_t buflen;
	uint8_t **src = NULL;
	uint32_t *src_len = NULL;
	int i = 0, max_filled_sgs = 0;

	if (0 == qemu_cmd->u.hash.finup_req.sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; sg_count = %d;nbytes = %d;\n",
				__func__,
		       qemu_cmd->u.hash.finup_req.sg_info.sg_count,
		       qemu_cmd->u.hash.finup_req.sg_info.nbytes);
	}

	/*
	 * Allocating memory for scatterlist in ahash_request
	 */
	sg = kzalloc(sizeof(struct scatterlist) *
		     qemu_cmd->u.hash.finup_req.sg_info.sg_count, GFP_KERNEL);
#if 0
	if (!sg) {
		print_error("scatter gather memory allocation failed\n");
		return -1;
	}
#else
	if (unlikely(ZERO_OR_NULL_PTR(sg))) {
		print_error("sg[%p] is ZERO_SIZE_PTR\n", sg);
		kfree(sg);
		return -1;
	}
#endif

	/* VM's virtual addresses of each sg entry */
	src = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.hash.finup_req.sg_info.sg_count,
				   GFP_KERNEL);
	if (!src) {
		print_error("src alloc failed\n");
		goto failed_src;
	}
	ret = copy_from_user(src, qemu_cmd->u.hash.finup_req.src,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.hash.finup_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("src Copy from user failed  = %d\n", ret);
		goto failed_copy_src;
	}

	src_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.hash.finup_req.sg_info.
				       sg_count, GFP_KERNEL);
	if (!src_len) {
		print_error("srclen alloc failed\n");
		goto failed_srclen;
	}
	ret = copy_from_user(src_len, qemu_cmd->u.hash.finup_req.src_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.hash.finup_req.sg_info.sg_count);
	if (ret != 0) {
		print_error("srclen Copy from user failed  = %d\n", ret);
		goto failed_copy_srclen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.hash.finup_req.sg_info.sg_count; i++) {
		buflen = src_len[i];
		buf = kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("buf alloc failed\n");
			goto failed_buf;
		}
		max_filled_sgs++;
		ret = copy_from_user(buf, src[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf;
		}
		sg_set_buf(&sg[i], (void *)buf, buflen);
	}

	/*
	 * Creating ahahs_request
	 */
	req =
	    (struct ahash_request *)kzalloc(sizeof(struct ahash_request) +
					    sizeof(struct hash_state),
					    GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req:%p,\n", req);
		goto failed_req;
	}
	req->result =
	    kzalloc(qemu_cmd->u.hash.finup_req.digestsize, GFP_KERNEL);
	if (!req->result) {
		print_error("result memory allocation failed\n");
		goto failed_result;
	}
	state = ahash_request_ctx(req);
	ret = copy_from_user(state, qemu_cmd->u.hash.update_req.state,
			     sizeof(struct hash_state));
	if (ret != 0) {
		print_error("Copy from user failed  = %d\n", ret);
		goto failed_copy_state;
		return -1;
	}

	req->nbytes = qemu_cmd->u.hash.finup_req.sg_info.nbytes;
	req->src = sg;

	kfree(src_len);
	kfree(src);
	src = NULL;
	src_len = NULL;

	if (AHASH_FINUP_CTX == qemu_cmd->op)
		ret = ahash_finup_ctx(req, virtio_job);
	else if (AHASH_FINUP_NO_CTX == qemu_cmd->op)
		ret = ahash_finup_no_ctx(req, virtio_job);

	if (-1 != ret) {
		print_debug("AHASH_FINUP[%d] job succesfully given to card: %d\n",
		     qemu_cmd->op, ret);
		return 0;
	}
	print_error("AHASH_FINUP[%d] returns: %d\n", qemu_cmd->op, ret);

failed_copy_state:
	kfree(req->result);
failed_result:
	kfree(req);
failed_req:
failed_buf:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_sgs; i++) {
			buf = sg_virt(&sg[i]);
			kfree(buf);
		}
	}
failed_copy_srclen:
	if (src_len)
		kfree(src_len);
failed_srclen:
failed_copy_src:
	if (src)
		kfree(src);
failed_src:
	kfree(sg);
	return -1;
}

#endif

#ifdef SYMMETRIC_OFFLOAD
extern int fill_crypto_dev_sess_ctx(crypto_dev_sess_t *ctx, uint32_t op_type);

/***********************************************************************
* Function     : virtio_c2x0_symm_cra_init
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Context initialization for Ciphers
*
************************************************************************/
int virtio_c2x0_symm_cra_init(struct virtio_c2x0_job_ctx *virtio_job)
{
	struct virtio_c2x0_crypto_sess_ctx *vc_sess = NULL;
	crypto_dev_sess_t *ctx = NULL;
	struct sym_ctx *sym_ctx = NULL;
	struct vc_symm_cra_init *init = NULL;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	/*
	 * Creating a special cipher session context
	 * for each cipher operation from VM
	 */
	vc_sess = (struct virtio_c2x0_crypto_sess_ctx *)
	    kzalloc(sizeof(struct virtio_c2x0_crypto_sess_ctx), GFP_KERNEL);
	if (!vc_sess) {
		print_error("virtio_c2x0_crypto_sess_ctx alloc failed\n");
		return -1;
	}
	/*
	 * Storing the crypto_dev_ctx in VM as the session index
	 * to uniquely identify defirrent cryptodev hash sessions
	 */
	vc_sess->sess_id = qemu_cmd->u.symm.init.sess_id;
	vc_sess->guest_id = qemu_cmd->guest_id;
	ctx = &vc_sess->c_sess;
	sym_ctx = &(ctx->u.symm);
	print_debug("****** SYMMETRIC CONTEXT ADDRESS FOR OPERATION : %p\n",
		    sym_ctx);

	init = &(qemu_cmd->u.symm.init);

	if (-1 == fill_crypto_dev_sess_ctx(ctx, init->op_type))
		return -1;

	print_debug("SYM_CRA_INIT\n");

	sym_ctx->class1_alg_type = OP_TYPE_CLASS1_ALG | init->class1_alg_type;
	sym_ctx->class2_alg_type = OP_TYPE_CLASS2_ALG | init->class2_alg_type;
	sym_ctx->alg_op = OP_TYPE_CLASS2_ALG | init->alg_op;

	/*  Adding job to pending job list  */
	spin_lock(&symm_sess_list_lock);
	list_add_tail(&vc_sess->list_entry, &virtio_c2x0_symm_sess_list);
	spin_unlock(&symm_sess_list_lock);

	return 0;
}

/************************************************************************
* Function     : virtio_c2x0_symm_cra_exit
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : Context Removal for Ciphers
*
*************************************************************************/
int virtio_c2x0_symm_cra_exit(struct virtio_c2x0_qemu_cmd *qemu_cmd)
{
	struct virtio_c2x0_crypto_sess_ctx *vc_sess = NULL, *next_sess = NULL;
	crypto_dev_sess_t *ctx = NULL;
	int flag = 0;

	print_debug("VIRTIO SYM_CRA_EXIT\n");

	spin_lock(&symm_sess_list_lock);
	list_for_each_entry_safe(vc_sess, next_sess,
				 &virtio_c2x0_symm_sess_list, list_entry) {
		if (vc_sess->sess_id == qemu_cmd->u.symm.exit.sess_id
		    && vc_sess->guest_id == qemu_cmd->guest_id) {
			ctx = &(vc_sess->c_sess);
			flag = 1;
			print_debug("Symm session FOUND; sess_id = %lx\n",
				    vc_sess->sess_id);
			break;
		}
	}
	if (0 == flag) {
		print_error("Symm session[%lx] for guest [%d] NOT found\n",
			    qemu_cmd->u.symm.exit.sess_id, qemu_cmd->guest_id);
		spin_unlock(&symm_sess_list_lock);
		return -1;
	}
	/* Remove the symm session from list */
	list_del(&vc_sess->list_entry);
	spin_unlock(&symm_sess_list_lock);

	kfree(vc_sess);

	print_debug("EXIT FROM VIRTIO SYM_CRA_EXIT\n");
	return 0;
}

int32_t process_virtio_ablkcipher_job(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;
	struct ablkcipher_request *req = NULL;
	struct scatterlist *sg_src = NULL;
	struct scatterlist *sg_dst = NULL;
	uint8_t *buf = NULL;
	uint32_t buflen;
	uint8_t **src = NULL;
	uint32_t *src_len = NULL;
	uint8_t **dst = NULL;
	uint32_t *dst_len = NULL;
	int i = 0, max_filled_src_sgs = 0, max_filled_dst_sgs = 0;

	if (0 == qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; src_sg_count = %d;nbytes = %d;\n",
		       __func__,
		       qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count,
		       qemu_cmd->u.symm.cmd_req.src_sg_info.nbytes);
	}
	if (0 == qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count) {
		printk(KERN_INFO "%s:Entered; dst_sg_count = %d;nbytes = %d;\n",
		       __func__,
		       qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count,
		       qemu_cmd->u.symm.cmd_req.dst_sg_info.nbytes);
	}

	/*
	 * Allocating memory for scatterlist in ablkcipher_request->src
	 */
	sg_src = kzalloc(sizeof(struct scatterlist) *
			 qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count,
			 GFP_KERNEL);
#if 0
	if (!sg_src) {
		print_error("scatter gather memory allocation failed\n");
		return -1;
	}
#else
	if (unlikely(ZERO_OR_NULL_PTR(sg_src))) {
		print_error("sg_src[%p] is ZERO_SIZE_PTR\n", sg_src);
		kfree(sg_src);
		return -1;
	}
#endif

	/* VM's virtual addresses of each sg entry */
	src = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.symm.cmd_req.src_sg_info.
				   sg_count, GFP_KERNEL);
	if (!src) {
		print_error("src alloc failed\n");
		goto failed_src;
	}
	ret = copy_from_user(src, qemu_cmd->u.symm.cmd_req.src,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count);
	if (ret != 0) {
		print_error("src Copy from user failed  = %d\n", ret);
		goto failed_copy_src;
	}

	src_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.symm.cmd_req.src_sg_info.
				       sg_count, GFP_KERNEL);
	if (!src_len) {
		print_error("srclen alloc failed\n");
		goto failed_srclen;
	}
	ret = copy_from_user(src_len, qemu_cmd->u.symm.cmd_req.src_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count);
	if (ret != 0) {
		print_error("srclen Copy from user failed  = %d\n", ret);
		goto failed_copy_srclen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.symm.cmd_req.src_sg_info.sg_count; i++) {
		buflen = src_len[i];
		buf = (uint8_t *) kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf_src;
		}
		max_filled_src_sgs++;
		ret = copy_from_user(buf, src[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf_src;
		}
		sg_set_buf(&sg_src[i], (void *)buf, buflen);
		buf = NULL;
	}

	/*
	 * Allocating memory for scatterlist in ablkcipher_request->dst
	 */
	sg_dst = kzalloc(sizeof(struct scatterlist) *
			 qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count,
			 GFP_KERNEL);
	if (!sg_dst) {
		print_error("scatter gather memory allocation failed\n");
		goto failed_sg_dst;
		return -1;
	}

	/* VM's virtual addresses of each sg entry */
	dst = (uint8_t **) kzalloc(sizeof(uint8_t *) *
				   qemu_cmd->u.symm.cmd_req.dst_sg_info.
				   sg_count, GFP_KERNEL);
	if (!dst) {
		print_error("src alloc failed\n");
		goto failed_dst;
	}
	ret = copy_from_user(dst, qemu_cmd->u.symm.cmd_req.dst,
			     sizeof(uint8_t *) *
			     qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count);
	if (ret != 0) {
		print_error("src Copy from user failed  = %d\n", ret);
		goto failed_copy_dst;
	}

	dst_len = (uint32_t *) kzalloc(sizeof(uint32_t *) *
				       qemu_cmd->u.symm.cmd_req.dst_sg_info.
				       sg_count, GFP_KERNEL);
	if (!dst_len) {
		print_error("srclen alloc failed\n");
		goto failed_dstlen;
	}
	ret = copy_from_user(dst_len, qemu_cmd->u.symm.cmd_req.dst_len,
			     sizeof(uint32_t *) *
			     qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count);
	if (ret != 0) {
		print_error("dstlen Copy from user failed  = %d\n", ret);
		goto failed_copy_dstlen;
	}

	/*
	 * Copy input data from VM and
	 * Fill the ahash_request->scatterlist entries from the
	 * VM's sg address received through Qemu
	 */
	for (i = 0; i < qemu_cmd->u.symm.cmd_req.dst_sg_info.sg_count; i++) {
		buflen = dst_len[i];
		buf = (uint8_t *) kzalloc(buflen, GFP_KERNEL);
		if (!buf) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf_dst;
		}
		max_filled_dst_sgs++;
		ret = copy_from_user(buf, dst[i], buflen);
		if (ret != 0) {
			print_error("Copy from user failed  = %d\n", ret);
			goto failed_buf_dst;
		}
		sg_set_buf(&sg_dst[i], (void *)buf, buflen);
		buf = NULL;
	}

	/*
	 * In driver's qemu_cmd, Overwrite the actual userspace
	 * qemu double pointer
	 * (holding adresses of userspace pointers)
	 * with local double pointer
	 * (holding copy of userspace pointers)
	 * This does NOT alter the qemu's copy of qemu_cmd
	 * This is done to preserve userspace pointers to
	 * copy output in response path
	 */
	qemu_cmd->u.symm.cmd_req.src = src;
	qemu_cmd->u.symm.cmd_req.src_len = src_len;
	qemu_cmd->u.symm.cmd_req.dst = dst;
	qemu_cmd->u.symm.cmd_req.dst_len = dst_len;

	/*
	 * Creating ablkcipher_request
	 */
	req =
	    (struct ablkcipher_request *)
	    kzalloc(sizeof(struct ablkcipher_request), GFP_KERNEL);
	if (!req) {
		print_error("Alloc failed req: %p,\n", req);
		goto failed_req;
	}

	req->nbytes = qemu_cmd->u.symm.cmd_req.src_sg_info.nbytes;
	req->src = sg_src;
	req->dst = sg_dst;

	req->info = kzalloc(qemu_cmd->u.symm.cmd_req.ivsize, GFP_KERNEL);
	if (!req->info) {
		print_error("result memory allocation failed\n");
		goto failed_info;
	}

	ret = copy_from_user(req->info, qemu_cmd->u.symm.cmd_req.info,
			     qemu_cmd->u.symm.cmd_req.ivsize);
	if (0 != ret) {
		print_error("copy_from_user failed\n");
		goto failed_copy_info;
	}

	if (ABLK_ENCRYPT == qemu_cmd->op)
		ret = fsl_ablkcipher(req, true, virtio_job);
	else if (ABLK_DECRYPT == qemu_cmd->op)
		ret = fsl_ablkcipher(req, false, virtio_job);

	if (-1 != ret) {
		print_debug("ABLK job succesfully given to card: %d\n", ret);
		return 0;
	}
	print_error("fsl_ablkcipher_desc_alloc returns: %d\n", ret);

failed_copy_info:
	kfree(req->info);
failed_info:
	kfree(req);
failed_req:
failed_buf_dst:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_dst_sgs; i++) {
			buf = sg_virt(&sg_dst[i]);
			kfree(buf);
		}
	}
failed_copy_dstlen:
	kfree(dst_len);
failed_dstlen:
failed_copy_dst:
	kfree(dst);
failed_dst:
	kfree(sg_dst);
failed_sg_dst:
failed_buf_src:
	{
		uint8_t *buf = NULL;

		int i = 0;
		for (i = 0; i < max_filled_src_sgs; i++) {
			buf = sg_virt(&sg_src[i]);
			kfree(buf);
		}
	}
failed_copy_srclen:
	kfree(src_len);
failed_srclen:
failed_copy_src:
	kfree(src);
failed_src:
	kfree(sg_src);
	return -1;

}
#endif

/********************************************************************
* Function     : process_virtio_app_req
*
* Arguments    : virtio_job - virtio job structure
*
* Return Value : int32_t
*
* Description  : processes the job  for virtio
*
**********************************************************************/

int32_t process_virtio_app_req(struct virtio_c2x0_job_ctx *virtio_job)
{
	int32_t ret = 0;
	struct virtio_c2x0_qemu_cmd *qemu_cmd = &virtio_job->qemu_cmd;

	print_debug("Virtio job request with operation: %d\n", qemu_cmd->op);
	switch (qemu_cmd->op) {
	case RSA:
		print_debug(" RSA Operation\n");
		ret = process_virtio_rsa_job(virtio_job);
		break;

	case DSA:
		print_debug(" DSA Operation\n");
		ret = process_virtio_dsa_job(virtio_job);
		break;
	case DH:
		print_debug(" DH Operation\n");
		ret = process_virtio_dh_job(virtio_job);
		break;
#ifdef HASH_OFFLOAD
	case HASH_SPLIT_KEY:
		print_debug("HASH_SPLIT_KEY operation\n");
		ret = process_virtio_hash_split_key_job(virtio_job);
		break;
	case AHASH_DIGEST:
		print_debug("AHASH_DIGEST operation\n");
		ret = process_virtio_ahash_digest_job(virtio_job);
		break;
	case AHASH_UPDATE_CTX:
		print_debug("AHASH_UPDATE_CTX operation\n");
		ret = process_virtio_ahash_update_job(virtio_job);
		break;
	case AHASH_UPDATE_NO_CTX:
		print_debug("AHASH_UPDATE_NO_CTX operation\n");
		ret = process_virtio_ahash_update_job(virtio_job);
		break;
	case AHASH_UPDATE_FIRST:
		print_debug("AHASH_UPDATE_FIRST operation\n");
		ret = process_virtio_ahash_update_job(virtio_job);
		break;
	case AHASH_FINAL_CTX:
		print_debug("AHASH_FINAL_CTX operation\n");
		ret = process_virtio_ahash_final_job(virtio_job);
		break;
	case AHASH_FINAL_NO_CTX:
		print_debug("AHASH_FINAL_NO_CTX operation\n");
		ret = process_virtio_ahash_final_job(virtio_job);
		break;
	case AHASH_FINUP_CTX:
		print_debug("AHASH_FINUP_CTX operation\n");
		ret = process_virtio_ahash_finup_job(virtio_job);
		break;
	case AHASH_FINUP_NO_CTX:
		print_debug("AHASH_FINUP_NO_CTX operation\n");
		ret = process_virtio_ahash_finup_job(virtio_job);
		break;
#endif
#ifdef SYMMETRIC_OFFLOAD
	case ABLK_ENCRYPT:
		print_debug("ABLK_ENCRYPT operation\n");
		ret = process_virtio_ablkcipher_job(virtio_job);
		break;
	case ABLK_DECRYPT:
		print_debug("ABLK_DECRYPT operation\n");
		ret = process_virtio_ablkcipher_job(virtio_job);
		break;
	case VIRTIO_C2X0_ABLK_SETKEY:
		{
			uint8_t *key = NULL;

			print_debug("VIRTIO_C2X0_ABLK_SETKEY operation\n");
			key =
			    (uint8_t *) kzalloc(virtio_job->qemu_cmd.u.symm.
						setkey_req.keylen, GFP_KERNEL);
			if (!key) {
				print_error("Key alloc failed\n");
				return -1;
			}

			ret =
			    copy_from_user(key,
					   virtio_job->qemu_cmd.u.symm.
					   setkey_req.key,
					   virtio_job->qemu_cmd.u.symm.
					   setkey_req.keylen);
			if (0 != ret) {
				print_error("copy from user failed with %d\n",
					    ret);
				kfree(key);
				return -1;
			}

			ret = fsl_ablkcipher_setkey(qemu_cmd,
						    key,
						    virtio_job->qemu_cmd.u.symm.
						    setkey_req.keylen);

			kfree(key);
			if (ret >= 0)
				return 0;

			break;
		}
#endif
#ifdef RNG_OFFLOAD
	case RNG:
		print_debug("RNG Operation\n");
		ret = process_virtio_rng_job(virtio_job);
		break;
#endif
	default:
		print_error("Invalid Operation!");
		ret = -1;
		break;
	}
	return ret;
}
#endif /* VIRTIO_C2X0 : handling virtio_operations */
