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
	uint16_t total_isrs = dev->priv_dev->intr_info.intr_vectors_cnt;
	struct bh_handler *instance;
	isr_ctx_t *isr_ctx;

	isr_ctx_list_head = &(dev->priv_dev->intr_info.isr_ctx_list_head);

	isr_ctx = list_entry(isr_ctx_list_head->next, isr_ctx_t, list);

	INIT_LIST_HEAD(&(isr_ctx->ring_list_head));

	/* Affine the ring to CPU & ISR */
	for (i = 0; i < config->num_of_rings; i++) {
		while (!(wt_cpu_mask & (1 << core_no))) {
			core_no = cpumask_next(core_no, cpu_online_mask) % nr_cpu_ids;
		}

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

		core_no = cpumask_next(core_no, cpu_online_mask) % nr_cpu_ids;
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

	host_v_addr = dma_alloc_coherent(&dev->priv_dev->dev->dev, ob_mem_len,
					&(mem->host_dma_addr), GFP_KERNEL);
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

void send_hs_init_ring_pair(fsl_crypto_dev_t *dev, struct ring_info *ring)
{
	const char *str_state = "HS_INIT_RING_PAIR\n";
	uint32_t resp_r_offset;

	set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
			(uint8_t *) str_state, strlen(str_state));

	resp_r_offset = (void *)dev->ring_pairs[ring->ring_id].resp_r -
			(void *)dev->host_mem;

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
}

void send_hs_complete(fsl_crypto_dev_t *dev)
{
	const char *str_state = "HS_COMPLETE\n";
	set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
			(uint8_t *) str_state, strlen(str_state));

	iowrite8(FW_HS_COMPLETE, &dev->c_hs_mem->state);
}

void send_hs_wait_for_rng(fsl_crypto_dev_t *dev)
{
	const char *str_state = "WAIT_FOR_RNG\n";

	set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
			(uint8_t *) str_state, strlen(str_state));

	iowrite8(FW_WAIT_FOR_RNG, &dev->c_hs_mem->state);
}

void send_hs_rng_done(fsl_crypto_dev_t *dev)
{
	const char *str_state = "RNG_DONE\n";

	set_sysfs_value(dev->priv_dev, DEVICE_STATE_SYSFILE,
			(uint8_t *) str_state, strlen(str_state));

	iowrite8(FW_RNG_DONE, &dev->c_hs_mem->state);
}

void hs_firmware_up(fsl_crypto_dev_t *dev)
{
	struct fw_up_data *hsdev = &dev->host_mem->hs_mem.data.device;
	uint32_t p_ib_l;
	uint32_t p_ib_h;
	uint32_t p_ob_l;
	uint32_t p_ob_h;

	print_debug(" ----------- FIRMWARE_UP -----------\n");

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
}

void hs_fw_init_complete(fsl_crypto_dev_t *dev, struct crypto_dev_config *config, uint8_t rid)
{
	struct config_data *hscfg = &dev->host_mem->hs_mem.data.config;
	void *ptr;
	uint32_t r_s_c_cntrs;
	uint32_t s_c_cntrs;
	uint32_t ip_pool;
	uint32_t resp_intr_ctrl_flag;
	int i;

	print_debug("--- FW_INIT_CONFIG_COMPLETE ---\n");

	dev->host_mem->hs_mem.state = DEFAULT;

	r_s_c_cntrs = be32_to_cpu(hscfg->r_s_c_cntrs);
	s_c_cntrs = be32_to_cpu(hscfg->s_c_cntrs);
	ip_pool = be32_to_cpu(hscfg->ip_pool);
	resp_intr_ctrl_flag = be32_to_cpu(hscfg->resp_intr_ctrl_flag);

	dev->r_s_c_cntrs = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + r_s_c_cntrs;
	dev->s_c_cntrs = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + s_c_cntrs;
	dev->dev_ip_pool.d_p_addr = dev->priv_dev->bars[MEM_TYPE_SRAM].dev_p_addr + ip_pool;
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
	print_debug("FW Pool host V addr: %p\n", dev->dev_ip_pool.h_v_addr);
}

void hs_init_rp_complete(fsl_crypto_dev_t *dev, struct crypto_dev_config *config, uint8_t rid)
{
	struct ring_data *hsring = &dev->host_mem->hs_mem.data.ring;
	uint32_t req_r;
	uint32_t intr_ctrl_flag;

	print_debug("---- FW_INIT_RING_PAIR_COMPLETE ----\n");

	dev->host_mem->hs_mem.state = DEFAULT;
	req_r = be32_to_cpu(hsring->req_r);
	intr_ctrl_flag = be32_to_cpu(hsring->intr_ctrl_flag);

	dev->ring_pairs[rid].shadow_counters = &(dev->r_s_c_cntrs[rid]);
	dev->ring_pairs[rid].req_r =dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + req_r;
	dev->ring_pairs[rid].intr_ctrl_flag = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr +
			intr_ctrl_flag;

	print_debug("Ring id     : %d\n", rid);
	print_debug("Shadow cntrs: %p\n", dev->ring_pairs[rid].shadow_counters);
	print_debug("Req r       : %p\n", dev->ring_pairs[rid].req_r);
	print_debug("Interrupt   : %p\n", dev->ring_pairs[rid].intr_ctrl_flag);
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
			send_hs_init_config(dev);
			break;
		case FW_INIT_CONFIG_COMPLETE:
			hs_fw_init_complete(dev, config, rid);
			send_hs_init_ring_pair(dev, &(config->ring[rid]));
			break;
		case FW_INIT_RING_PAIR_COMPLETE:
			no_secs = be32_to_cpu(dev->host_mem->hs_mem.data.device.no_secs);
			if (f_get_a(config->ring[rid].flags) > no_secs) {
				print_error("Wrong Affinity for the ring: %d\n", rid);
				print_error("No of SECs are %d\n", no_secs);
				goto error;
			}
			hs_init_rp_complete(dev, config, rid);
			rid++;
			if (rid < dev->num_of_rings) {
				send_hs_init_ring_pair(dev, &(config->ring[rid]));
			} else {
				send_hs_complete(dev);
			}
			break;
		case FW_INIT_RNG:
			send_hs_wait_for_rng(dev);
			if (rng_instantiation(dev)) {
				print_error("RNG Instantiation Failed!\n");
				goto error;
			}
			send_hs_rng_done(dev);
			goto exit;
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
	 * Set LAW0 for target platform SRAM, size 2^0x13 = 512KB
	 * We don't overlap this window with the one for Cache SRAM as recommended
	 * by the reference manual:
	 * "Overlapping SRAM and local access windows is discouraged because
	 * processor and snoopable I/O transactions would map to the SRAM while
	 * non-snooped I/O transactions would be mapped by the local access
	 * windows */

	iowrite32be(p_sram_start >> 12,	ccsr + 0xc08); /* LAW_LAWBAR0 */
	iowrite32be(0x80a00012,		ccsr + 0xc10); /* LAW_LAWAR0 */

	/* Set LAW1 for target PCIe, size 2^0x22 = 16G, starting address 32G */
	iowrite32be(0x800000000 >> 12,	ccsr + 0xc28); /* LAW_LAWBAR1 */
	iowrite32be(0x80200021,		ccsr + 0xc30); /* LAW_LAWAR1 */

	/* Set PEX inbound and outbound window translations. These must match
	 * the LAWs defined earlier
	 *
	 * Set inbound address translation:
	 * 	Host		Device
	 *	0x00000 --- 0xfff00000
	 *	0xfffff --- 0xffffffff
	 */
	iowrite32be(l2_sram_start >> 12, ccsr + 0xadc0); /* PEX_PEXITAR1 */
	iowrite32be(0,			ccsr + 0xadc8);  /* PEX_PEXIWBAR1 */
	iowrite32be(0xa0f55013,		ccsr + 0xadd0);  /* PEX_PEXIWAR1 */

	/* Set outbound address translation
	 * 	Device		Host
	 *	0x800000000	0x800000000
	 * 	0xBFFFFFFFF	0xBFFFFFFFF
	 */

	iowrite32be(0,			ccsr + 0xac20); /* PEX_PEXOTAR1 */
	iowrite32be(0,			ccsr + 0xac24); /* PEX_PEXOTEAR1 */
	iowrite32be(0x800000000 >> 12,	ccsr + 0xac28); /* PEX_PEXOWBAR1 */
	iowrite32be(0x80044021,		ccsr + 0xac30); /* PEX_PEXOWAR1 */

	/* Read-back LAW register to guarantee visibility to all device blocks */
	val = ioread32be(ccsr + 0xc30); /* LAW_LAWAR1 */

	print_debug("======= setup_ep =======\n");
	print_debug("Ob mem dma_addr: %pa\n", &(dev->priv_dev->bars[MEM_TYPE_DRIVER].host_dma_addr));
	print_debug("Ob mem dev_p_addr: %pa\n", &(dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr));
	print_debug("Ob mem len: %pa\n", &dev->priv_dev->bars[MEM_TYPE_DRIVER].len);
	print_debug("BAR0 V Addr: %p\n", ccsr);
	print_debug("MSI mem: %pa\n", &(dev->priv_dev->bars[MEM_TYPE_MSI].host_p_addr));

	/* Dumping the registers set */
	print_debug(" ==== EP REGISTERS ====\n");
	print_debug("L2CACHE CSRBAR\n");
	print_debug("0X20100 :- %0x\n", ioread32be(ccsr + 0x20100));
	print_debug("0X20104 :- %0x\n", ioread32be(ccsr + 0x20104));
	print_debug("0X20000 :- %0x\n", ioread32be(ccsr + 0x20000));
	print_debug("\n");
	print_debug("LAW 0\n");
	print_debug("0xc08  :- :%0x\n", ioread32be(ccsr + 0xc08));
	print_debug("0xc10  :- :%0x\n", ioread32be(ccsr + 0xc10));
	print_debug("\n");
	print_debug("LAW 1\n");
	print_debug("0xc28  :- :%0x\n", ioread32be(ccsr + 0xc28));
	print_debug("0xc30  :- :%0x\n", ioread32be(ccsr + 0xc30));
	print_debug("\n");
	print_debug("inbound window 0\n");
	print_debug("0xadf0 :- :%0x\n", ioread32be(ccsr + 0xadf0));
	print_debug("0xadc0 :- :%0x\n", ioread32be(ccsr + 0xade0));
	print_debug("\n");
	print_debug("inbound window 1\n");
	print_debug("0xadd0 :- :%0x\n", ioread32be(ccsr + 0xadd0));
	print_debug("0xadc8 :- :%0x\n", ioread32be(ccsr + 0xadc8));
	print_debug("0xadc0 :- :%0x\n", ioread32be(ccsr + 0xadc0));
	print_debug("\n");
	print_debug("outbound window 1\n");
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
}

void init_ip_pool(fsl_crypto_dev_t *dev)
{
	create_pool(&dev->host_ip_pool.buf_pool, dev->host_mem->ip_pool,
			FIRMWARE_IP_BUFFER_POOL_SIZE);

	dev->host_ip_pool.h_v_addr = dev->host_mem->ip_pool;
	dev->host_ip_pool.h_dma_addr = dev->priv_dev->bars[MEM_TYPE_DRIVER].host_dma_addr + dev->ob_mem.ip_pool;
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
	fsl_h_rsrc_ring_pair_t *rp = NULL;

	print_debug("Sec desc addr: %llx\n", sec_desc);
	print_debug("Enqueue job in ring: %d\n", jr_id);

	rp = &(c_dev->ring_pairs[jr_id]);

	/* Acquire the lock on current ring */
	spin_lock_bh(&rp->ring_lock);

	jobs_processed = be32_to_cpu(rp->r_s_cntrs->jobs_processed);

	if (rp->counters->jobs_added - jobs_processed >= rp->depth) {
		print_debug("Ring: %d is full\n", jr_id);
		spin_unlock_bh(&(rp->ring_lock));
		return -1;
	}
	wi = rp->indexes->w_index;

	print_debug("Enqueuing at the index: %d\n", wi);
	print_debug("Enqueuing to the req r addr: %p\n", rp->req_r);
	print_debug("Writing at the addr	: %p\n", &(rp->req_r[wi].sec_desc));

	rp->req_r[wi].sec_desc = cpu_to_be64(sec_desc);

	/* confirm the descriptor has been written before updating ring index */
	wmb();

	rp->indexes->w_index = (wi + 1) % rp->depth;
	print_debug("Update W index: %d\n", rp->indexes->w_index);

	rp->counters->jobs_added += 1;
	print_debug("Updated jobs added: %d\n", rp->counters->jobs_added);
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

	/* Set the EP registers correctly before booting... */
	setup_ep(c_dev);

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
	void *h_desc;
	crypto_op_ctx_t *ctx0 = NULL;
	dev_p_addr_t offset = dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;

	h_desc = dev->host_ip_pool.h_v_addr + (desc - offset) -
			dev->host_ip_pool.h_dma_addr;

	ctx0 = (crypto_op_ctx_t *) get_priv_data(h_desc);
	if (ctx0) {
		ctx0->op_done(ctx0, res);
	} else {
		print_debug("NULL Context!!\n");
	}

	return;
}

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

	pollcount = 0;

	while (pollcount++ < napi_poll_count) {
		jobs_added = be32_to_cpu(ring_cursor->r_s_cntrs->jobs_added);
		resp_cnt = jobs_added - ring_cursor->counters->jobs_processed;
		if (!resp_cnt)
			continue;

		dev = ring_cursor->dev;
		ri = ring_cursor->indexes->r_index;
		print_debug("RING ID: %d\n", ring_cursor->info.ring_id);
		print_debug("GOT INTERRUPT FROM DEV: %d\n", dev->config->dev_no);

		while (resp_cnt) {
			desc = be64_to_cpu(ring_cursor->resp_r[ri].sec_desc);
			res = be32_to_cpu(ring_cursor->resp_r[ri].result);
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

	print_debug("DONE PROCESSING RESPONSE\n");
	return 0;
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
