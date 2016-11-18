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

#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/sched.h>

#include "debug_print.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "error.h"

extern int32_t wt_cpu_mask;
extern struct bh_handler __percpu *bh_workers;

#define FIRMWARE_IP_BUFFER_POOL_SIZE		(512*1024)

/* Application ring properties bit masks and shift */
#define APP_RING_PROP_ORDER_MASK    0x01
#define APP_RING_PROP_ORDER_SHIFT   0

#define APP_RING_PROP_AFFINE_MASK   0X0E
#define APP_RING_PROP_AFFINE_SHIFT  1

#define APP_RING_PROP_PRIO_MASK     0XF0
#define APP_RING_PROP_PRIO_SHIFT    4

#define PHYS_ADDR_L_32_BIT_MASK       0xFFFFFFFF
/* Since the device has 36bit bus --
 * Only two bits from higher address is sufficient */
#define PHYS_ADDR_H_32_BIT_MASK       0x300000000ull

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
	struct list_head *isr_ctx_head;
	uint16_t total_isrs = dev->priv_dev->intr_info.intr_vectors_cnt;
	struct bh_handler *bh_worker;
	isr_ctx_t *isr_ctx;

	isr_ctx_head = &(dev->priv_dev->intr_info.isr_ctx_head);

	isr_ctx = list_entry(isr_ctx_head->next, isr_ctx_t, list);

	INIT_LIST_HEAD(&(isr_ctx->ring_list_head));

	/* Affine the ring to CPU & ISR */
	for (i = 0; i < config->num_of_rps; i++) {
		while (!(wt_cpu_mask & (1 << core_no))) {
			core_no = cpumask_next(core_no, cpu_online_mask) % nr_cpu_ids;
		}

		print_debug("Ring no: %d Core no: %d\n", i, core_no);
		bh_worker = per_cpu_ptr(bh_workers, core_no);

		rp = &(dev->ring_pairs[i]);
		rp->core_no = core_no;

		config->ring[i].msi_addr_l = isr_ctx->msi_addr_low;
		config->ring[i].msi_addr_h = isr_ctx->msi_addr_high;
		config->ring[i].msi_data = isr_ctx->msi_data;

		/* Adding the ring to the ISR */
		list_add(&(rp->isr_ctx_list_node), &(isr_ctx->ring_list_head));
		list_add(&(rp->bh_ctx_list_node), &(bh_worker->ring_list_head));

		if ((++isr_count) % total_isrs) {
			isr_ctx = list_entry(isr_ctx->list.next, isr_ctx_t, list);
		} else {
			isr_ctx = list_entry(isr_ctx_head->next, isr_ctx_t,
						list);
		}

		print_debug("ISR COUNT: %d total num of isrs: %d\n",
			    isr_count, total_isrs);

		core_no = cpumask_next(core_no, cpu_online_mask) % nr_cpu_ids;
	}
}

static uint32_t count_ring_slots(struct crypto_dev_config *config)
{
	uint32_t i, len = 0;

	for (i = 0; i < config->num_of_rps; i++) {
		len += config->ring[i].depth;
	}
	return len;
}

uint32_t ob_alloc(size_t size)
{
	static uint32_t addr;
	uint32_t save_addr;

	save_addr = cache_line_align(addr);
	addr = save_addr + size;

	return save_addr;
}

static uint32_t calc_ob_mem_len(fsl_crypto_dev_t *dev,
				struct crypto_dev_config *config)
{
	uint32_t total_ring_slots;

	total_ring_slots = count_ring_slots(config);

	dev->ob_mem.hs_mem = ob_alloc(sizeof(struct host_mem_layout));
	dev->ob_mem.drv_resp_rings = ob_alloc(total_ring_slots *
					sizeof(struct resp_ring_entry));
	dev->ob_mem.idxs_mem = ob_alloc(config->num_of_rps *
					sizeof(struct ring_idxs_mem));
	dev->ob_mem.cntrs_mem = ob_alloc(config->num_of_rps *
					sizeof(struct ring_counters_mem));
	dev->ob_mem.r_s_cntrs_mem = ob_alloc(config->num_of_rps *
					sizeof(struct ring_counters_mem));
	dev->ob_mem.ip_pool = ob_alloc(FIRMWARE_IP_BUFFER_POOL_SIZE);

	/* Make the total mem requirement aligned to page size */
	return page_align(ob_alloc(0));
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
	dev->host_mem->drv_resp_rings = host_v_addr + dev->ob_mem.drv_resp_rings;
	dev->host_mem->idxs_mem = host_v_addr + dev->ob_mem.idxs_mem;
	dev->host_mem->cntrs_mem = host_v_addr + dev->ob_mem.cntrs_mem;
	dev->host_mem->r_s_cntrs_mem = host_v_addr + dev->ob_mem.r_s_cntrs_mem;
	dev->host_mem->ip_pool = host_v_addr + dev->ob_mem.ip_pool;

	print_debug("====== OB MEM POINTERS =======\n");
	print_debug("Hmem		: %p\n", dev->host_mem);
	print_debug("H HS Mem		: %p\n", &(dev->host_mem->hs_mem));
	print_debug("Drv resp rings	: %p\n", dev->host_mem->drv_resp_rings);
	print_debug("Idxs mem	        : %p\n", dev->host_mem->idxs_mem);
	print_debug("cntrs mem          : %p\n", dev->host_mem->cntrs_mem);
	print_debug("S C R cntrs mem	: %p\n", dev->host_mem->r_s_cntrs_mem);
	print_debug("IP pool		: %p\n", dev->host_mem->ip_pool);

	return 0;
}

void init_handshake(fsl_crypto_dev_t *dev)
{
	dma_addr_t ob_mem = dev->priv_dev->bars[MEM_TYPE_DRIVER].host_dma_addr;

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
	 * When the device is started it will want to know where to put things
	 * where the host driver will find them: host memory (at the base of
	 * which there is the host handshake area) and interrupt information
	 * (which will be given with each ring later during handshake)
	 */
	iowrite32be(l_val, (void *) &dev->c_hs_mem->h_ob_mem_l);
	iowrite32be(h_val, (void *) &dev->c_hs_mem->h_ob_mem_h);
}

void init_ring_pairs(fsl_crypto_dev_t *dev)
{
	fsl_h_rsrc_ring_pair_t *rp;
	uint32_t i;
	/* all response ring entries start here. Each ring has rp->depth entries */
	struct resp_ring_entry *resp_r = dev->host_mem->drv_resp_rings;

	for (i = 0; i < dev->num_of_rps; i++) {
		rp = &(dev->ring_pairs[i]);

		rp->dev = dev;
		rp->depth = dev->config->ring[i].depth;

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

		spin_lock_init(&(rp->ring_lock));
	}

}

void send_hs_init_config(fsl_crypto_dev_t *dev)
{
	struct c_config_data *config = &dev->c_hs_mem->data.config;

	iowrite8(dev->num_of_rps, &config->num_of_rps);
	iowrite32be(dev->ob_mem.r_s_cntrs_mem, &config->r_s_cntrs);

	print_debug("HS_INIT_CONFIG Details\n");
	print_debug("Num of ring pairs: %d\n", dev->num_of_rps);
	print_debug("R S counters  : %x\n", dev->ob_mem.r_s_cntrs_mem);
	print_debug("Sending FW_INIT_CONFIG command at addr: %p\n",
			&(dev->c_hs_mem->state));
	barrier();
	iowrite8(FW_INIT_CONFIG, &dev->c_hs_mem->state);
}

void send_hs_init_ring_pair(fsl_crypto_dev_t *dev, struct ring_info *ring)
{
	uint32_t resp_r_offset;

	resp_r_offset = (void *)dev->ring_pairs[ring->ring_id].resp_r -
			(void *)dev->host_mem;

	iowrite8(ring->ring_id, &dev->c_hs_mem->data.ring.rid);
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
	iowrite8(FW_HS_COMPLETE, &dev->c_hs_mem->state);
}

void send_hs_wait_for_rng(fsl_crypto_dev_t *dev)
{
	iowrite8(FW_WAIT_FOR_RNG, &dev->c_hs_mem->state);
}

void send_hs_rng_done(fsl_crypto_dev_t *dev)
{
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

void hs_fw_init_complete(fsl_crypto_dev_t *dev, uint8_t rid)
{
	struct config_data *hscfg = &dev->host_mem->hs_mem.data.config;
	uint32_t r_s_c_cntrs;

	print_debug("--- FW_INIT_CONFIG_COMPLETE ---\n");

	dev->host_mem->hs_mem.state = DEFAULT;

	r_s_c_cntrs = be32_to_cpu(hscfg->r_s_c_cntrs);

	dev->r_s_c_cntrs = dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + r_s_c_cntrs;

	print_debug(" ----- Details from firmware  -------\n");
	print_debug("SRAM H V ADDR: %p\n", dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr);
	print_debug("R S C CNTRS OFFSET: %x\n", r_s_c_cntrs);
	print_debug("-----------------------------------\n");
	print_debug("R S C Cntrs: %p\n", dev->r_s_c_cntrs);
}

void hs_init_rp_complete(fsl_crypto_dev_t *dev, uint8_t rid)
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
	uint32_t timecntr = 0;

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
			hs_fw_init_complete(dev, rid);
			send_hs_init_ring_pair(dev, &(config->ring[rid]));
			break;
		case FW_INIT_RING_PAIR_COMPLETE:
			hs_init_rp_complete(dev, rid);
			rid++;
			if (rid < dev->num_of_rps) {
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
			if (timecntr > HS_TIMEOUT) {
				print_error("HS Timed out!!!!\n");
				goto error;
			}
			timecntr += HS_LOOP_BREAK;
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(msecs_to_jiffies(HS_LOOP_BREAK));

			break;

		default:
			print_error("Invalid state: %d\n", dev->host_mem->hs_mem.state);
			goto error;
		}
	}
exit:
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

int32_t ring_enqueue(fsl_crypto_dev_t *c_dev, uint32_t jr_id,
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
	fsl_crypto_dev_t *c_dev;
	int err;

	/* some fields are assumed to be null when they are first used */
	c_dev = kzalloc(sizeof(fsl_crypto_dev_t), GFP_KERNEL);
	if (!c_dev)
		return NULL;

	c_dev->ring_pairs = kzalloc(sizeof(fsl_h_rsrc_ring_pair_t) *
				    config->num_of_rps, GFP_KERNEL);
	if (!c_dev->ring_pairs)
		goto rp_fail;

	c_dev->priv_dev = fsl_pci_dev;
	c_dev->config = config;
	c_dev->num_of_rps = config->num_of_rps;

	/* HACK */
	fsl_pci_dev->crypto_dev = c_dev;

	atomic_set(&(c_dev->crypto_dev_sess_cnt), 0);

	c_dev->c_hs_mem = c_dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr + HS_MEM_OFFSET;

	print_debug("IB mem addr: %p\n", c_dev->priv_dev->bars[MEM_TYPE_SRAM].host_v_addr);
	print_debug("Device hs mem addr: %p\n", c_dev->c_hs_mem);

	err = alloc_ob_mem(c_dev, config);
	if (err) {
		print_error("Ob mem alloc failed....\n");
		goto ob_mem_fail;
	}

	init_ip_pool(c_dev);

	err = init_crypto_ctx_pool(c_dev);
	if (err) {
		print_error("Failed to allocate context pool\n");
		goto ctx_pool_fail;
	}

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

	err = handshake(c_dev, config);
	if (err) {
		print_error("Handshake failed\n");
		goto error;
	}

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
	struct bh_handler *bh_worker;
	struct list_head *pos, *next;

	for_each_online_cpu(i) {
		bh_worker = per_cpu_ptr(bh_workers, i);

		list_for_each_safe(pos, next, &(bh_worker->ring_list_head)) {
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
	for (i = 0; i < dev->num_of_rps; i++) {
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

/* FIXME: function argument dev is overwritten in the first loop */
void process_response(fsl_crypto_dev_t *dev, fsl_h_rsrc_ring_pair_t *ring_cursor)
{
	uint32_t pollcount;
	uint32_t jobs_added;
	uint32_t resp_cnt;
	uint32_t ri;
	uint64_t desc;
	uint32_t res;
	struct device *my_dev = &dev->priv_dev->dev->dev;

	pollcount = 0;

	while (pollcount++ < napi_poll_count) {
		jobs_added = be32_to_cpu(ring_cursor->r_s_cntrs->jobs_added);
		resp_cnt = jobs_added - ring_cursor->counters->jobs_processed;
		if (!resp_cnt)
			continue;

		dev = ring_cursor->dev;
		ri = ring_cursor->indexes->r_index;
		print_debug("GOT INTERRUPT FROM DEV: %d\n", dev->config->dev_no);

		while (resp_cnt) {
			desc = be64_to_cpu(ring_cursor->resp_r[ri].sec_desc);
			res = be32_to_cpu(ring_cursor->resp_r[ri].result);
			{
				print_debug("APP RING GOT AN INTERRUPT\n");
				if (desc != 0) {
					handle_response(dev, desc, res);
				} else {
					dev_err(my_dev, "INVALID DESC AT RI : %u\n", ri);
				}
				if (res != 0) {
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

/*******************************************************************************
 * Function     : response_ring_handler
 *
 * Arguments    : work - Kernel work posted to this handler
 *
 * Return Value : none
 *
 * Description  : Bottom half implementation to handle the responses.
 *
 ******************************************************************************/
void response_ring_handler(struct work_struct *work)
{
	struct bh_handler *bh = container_of(work, struct bh_handler, work);
	fsl_crypto_dev_t *c_dev;

	if (unlikely(NULL == bh)) {
		print_error("No bottom half handler found for the work\n");
		return;
	}

	c_dev = bh->c_dev;	/* get_crypto_dev(1); */
	print_debug("GOT INTERRUPT FROM DEV : %d\n", c_dev->config->dev_no);
	print_debug("Worker thread invoked on cpu [%d]\n", bh->core_no);
	process_rings(c_dev, &(bh->ring_list_head));
	return;
}
