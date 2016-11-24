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

/* The size of the ip_pool was chosen 512K so it could fit in the device SRAM
 * (which has less than 1M available) without changing the supporting code.
 * Since the current implementation has all data in host RAM, this limitation
 * may be lifted */
#define BUFFER_MEM_SIZE		(512*1024)

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

void distribute_rings(struct c29x_dev *c_dev)
{
	fsl_h_rsrc_ring_pair_t *rp;
	uint32_t core_no = 0;
	uint16_t isr_count = 0;
	uint32_t i;
	struct list_head *isr_ctx_head;
	uint16_t total_isrs = c_dev->intr_info.intr_vectors_cnt;
	struct bh_handler *bh_worker;
	isr_ctx_t *isr_ctx;

	isr_ctx_head = &(c_dev->intr_info.isr_ctx_head);
	isr_ctx = list_entry(isr_ctx_head->next, isr_ctx_t, list);

	INIT_LIST_HEAD(&(isr_ctx->ring_list_head));

	/* Affine the ring to CPU & ISR */
	for (i = 0; i < c_dev->config.num_of_rps; i++) {
		while (!(wt_cpu_mask & (1 << core_no))) {
			core_no = cpumask_next(core_no, cpu_online_mask) % nr_cpu_ids;
		}

		print_debug("Ring no: %d Core no: %d\n", i, core_no);
		bh_worker = per_cpu_ptr(bh_workers, core_no);

		rp = &(c_dev->ring_pairs[i]);
		rp->core_no = core_no;
		rp->msi_addr_l = isr_ctx->msi_addr_low;
		rp->msi_addr_h = isr_ctx->msi_addr_high;
		rp->msi_data = isr_ctx->msi_data;

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

uint32_t ob_alloc(size_t size)
{
	static uint32_t addr;
	uint32_t save_addr;

	save_addr = cache_line_align(addr);
	addr = save_addr + size;

	return save_addr;
}

void calc_ob_mem_len(struct c29x_dev *c_dev, struct driver_ob_mem *obm)
{
	uint32_t total_ring_slots;
	struct c29x_cfg *config = &(c_dev->config);

	total_ring_slots = config->num_of_rps * config->ring_depth;

	obm->hs_mem = ob_alloc(sizeof(struct host_handshake_mem));
	obm->drv_resp_rings = ob_alloc(total_ring_slots *
					sizeof(struct resp_ring_entry));
	obm->idxs_mem = ob_alloc(config->num_of_rps *
					sizeof(struct ring_idxs_mem));
	obm->cntrs_mem = ob_alloc(config->num_of_rps *
					sizeof(struct ring_counters_mem));
	obm->r_s_cntrs_mem = ob_alloc(config->num_of_rps *
					sizeof(struct ring_counters_mem));
	obm->buf_pool = ob_alloc(config->num_of_rps * BUFFER_MEM_SIZE);

	obm->len = page_align(ob_alloc(0));
}

int32_t alloc_ob_mem(struct c29x_dev *c_dev)
{
	void *host_v_addr;
	struct driver_ob_mem obm;

	calc_ob_mem_len(c_dev, &obm);
	print_debug("Total ob mem returned: %d\n", obm.len);

	c_dev->drv_mem.len = obm.len;
	host_v_addr = dma_alloc_coherent(&(c_dev->dev->dev), c_dev->drv_mem.len,
					 &(c_dev->drv_mem.host_dma_addr),
					 GFP_KERNEL);
	if (!host_v_addr) {
		print_error("Allocating ob mem failed...\n");
		return -ENOMEM;
	}
	c_dev->drv_mem.host_v_addr = host_v_addr;
	c_dev->drv_mem.h_dma_offset = c_dev->drv_mem.host_v_addr -
			(void*)c_dev->drv_mem.host_dma_addr;
	c_dev->drv_mem.buf_pool_offset = obm.buf_pool;

	print_debug("OB Mem address	: %p\n", c_dev->drv_mem.host_v_addr);
	print_debug("OB Mem dma address	: %pad\n", &(c_dev->drv_mem.host_dma_addr));

	c_dev->hs_mem = host_v_addr + obm.hs_mem;
	c_dev->drv_resp_rings = host_v_addr + obm.drv_resp_rings;
	c_dev->idxs_mem = host_v_addr + obm.idxs_mem;
	c_dev->cntrs_mem = host_v_addr + obm.cntrs_mem;
	c_dev->r_s_cntrs_mem = host_v_addr + obm.r_s_cntrs_mem;

	print_debug("====== OB MEM POINTERS =======\n");
	print_debug("H HS Mem		: %p\n", c_dev->hs_mem);
	print_debug("Drv resp rings	: %p\n", c_dev->drv_resp_rings);
	print_debug("Idxs mem	        : %p\n", c_dev->idxs_mem);
	print_debug("cntrs mem          : %p\n", c_dev->cntrs_mem);
	print_debug("S C R cntrs mem	: %p\n", c_dev->r_s_cntrs_mem);

	return 0;
}

void init_handshake(struct c29x_dev *c_dev)
{
	dma_addr_t ob_mem = c_dev->drv_mem.host_dma_addr;

	/* Write our address to the firmware -
	 * It uses this to give it details when it is up */
	uint32_t l_val = (uint32_t) (ob_mem & PHYS_ADDR_L_32_BIT_MASK);
	uint32_t h_val = (ob_mem & PHYS_ADDR_H_32_BIT_MASK) >> 32;

	/* Reset driver handshake state so it loops until signaled by the
	 * device firmware */
	c_dev->hs_mem->state = DEFAULT;

	print_debug("C HS mem addr: %p\n", &(c_dev->c_hs_mem->h_ob_mem_l));
	print_debug("Host ob mem addr	L: %0x	H: %0x\n", l_val, h_val);

	/* First phase of communication:
	 * When the device is started it will want to know where to put things
	 * where the host driver will find them: host memory (at the base of
	 * which there is the host handshake area) and interrupt information
	 * (which will be given with each ring later during handshake)
	 */
	iowrite32be(l_val, (void *) &c_dev->c_hs_mem->h_ob_mem_l);
	iowrite32be(h_val, (void *) &c_dev->c_hs_mem->h_ob_mem_h);
}

void init_ring_pairs(struct c29x_dev *c_dev)
{
	fsl_h_rsrc_ring_pair_t *rp;
	uint32_t i;
	/* all response ring entries start here. Each ring has rp->depth entries */
	struct resp_ring_entry *resp_r = c_dev->drv_resp_rings;

	for (i = 0; i < c_dev->config.num_of_rps; i++) {
		rp = &(c_dev->ring_pairs[i]);

		rp->c_dev = c_dev;
		rp->depth = c_dev->config.ring_depth;

		rp->req_r = NULL;
		rp->resp_r = resp_r;
		resp_r += rp->depth;

		rp->intr_ctrl_flag = NULL;
		rp->indexes = &(c_dev->idxs_mem[i]);
		rp->counters = &(c_dev->cntrs_mem[i]);
		rp->r_s_cntrs = &(c_dev->r_s_cntrs_mem[i]);
		rp->r_s_c_cntrs = NULL;

		INIT_LIST_HEAD(&(rp->isr_ctx_list_node));
		INIT_LIST_HEAD(&(rp->bh_ctx_list_node));

		spin_lock_init(&(rp->ring_lock));
	}

}

void send_hs_init_config(struct c29x_dev *c_dev)
{
	struct c_config_data *config = &c_dev->c_hs_mem->data.config;

	iowrite8(c_dev->config.num_of_rps, &config->num_of_rps);
	iowrite32be((void*)c_dev->r_s_cntrs_mem - (void*)c_dev->hs_mem, &config->r_s_cntrs);

	print_debug("HS_INIT_CONFIG Details\n");
	print_debug("Num of ring pairs: %d\n", c_dev->config.num_of_rps);
	print_debug("Sending FW_INIT_CONFIG command at addr: %p\n",
			&(c_dev->c_hs_mem->state));
	barrier();
	iowrite8(FW_INIT_CONFIG, &c_dev->c_hs_mem->state);
}

void send_hs_init_ring_pair(struct c29x_dev *c_dev, uint8_t rid)
{
	uint32_t resp_r_offset;
	fsl_h_rsrc_ring_pair_t *rp = &(c_dev->ring_pairs[rid]);

	resp_r_offset = (void *)rp->resp_r - (void *)c_dev->drv_mem.host_v_addr;

	iowrite8(rid, &c_dev->c_hs_mem->data.ring.rid);
	iowrite16be(rp->msi_data, &c_dev->c_hs_mem->data.ring.msi_data);
	iowrite32be(rp->depth, &c_dev->c_hs_mem->data.ring.depth);
	iowrite32be(resp_r_offset, &c_dev->c_hs_mem->data.ring.resp_ring_offset);
	iowrite32be(rp->msi_addr_l, &c_dev->c_hs_mem->data.ring.msi_addr_l);
	iowrite32be(rp->msi_addr_h, &c_dev->c_hs_mem->data.ring.msi_addr_h);

	print_debug("HS_INIT_RING_PAIR Details\n");
	print_debug("Rid: %d\n", rid);
	print_debug("Depth: %d\n", rp->depth);
	print_debug("MSI Data: %x\n", rp->msi_data);
	print_debug("MSI Addr L: %x\n", rp->msi_addr_l);
	print_debug("MSI Addr H: %x\n", rp->msi_addr_h);

	barrier();
	iowrite8(FW_INIT_RING_PAIR, &c_dev->c_hs_mem->state);
}

void send_hs_complete(struct c29x_dev *c_dev)
{
	iowrite8(FW_HS_COMPLETE, &c_dev->c_hs_mem->state);
}

void send_hs_wait_for_rng(struct c29x_dev *c_dev)
{
	iowrite8(FW_WAIT_FOR_RNG, &c_dev->c_hs_mem->state);
}

void send_hs_rng_done(struct c29x_dev *c_dev)
{
	iowrite8(FW_RNG_DONE, &c_dev->c_hs_mem->state);
}

void hs_firmware_up(struct c29x_dev *c_dev)
{
	struct fw_up_data *hsdev = &c_dev->hs_mem->data.device;
	uint32_t p_ib_l;
	uint32_t p_ib_h;
	uint32_t p_pci_l;
	uint32_t p_pci_h;

	print_debug(" ----------- FIRMWARE_UP -----------\n");

	c_dev->hs_mem->state = DEFAULT;

	p_ib_l = be32_to_cpu(hsdev->p_ib_mem_base_l);
	p_ib_h = be32_to_cpu(hsdev->p_ib_mem_base_h);
	p_pci_l = be32_to_cpu(hsdev->p_pci_mem_l);
	p_pci_h = be32_to_cpu(hsdev->p_pci_mem_h);

	c_dev->bars[MEM_TYPE_SRAM].dev_p_addr = (dev_p_addr_t) p_ib_h << 32;
	c_dev->bars[MEM_TYPE_SRAM].dev_p_addr |= p_ib_l;

	c_dev->drv_mem.dev_pci_base = (dev_p_addr_t) p_pci_h << 32;
	c_dev->drv_mem.dev_pci_base |= p_pci_l;

	c_dev->drv_mem.d2h_offset = c_dev->drv_mem.h_dma_offset -
			c_dev->drv_mem.dev_pci_base;

	print_debug("Device Shared Details\n");
	print_debug("Ib mem PhyAddr L: %0x, H: %0x\n", p_ib_l, p_ib_h);
	print_debug("PCI mem PhyAddr L: %0x, H: %0x\n", p_pci_l, p_pci_h);
	print_debug("Formed dev ib mem phys address: %llx\n",
			(uint64_t)c_dev->bars[MEM_TYPE_SRAM].dev_p_addr);
	print_debug("Formed dev pci mem phys address: %llx\n",
			(uint64_t)c_dev->drv_mem.dev_pci_base);
}

void hs_fw_init_complete(struct c29x_dev *c_dev, uint8_t rid)
{
	struct config_data *hscfg = &c_dev->hs_mem->data.config;
	uint32_t r_s_c_cntrs;

	print_debug("--- FW_INIT_CONFIG_COMPLETE ---\n");

	c_dev->hs_mem->state = DEFAULT;

	r_s_c_cntrs = be32_to_cpu(hscfg->r_s_c_cntrs);

	c_dev->r_s_c_cntrs = c_dev->bars[MEM_TYPE_SRAM].host_v_addr + r_s_c_cntrs;

	print_debug(" ----- Details from firmware  -------\n");
	print_debug("SRAM H V ADDR: %p\n", c_dev->bars[MEM_TYPE_SRAM].host_v_addr);
	print_debug("R S C CNTRS OFFSET: %x\n", r_s_c_cntrs);
	print_debug("-----------------------------------\n");
	print_debug("R S C Cntrs: %p\n", c_dev->r_s_c_cntrs);
}

void hs_init_rp_complete(struct c29x_dev *c_dev, uint8_t rid)
{
	struct ring_data *hsring = &c_dev->hs_mem->data.ring;
	void *sram = c_dev->bars[MEM_TYPE_SRAM].host_v_addr;
	fsl_h_rsrc_ring_pair_t *rp = &(c_dev->ring_pairs[rid]);

	print_debug("---- FW_INIT_RING_PAIR_COMPLETE ----\n");

	c_dev->hs_mem->state = DEFAULT;

	rp->r_s_c_cntrs    = &(c_dev->r_s_c_cntrs[rid]);
	rp->req_r          = sram + be32_to_cpu(hsring->req_r);
	rp->intr_ctrl_flag = sram + be32_to_cpu(hsring->intr_ctrl_flag);

	print_debug("Ring id     : %d\n", rid);
	print_debug("Shadow cntrs: %p\n", rp->r_s_c_cntrs);
	print_debug("Req r       : %p\n", rp->req_r);
	print_debug("Interrupt   : %p\n", rp->intr_ctrl_flag);
}

int32_t handshake(struct c29x_dev *c_dev)
{
	uint8_t rid = 0;
	uint32_t timecntr = 0;

	while (true) {
		switch (c_dev->hs_mem->state) {
		case FIRMWARE_UP:
			/* This is the first thing communicated by the firmware:
			 * The device is UP and converted the MSI and OB_MEM
			 * addresses into device space.
			 */
			hs_firmware_up(c_dev);
			send_hs_init_config(c_dev);
			break;
		case FW_INIT_CONFIG_COMPLETE:
			hs_fw_init_complete(c_dev, rid);
			send_hs_init_ring_pair(c_dev, rid);
			break;
		case FW_INIT_RING_PAIR_COMPLETE:
			hs_init_rp_complete(c_dev, rid);
			rid++;
			if (rid < c_dev->config.num_of_rps) {
				send_hs_init_ring_pair(c_dev, rid);
			} else {
				send_hs_complete(c_dev);
			}
			break;
		case FW_INIT_RNG:
			send_hs_wait_for_rng(c_dev);
			if (rng_instantiation(c_dev)) {
				print_error("RNG Instantiation Failed!\n");
				goto error;
			}
			send_hs_rng_done(c_dev);
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
			print_error("Invalid state: %d\n", c_dev->hs_mem->state);
			goto error;
		}
	}
exit:
	return 0;

error:
	return -1;

}

#ifdef CHECK_EP_BOOTUP
static void check_ep_bootup(struct c29x_dev *c_dev)
{
	unsigned char *ibaddr = c_dev->bars[MEM_TYPE_SRAM].host_v_addr;
	unsigned char *obaddr = c_dev->drv_mem.host_v_addr;

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

static void setup_ep(struct c29x_dev *c_dev)
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
	void *ccsr = c_dev->bars[MEM_TYPE_CONFIG].host_v_addr;

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
	print_debug("Ob mem dma_addr: %pa\n", &(c_dev->drv_mem.host_dma_addr));
	print_debug("Ob mem dev_pci_base: %pa\n", &(c_dev->drv_mem.dev_pci_base));
	print_debug("Ob mem len: %pa\n", &c_dev->drv_mem.len);
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

static int32_t load_firmware(struct c29x_dev *c_dev)
{
	uint8_t byte;
	uint32_t i;
	void *fw_addr = c_dev->bars[MEM_TYPE_SRAM].host_v_addr +
				FIRMWARE_IMAGE_START_OFFSET;
	uint8_t *fw_file_path = c_dev->config.firmware;
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

void init_buf_pool(struct buffer_pool *buf_pool, struct host_mem_info *drv_mem,
		uint32_t offset)
{
	buf_pool->h_v_addr = drv_mem->host_v_addr + offset;
	buf_pool->h_dma_addr = drv_mem->host_dma_addr + offset;

	create_pool(buf_pool, BUFFER_MEM_SIZE);
}

int init_crypto_ctx_pool(struct c29x_dev *c_dev)
{
	int i, id;
	struct ctx_pool *pool;
	uint8_t nr_ctx_pools = c_dev->config.num_of_rps;
	ptrdiff_t offset = c_dev->drv_mem.buf_pool_offset;

	pool = kcalloc(nr_ctx_pools, sizeof(struct ctx_pool), GFP_KERNEL);
	if (pool == NULL) {
		return -ENOMEM;
	}

	/* save the address of the first context pool */
	c_dev->ctx_pool = pool;

	for (id = 0; id < nr_ctx_pools; id++) {
		for (i = 0; i < NUM_OF_CTXS - 1; i++) {
			pool->mem[i].next = &(pool->mem[i + 1]);
		}

		init_buf_pool(&(pool->buf_pool), &(c_dev->drv_mem), offset);
		offset += BUFFER_MEM_SIZE;

		pool->mem[i].next = NULL;
		pool->head = &pool->mem[0];
		spin_lock_init(&pool->ctx_lock);

		pool += 1;
	}
	return 0;
}

int32_t ring_enqueue(struct c29x_dev *c_dev, uint32_t jr_id,
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
		    &(rp->r_s_c_cntrs->jobs_added));
	rp->r_s_c_cntrs->jobs_added = be32_to_cpu(rp->counters->jobs_added);

	spin_unlock_bh(&(rp->ring_lock));
	return 0;
}

void stop_device(struct c29x_dev *c_dev)
{
	void *ccsr = c_dev->bars[MEM_TYPE_CONFIG].host_v_addr;
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

void start_device(struct c29x_dev *c_dev)
{
	void *ccsr = c_dev->bars[MEM_TYPE_CONFIG].host_v_addr;
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

int32_t fsl_crypto_layer_add_device(struct c29x_dev *c_dev)
{
	int err;
	struct c29x_cfg config = c_dev->config;

	c_dev->ring_pairs = kzalloc(sizeof(fsl_h_rsrc_ring_pair_t) *
				config.num_of_rps, GFP_KERNEL);
	if (!c_dev->ring_pairs)
		goto rp_fail;

	atomic_set(&(c_dev->crypto_dev_sess_cnt), 0);

	c_dev->c_hs_mem = c_dev->bars[MEM_TYPE_SRAM].host_v_addr + HS_MEM_OFFSET;

	print_debug("IB mem addr: %p\n", c_dev->bars[MEM_TYPE_SRAM].host_v_addr);
	print_debug("Device hs mem addr: %p\n", c_dev->c_hs_mem);

	err = alloc_ob_mem(c_dev);
	if (err) {
		print_error("Ob mem alloc failed....\n");
		goto ob_mem_fail;
	}

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
	distribute_rings(c_dev);
	print_debug("Distribute ring complete...\n");

	stop_device(c_dev);

	/* Set the EP registers correctly before booting... */
	setup_ep(c_dev);

	print_debug("Init Handshake....\n");
	init_handshake(c_dev);
	print_debug("Init Handshake complete...\n");

	err = load_firmware(c_dev);
	if (err) {
		print_error("Firmware download failed\n");
		goto error;
	}

	start_device(c_dev);

#ifdef CHECK_EP_BOOTUP
	check_ep_bootup(c_dev);
#endif

	err = handshake(c_dev);
	if (err) {
		print_error("Handshake failed\n");
		goto error;
	}

	printk(KERN_INFO "[FSL-CRYPTO-OFFLOAD-DRV] DevId:%d DEVICE IS UP\n",
	       c_dev->dev_no);

	return 0;

error:
	kfree(c_dev->ctx_pool);
ctx_pool_fail:
	pci_free_consistent(c_dev->dev,
			    c_dev->drv_mem.len,
			    c_dev->drv_mem.host_v_addr,
			    c_dev->drv_mem.host_dma_addr);
ob_mem_fail:
	kfree(c_dev->ring_pairs);
rp_fail:
	return -ENODEV;
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

void cleanup_crypto_device(struct c29x_dev *c_dev)
{
	if (NULL == c_dev)
		return;

	kfree(c_dev->ctx_pool);

	if (c_dev->drv_mem.host_v_addr) {
		pci_free_consistent(c_dev->dev,
				    c_dev->drv_mem.len,
				    c_dev->drv_mem.host_v_addr,
				    c_dev->drv_mem.host_dma_addr);
	}

	clear_ring_lists();
	kfree(c_dev->ring_pairs);
}

void handle_response(struct c29x_dev *c_dev, uint64_t desc, int32_t res)
{
	void *h_desc;
	struct crypto_op_ctx *ctx0;

	/* convert descriptor address from device space to host space to
	 * recover its associated context. We practically do the operations
	 * from host_to_dev in reverse:
	 * 	h_dma_addr = desc - c_dev->drv_mem.dev_pci_base;
	 * 	offset = h_dma_addr - c_dev->buf_pool[0].h_dma_addr;
	 * 	h_desc = c_dev->buf_pool[0].h_v_addr + offset;
	 */

	h_desc = (void*)(desc + c_dev->drv_mem.d2h_offset);
	ctx0 = (struct crypto_op_ctx *) get_priv_data(h_desc);
	if (ctx0) {
		ctx0->op_done(ctx0, res);
	} else {
		print_debug("NULL Context!!\n");
	}

	return;
}

/* FIXME: function argument dev is overwritten in the first loop */
void process_response(struct c29x_dev *c_dev, fsl_h_rsrc_ring_pair_t *ring_cursor)
{
	uint32_t pollcount;
	uint32_t jobs_added;
	uint32_t resp_cnt;
	uint32_t ri;
	uint64_t desc;
	uint32_t res;
	struct device *my_dev = &c_dev->dev->dev;

	pollcount = 0;

	while (pollcount++ < napi_poll_count) {
		jobs_added = be32_to_cpu(ring_cursor->r_s_cntrs->jobs_added);
		resp_cnt = jobs_added - ring_cursor->counters->jobs_processed;
		if (!resp_cnt)
			continue;

		c_dev = ring_cursor->c_dev;
		ri = ring_cursor->indexes->r_index;
		print_debug("GOT INTERRUPT FROM DEV: %d\n", c_dev->dev_no);

		while (resp_cnt) {
			desc = be64_to_cpu(ring_cursor->resp_r[ri].sec_desc);
			res = be32_to_cpu(ring_cursor->resp_r[ri].result);
			{
				print_debug("APP RING GOT AN INTERRUPT\n");
				if (desc != 0) {
					handle_response(c_dev, desc, res);
				} else {
					dev_err(my_dev, "INVALID DESC AT RI : %u\n", ri);
				}
				if (res != 0) {
					sec_jr_strstatus(my_dev, res);
				}
			}
			ring_cursor->counters->jobs_processed += 1;
			iowrite32be(ring_cursor->counters->jobs_processed,
				&ring_cursor->r_s_c_cntrs->jobs_processed);

			ri = (ri + 1) % (ring_cursor->depth);
			ring_cursor->indexes->r_index = ri;
			--resp_cnt;
		}
	}
	/* Enable the intrs for this ring */
	*(ring_cursor->intr_ctrl_flag) = 0;
}

int32_t process_rings(struct c29x_dev *c_dev,
			 struct list_head *ring_list_head)
{
	fsl_h_rsrc_ring_pair_t *ring_cursor = NULL;

	print_debug("---------------- PROCESSING RESPONSE ------------------\n");

	list_for_each_entry(ring_cursor, ring_list_head, bh_ctx_list_node) {
		process_response(c_dev, ring_cursor);
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
	struct c29x_dev *c_dev;

	if (unlikely(NULL == bh)) {
		print_error("No bottom half handler found for the work\n");
		return;
	}

	c_dev = bh->c_dev;	/* get_crypto_dev(1); */
	print_debug("GOT INTERRUPT FROM DEV : %d\n", c_dev->dev_no);
	print_debug("Worker thread invoked on cpu [%d]\n", bh->core_no);
	process_rings(c_dev, &(bh->ring_list_head));
	return;
}
