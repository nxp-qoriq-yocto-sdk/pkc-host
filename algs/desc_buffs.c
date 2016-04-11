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
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "desc_buffs.h"
#include "pkc_desc.h"

extern struct c29x_dev *g_fsl_pci_dev;

static void distribute_buffers(crypto_mem_info_t *mem_info, uint8_t *mem)
{
	uint32_t i;
	buffer_info_t *buffers = mem_info->buffers;

	for (i = 0; i < mem_info->count; i++) {
		switch (buffers[i].bt) {
		case BT_DESC:
			buffers[i].h_v_addr = mem;
			mem += ALIGN_LEN_TO_DMA(buffers[i].len);
			break;
		case BT_IP:
			if (!mem_info->split_ip) {
				buffers[i].h_v_addr = mem;
				mem += ALIGN_LEN_TO_DMA(buffers[i].len);
			}
			break;
		case BT_OP:
			break;
		}
	}
	return;
}

int32_t alloc_crypto_mem(crypto_mem_info_t *mem_info)
{
	uint32_t i;
	uint32_t tot_mem = 0;
	uint32_t aligned_len;
	uint8_t *mem;
	buffer_info_t *buffers = mem_info->buffers;

	/* The structure will have all the memory requirements */
	for (i = 0; i < mem_info->count; i++) {
		aligned_len = ALIGN_LEN_TO_DMA(buffers[i].len);
		switch (buffers[i].bt) {
		case BT_DESC:
			tot_mem += aligned_len;
			break;
		case BT_IP:
			if (mem_info->split_ip) {
				buffers[i].h_v_addr = alloc_buffer(mem_info->buf_pool,
								aligned_len, 1);
				if (unlikely(!buffers[i].h_v_addr)) {
					print_error("Alloc mem for buff :%d type :%d failed\n",
						     i, buffers[i].bt);
					goto error;
				}
				mem_info->sg_cnt++;
			} else {
				tot_mem += aligned_len;
			}
			break;
		case BT_OP:
			break;
		}
	}

	mem = alloc_buffer(mem_info->buf_pool, tot_mem, 1);
	if (!mem)
		goto no_mem;

	mem_info->sg_cnt++;
	mem_info->src_buff = mem;
	mem_info->alloc_len = tot_mem;
	distribute_buffers(mem_info, mem);

	return 0;

no_mem:
	if (!mem_info->split_ip) {
		return -ENOMEM;
	}
error:
	while (i--) {
		if (buffers[i].bt == BT_IP) {
			free_buffer(mem_info->buf_pool, buffers[i].h_v_addr);
			mem_info->sg_cnt--;
		}
	}
	return -ENOMEM;
}


int32_t dealloc_crypto_mem(crypto_mem_info_t *mem_info)
{
	struct c29x_dev *pci_dev = mem_info->dev->priv_dev;
	buffer_info_t *buffers = mem_info->buffers;
	uint32_t i = 0;

	if (buffers[0].h_v_addr) {
		free_buffer(mem_info->buf_pool, buffers[0].h_v_addr);
	}

	for (i = 1; i < mem_info->count; i++) {
		switch (buffers[i].bt) {
		case BT_IP:
			if (mem_info->split_ip && buffers[i].h_v_addr) {
				free_buffer(mem_info->buf_pool, buffers[i].h_v_addr);
			}
			break;
		case BT_OP:
			if (buffers[i].h_dma_addr) {
				pci_unmap_single(pci_dev->dev,
						buffers[i].h_dma_addr,
						buffers[i].len,
						PCI_DMA_BIDIRECTIONAL);
			}
		default:
			break;
		}
	}

	return 0;
}

void host_to_dev(crypto_mem_info_t *mem_info)
{
	uint32_t i;
	buffer_info_t *buffers = mem_info->buffers;
	struct fsl_crypto_dev *c_dev = mem_info->dev;
	struct pci_dev *dev = c_dev->priv_dev->dev;
	struct pci_bar_info *bars = c_dev->priv_dev->bars;
	uint64_t offset;

	for (i = 0; i < mem_info->count; i++) {
		buffers[i].h_p_addr = __pa(buffers[i].h_v_addr);

		switch (buffers[i].bt) {
		case BT_DESC:
		case BT_IP:
			buffers[i].h_dma_addr = buffers[i].h_p_addr;
			offset = buffers[i].h_v_addr - c_dev->host_ip_pool.h_v_addr;
			buffers[i].d_v_addr = c_dev->dev_ip_pool.h_v_addr + offset;
			buffers[i].d_p_addr = c_dev->dev_ip_pool.d_p_addr + offset;
			break;
		case BT_OP:
			buffers[i].h_dma_addr = pci_map_single(dev,
					buffers[i].h_v_addr, buffers[i].len,
					PCI_DMA_BIDIRECTIONAL);
			buffers[i].d_p_addr = buffers[i].h_dma_addr +
					bars[MEM_TYPE_DRIVER].dev_p_addr;
			break;
		}
	}
}

int32_t map_crypto_mem(crypto_mem_info_t *crypto_mem) {
	int32_t i;
	buffer_info_t *buffers;

	if (!crypto_mem) {
		return -1;
	}

	buffers = crypto_mem->buffers;
	for (i = 0; i < crypto_mem->count; i++) {
		if (buffers[i].bt != BT_IP) {
			continue;
		}

		buffers[i].h_p_addr = (phys_addr_t)pci_map_single(
			g_fsl_pci_dev->dev, buffers[i].req_ptr, buffers[i].len,
			PCI_DMA_BIDIRECTIONAL);
	}

	return 0;
}

int32_t unmap_crypto_mem(crypto_mem_info_t *crypto_mem) {
	int32_t i;
	buffer_info_t *buffers;

	if (!crypto_mem) {
		return -1;
	}

	buffers = crypto_mem->buffers;
	for (i = 0; i < crypto_mem->count; i++) {
		if (buffers[i].bt != BT_IP) {
			continue;
		}

		pci_unmap_single(g_fsl_pci_dev->dev,
			(dma_addr_t)buffers[i].h_p_addr, buffers[i].len,
			PCI_DMA_BIDIRECTIONAL);
	}

	return 0;
}

int32_t memcpy_to_dev(crypto_mem_info_t *mem)
{
	uint32_t i = 0;
	buffer_info_t *buffers = mem->buffers;

	/* This function will take care of endian conversions across pcie */
	for (i = 0; i < (mem->count); i++) {
		switch (buffers[i].bt) {
		case BT_DESC:
			memcpy(buffers[i].d_v_addr, buffers[i].h_v_addr, buffers[i].len);
			break;
		case BT_IP:
		case BT_OP:
			break;
		}
	}

	return 0;
}
