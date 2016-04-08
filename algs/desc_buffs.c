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
			buffers[i].h_v_addr = mem;
			mem += ALIGN_LEN_TO_DMA(buffers[i].len);
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
			tot_mem += aligned_len;
			break;
		case BT_OP:
			break;
		}
	}

	mem = alloc_buffer(mem_info->buf_pool, tot_mem, 1);
	if (!mem)
		goto no_mem;

	mem_info->src_buff = mem;
	mem_info->alloc_len = tot_mem;
	distribute_buffers(mem_info, mem);
	return 0;

no_mem:
	return -ENOMEM;
}


int32_t dealloc_crypto_mem(crypto_mem_info_t *mem_info)
{
	struct c29x_dev *pci_dev = mem_info->dev->priv_dev;
	buffer_info_t *buffers = mem_info->buffers;
	uint32_t i = 0;

	for (i = 1; i < mem_info->count; i++) {
		switch (buffers[i].bt) {
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

	free_buffer(mem_info->buf_pool, mem_info->src_buff);
	return 0;
}

void host_to_dev(crypto_mem_info_t *mem_info)
{
	uint32_t i;
	buffer_info_t *buffers = mem_info->buffers;
	struct fsl_crypto_dev *c_dev = mem_info->dev;
	struct pci_dev *dev = c_dev->priv_dev->dev;
	struct pci_bar_info *bars = c_dev->priv_dev->bars;

	for (i = 0; i < mem_info->count; i++) {
		switch (buffers[i].bt) {
		case BT_DESC:
			buffers[i].h_dma_addr = c_dev->host_ip_pool.h_dma_addr +
				(buffers[i].h_v_addr - c_dev->host_ip_pool.h_v_addr);
			break;
		case BT_IP:
			buffers[i].h_dma_addr = pci_map_single(dev,
					buffers[i].req_ptr, buffers[i].len,
					PCI_DMA_BIDIRECTIONAL);
			break;
		case BT_OP:
			buffers[i].h_dma_addr = pci_map_single(dev,
					buffers[i].h_v_addr, buffers[i].len,
					PCI_DMA_BIDIRECTIONAL);
			break;
		}
		buffers[i].d_p_addr = bars[MEM_TYPE_DRIVER].dev_p_addr +
					buffers[i].h_dma_addr;
	}
}

int32_t unmap_crypto_mem(crypto_mem_info_t *crypto_mem) {
	int32_t i;
	buffer_info_t *buffers;
	struct pci_dev *dev = crypto_mem->dev->priv_dev->dev;

	if (!crypto_mem) {
		return -1;
	}

	buffers = crypto_mem->buffers;
	for (i = 0; i < crypto_mem->count; i++) {
		if (buffers[i].bt != BT_IP) {
			continue;
		}
		pci_unmap_single(dev, buffers[i].h_dma_addr, buffers[i].len,
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
