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
#include "desc_cnstr.h"
#include "pkc_desc.h"
#include "memmgr.h"

/* FIXME: code depending on OP_BUFFER_IN_DEV_MEM is wrapped by #if 0 */
#undef OP_BUFFER_IN_DEV_MEM

#ifdef SEC_DMA
extern fsl_pci_dev_t *g_fsl_pci_dev;
#endif

static void distribute_buffers(crypto_mem_info_t *mem_info, uint8_t *mem)
{
	uint32_t i;
	buffer_info_t *buffers = (buffer_info_t *) &mem_info->c_buffers;

	for (i = 0; i < mem_info->count; i++) {
		switch (buffers[i].bt) {
		case BT_DESC:
			buffers[i].v_mem = mem;
			mem += ALIGN_LEN_TO_DMA(buffers[i].len);
			break;
		case BT_IP:
			if (!mem_info->split_ip) {
				buffers[i].v_mem = mem;
				mem += ALIGN_LEN_TO_DMA(buffers[i].len);
			}
			break;
		case BT_OP:
#ifdef OP_BUFFER_IN_DEV_MEM
			buffers[i].v_mem = mem;
			mem += ALIGN_LEN_TO_DMA(buffers[i].len);
#endif
			break;
		}
	}
	return;
}

/******************************************************************************
Description :	Allocates device memory as specified in the given structure
				crypto_mem_info_t.    
Fields      :   
			mem_info	:	Contains all the information needed to allocate 
							the memory (like, how much memory needed, how
							many buffers need memory etc).   
Returns		:	SUCCESS/FAILURE
******************************************************************************/

int32_t alloc_crypto_mem(crypto_mem_info_t *mem_info)
{
	uint32_t i;
	uint32_t tot_mem = 0;
	uint32_t aligned_len;
	uint8_t *mem;
	buffer_info_t *buffers = (buffer_info_t *) &mem_info->c_buffers;

	/* The structure will have all the memory requirements */
	for (i = 0; i < mem_info->count; i++) {
		aligned_len = ALIGN_LEN_TO_DMA(buffers[i].len);
		switch (buffers[i].bt) {
		case BT_DESC:
			tot_mem += aligned_len;
			break;
		case BT_IP:
			if (mem_info->split_ip) {
				buffers[i].v_mem = alloc_buffer(mem_info->pool,
								aligned_len, 1);
				if (unlikely(!buffers[i].v_mem)) {
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
#ifdef OP_BUFFER_IN_DEV_MEM
			tot_mem += aligned_len;
#endif
			break;
		}
	}

	mem = alloc_buffer(mem_info->pool, tot_mem, 1);
	if (!mem)
		goto no_mem;

	mem_info->sg_cnt++;
	mem_info->src_buff = mem;
	mem_info->alloc_len = tot_mem;
	distribute_buffers(mem_info, mem);

	return 0;

no_mem:
	if (!mem_info->split_ip)
		return -ENOMEM;
error:
	while (i--) {
		if (buffers[i].bt == BT_IP) {
			free_buffer(mem_info->pool, buffers[i].v_mem);
			mem_info->sg_cnt--;
		}
	}
	return -ENOMEM;
}

/******************************************************************************
Description :	Deallocates the device memory from the structure
				crypto_mem_info_t.   
Fields      :
			mem_info	:	Contains all the information needed to deallocate 
							the memory (like, how much memory needed, how
							many buffers need memory etc).   
Returns     :	SUCCESS/FAILURE
******************************************************************************/

int32_t dealloc_crypto_mem(crypto_mem_info_t *mem_info)
{
	fsl_pci_dev_t *pci_dev = mem_info->dev->priv_dev;
	buffer_info_t *buffers = (buffer_info_t *) &mem_info->c_buffers;
	uint32_t i = 0;

	if (buffers[0].v_mem)
		free_buffer(mem_info->pool, buffers[0].v_mem);

	for (i = 1; i < mem_info->count; i++) {
		switch (buffers[i].bt) {
		case BT_IP:
			if (mem_info->split_ip && buffers[i].v_mem)
				free_buffer(mem_info->pool, buffers[i].v_mem);
			break;
		case BT_OP:
			if (buffers[i].dev_buffer.h_dma_addr)
				pci_unmap_single(pci_dev->dev, buffers[i].dev_buffer.
						 h_dma_addr, buffers[i].len,
						 PCI_DMA_BIDIRECTIONAL);
		default:
			break;
		}
	}

#if 0
#ifdef OP_BUFFER_IN_DEV_MEM
	for (i = 0; i < mem_info->count; i++) {
		if (BT_OP == mem_info->buffers[i].bt)
			free_buffer(mem_info->pool, mem_info->buffers[i].v_mem);
	}
#endif
#endif
	return 0;
}

static inline dev_dma_addr_t desc_d_p_addr(fsl_crypto_dev_t *dev, void *h_v_addr)
{
	unsigned long offset = h_v_addr - dev->ip_pool.drv_map_pool.v_addr;
	return dev->ip_pool.fw_pool.dev_p_addr + offset;
}

static inline void *desc_d_v_addr(fsl_crypto_dev_t *dev, void *h_v_addr)
{
	unsigned long offset = h_v_addr - dev->ip_pool.drv_map_pool.v_addr;
	return dev->ip_pool.fw_pool.host_map_v_addr + offset;
}

static inline dma_addr_t
op_buf_h_dma_addr(fsl_crypto_dev_t *crypto_dev, void *h_v_addr, uint32_t len)
{
	struct pci_dev *dev = crypto_dev->priv_dev->dev;
	return pci_map_single(dev, h_v_addr, len, PCI_DMA_BIDIRECTIONAL);
}

static inline dev_dma_addr_t op_buf_d_dma_addr(fsl_crypto_dev_t *dev,
					       dma_addr_t h_dma_addr)
{
	dev_dma_addr_t d_dma = (dev_dma_addr_t) h_dma_addr;
	return d_dma + dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
}

static phys_addr_t h_map_p_addr(fsl_crypto_dev_t *dev, void *h_v_addr)
{
	unsigned long offset = h_v_addr - dev->ip_pool.drv_map_pool.v_addr;
	return dev->ip_pool.fw_pool.host_map_p_addr + offset;
}

/******************************************************************************
Description :	Calculate all the related addresses from the device memory
				allocated.   
Fields      :   
			mem_info	:	The data structure which contains all the
							information related to the device memory allocated
							for any particular job.
Returns     :	SUCCESS/ FAILURE
******************************************************************************/

void host_to_dev(crypto_mem_info_t *mem_info)
{
	uint32_t i;
	buffer_info_t *buffers = (buffer_info_t *) &mem_info->c_buffers;

	for (i = 0; i < mem_info->count; i++) {
		buffers[i].dev_buffer.h_v_addr = buffers[i].v_mem;
		buffers[i].dev_buffer.h_p_addr = __pa(buffers[i].dev_buffer.h_v_addr);

		switch (buffers[i].bt) {
		case BT_DESC:
		case BT_IP:
			buffers[i].dev_buffer.h_dma_addr = buffers[i].dev_buffer.h_p_addr;
			buffers[i].dev_buffer.h_map_p_addr = h_map_p_addr(mem_info->dev, buffers[i].v_mem);

			buffers[i].dev_buffer.d_v_addr = desc_d_v_addr(mem_info->dev, buffers[i].v_mem);
			buffers[i].dev_buffer.d_p_addr = desc_d_p_addr(mem_info->dev, buffers[i].v_mem);
			break;

		case BT_OP:
#ifndef OP_BUFFER_IN_DEV_MEM
			buffers[i].dev_buffer.h_dma_addr = op_buf_h_dma_addr(mem_info->dev,
					buffers[i].v_mem, buffers[i].len);
			buffers[i].dev_buffer.d_p_addr = op_buf_d_dma_addr(mem_info->dev,
					      buffers[i].dev_buffer.h_dma_addr);
#else
			buffers[i].dev_buffer.h_dma_addr = buffers[i].dev_buffer.h_p_addr;
			buffers[i].dev_buffer.d_v_addr = desc_d_v_addr(mem_info->dev, buffers[i].v_mem);
			buffers[i].dev_buffer.d_p_addr = desc_d_p_addr(mem_info->dev, buffers[i].v_mem);
#endif
			break;

		}
	}
}

#ifdef SEC_DMA
/**
 * Map Crypto Memory.
 *
 * @param  crypto_mem crypto memory
 * @return            error code
 *                    0:  success
 *                    -1: failure
 */
int32_t map_crypto_mem(crypto_mem_info_t *crypto_mem) {
	int32_t i;
	buffer_info_t *buffers = (buffer_info_t *) &crypto_mem->c_buffers;

	if (!crypto_mem)
		return -1;

	for (i = 0; i < crypto_mem->count; i++) {
		if (buffers[i].bt != BT_IP)
			continue;

		buffers[i].dev_buffer.h_p_addr = (phys_addr_t)pci_map_single(
			g_fsl_pci_dev->dev, buffers[i].req_ptr, buffers[i].len,
			PCI_DMA_BIDIRECTIONAL);
	}

	return 0;
}


/**
 * Unmap Crypto Memory.
 *
 * @param  crypto_mem crypto memory
 * @return            error code
 *                    0:  success
 *                    -1: failure
 */
int32_t unmap_crypto_mem(crypto_mem_info_t *crypto_mem) {
	int32_t i;
	buffer_info_t *buffers = (buffer_info_t *) &crypto_mem->c_buffers;

	if (!crypto_mem)
		return -1;

	for (i = 0; i < crypto_mem->count; i++) {
		if (buffers[i].bt != BT_IP)
			continue;

		pci_unmap_single(g_fsl_pci_dev->dev,
			(dma_addr_t)buffers[i].dev_buffer.h_p_addr, buffers[i].len,
			PCI_DMA_BIDIRECTIONAL);
	}

	return 0;
}
#endif

/******************************************************************************
Description : Copy the data from host memory to device memory.   
Fields      :   
			mem	:	The data structure which contains all the
					information related to the device memory allocated
					for any particular job.	
Returns     :	SUCCESS/ FAILURE
******************************************************************************/

int32_t memcpy_to_dev(crypto_mem_info_t *mem)
{
	uint32_t i = 0;
	buffer_info_t *src;
	buffer_info_t *buffers = (buffer_info_t *) &mem->c_buffers;
	dev_buffer_t *dst;

	/* This function will take care of endian conversions across pcie */
	for (i = 0; i < (mem->count); i++) {
		src = &buffers[i];
		dst = &buffers[i].dev_buffer;
		switch (src->bt) {
		case BT_DESC:
			memcpy((void *)dst->d_v_addr, src->v_mem, src->len);
			break;
		case BT_IP:
			memcpy((void *)dst->d_v_addr, src->req_ptr, src->len);
		case BT_OP:
			break;
		}
	}

	return 0;
}
