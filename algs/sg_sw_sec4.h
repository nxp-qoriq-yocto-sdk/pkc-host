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

#ifndef __SG_SW_SEC4_H__
#define __SG_SW_SEC4_H__

#include"common.h"
#include "memmgr.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#ifdef VIRTIO_C2X0
#include <crypto/scatterwalk.h>
#endif
struct sec4_sg_entry;

static inline void sg_map_copy(u8 *dest, struct scatterlist *sg,
			       int len, int offset)
{
	u8 *mapped_addr;

	/*
	 * Page here can be user-space pinned using get_user_pages
	 * Same must be kmapped before use and kunmapped subsequently
	 */
	mapped_addr = kmap(sg_page(sg));
	memcpy(dest, mapped_addr + offset, len);
	kunmap(sg_page(sg));
}

/*
 * convert single dma address to h/w link table format
 */
static inline void dev_dma_to_sec4_sg_one(struct sec4_sg_entry *sec4_sg_ptr,
					  dev_dma_addr_t dma, u32 len,
					  u16 offset)
{
	ASSIGN64(sec4_sg_ptr->ptr, dma);
	ASSIGN32(sec4_sg_ptr->len, len);
	iowrite8(0, &sec4_sg_ptr->reserved);
	iowrite8(0, &sec4_sg_ptr->buf_pool_id);
	iowrite16be(offset, &sec4_sg_ptr->offset);
}

/* count number of elements in scatterlist */
static inline int __sg_count(struct scatterlist *sg_list, int nbytes,
			     bool *chained)
{
	struct scatterlist *sg = sg_list;
	int sg_nents = 0;

	while (nbytes > 0) {
		sg_nents++;
		nbytes -= sg->length;
		if (!sg_is_last(sg) && (sg + 1)->length == 0)
			*chained = true;
		sg = scatterwalk_sg_next(sg);
	}

	return sg_nents;
}

/* derive number of elements in scatterlist, but return 0 for 1 */
static inline int sg_count(struct scatterlist *sg_list, int nbytes,
			   bool *chained)
{
	int sg_nents = __sg_count(sg_list, nbytes, chained);

	if (likely(sg_nents == 1))
		return 0;

	return sg_nents;
}

static inline int dma_map_sg_chained(struct device *dev, struct scatterlist *sg,
				     unsigned int nents,
				     enum dma_data_direction dir, bool chained)
{
	if (unlikely(chained)) {
		int i;
		for (i = 0; i < nents; i++) {
			dma_map_sg(dev, sg, 1, dir);
			sg = scatterwalk_sg_next(sg);
		}
	} else {
		dma_map_sg(dev, sg, nents, dir);
	}
	return nents;
}

static inline int dma_unmap_sg_chained(struct device *dev,
				       struct scatterlist *sg,
				       unsigned int nents,
				       enum dma_data_direction dir,
				       bool chained)
{
	if (unlikely(chained)) {
		int i;
		for (i = 0; i < nents; i++) {
			dma_unmap_sg(dev, sg, 1, dir);
			sg = scatterwalk_sg_next(sg);
		}
	} else {
		dma_unmap_sg(dev, sg, nents, dir);
	}
	return nents;
}

/* FIXME: remove these functions. See kernel patch d45f6546907e3eb870a3f176181278b8d2b1aebb */
/* Copy from len bytes of sg to dest, starting from beginning */
static inline void sg_copy(u8 *dest, struct scatterlist *sg, unsigned int len)
{
	struct scatterlist *current_sg = sg;
	int cpy_index = 0, next_cpy_index = current_sg->length;

	while (next_cpy_index < len) {
		/*      memcpy(dest + cpy_index, (u8 *) sg_virt(current_sg),
		   current_sg->length); */

		sg_map_copy(dest + cpy_index, current_sg, current_sg->length,
			    current_sg->offset);
		current_sg = scatterwalk_sg_next(current_sg);
		cpy_index = next_cpy_index;
		next_cpy_index += current_sg->length;
	}
	if (cpy_index < len)
		/*memcpy(dest + cpy_index, (u8 *) sg_virt(current_sg),
		   len - cpy_index); */
		sg_map_copy(dest + cpy_index, current_sg, len - cpy_index,
			    current_sg->offset);
}

/* Copy sg data, from to_skip to end, to dest */
static inline void sg_copy_part(u8 *dest, struct scatterlist *sg,
				int to_skip, unsigned int end)
{
	struct scatterlist *current_sg = sg;
	/*int sg_index, cpy_index; */
	int sg_index, cpy_index, offset;

	sg_index = current_sg->length;
	while (sg_index <= to_skip) {
		current_sg = scatterwalk_sg_next(current_sg);
		sg_index += current_sg->length;
	}
	cpy_index = sg_index - to_skip;
	/*memcpy(dest, (u8 *) sg_virt(current_sg) +
	   current_sg->length - cpy_index, cpy_index);
	   current_sg = scatterwalk_sg_next(current_sg);
	   if (end - sg_index) */
	offset = current_sg->offset + current_sg->length - cpy_index;
	sg_map_copy(dest, current_sg, cpy_index, offset);
	if (end - sg_index) {
		current_sg = scatterwalk_sg_next(current_sg);
		sg_copy(dest + cpy_index, current_sg, end - sg_index);
	}
}

#endif
