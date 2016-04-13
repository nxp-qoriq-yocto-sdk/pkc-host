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

#include <linux/crypto.h>

#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "dsa.h"
#include "pkc_desc.h"
#include "desc.h"
#include "crypto_ctx.h"
#ifdef VIRTIO_C2X0
#include "fsl_c2x0_virtio.h"
#endif

/* Callback test functions */
typedef void (*dsa_op_cb) (struct pkc_request *, int32_t result);
dsa_op_cb dsa_completion_cb;
dsa_op_cb ecdsa_completion_cb;

static void dsa_op_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[DSA OP DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));

#ifndef VIRTIO_C2X0
	dsa_completion_cb(crypto_ctx->req.pkc, res);

	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
#endif
#ifdef VIRTIO_C2X0
	/* Update the sec result to crypto job context */
	crypto_ctx->card_status = res;
	print_debug("Updated card status to %d\n", crypto_ctx->card_status);
#endif
}

static void ecdsa_op_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[ECDSA OP DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));

#ifndef VIRTIO_C2X0
	ecdsa_completion_cb(crypto_ctx->req.pkc, res);

	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
#endif
#ifdef VIRTIO_C2X0
	/* Update the sec result to crypto job context */
	crypto_ctx->card_status = res;
	print_debug("Updated card status to %d\n", crypto_ctx->card_status);
#endif
}

/* Memory copy functions */
static void dsa_sign_init_len(struct dsa_sign_req_s *req,
			      crypto_mem_info_t *mem_info, bool ecdsa)
{
	dsa_sign_buffers_t *mem = &(mem_info->c_buffers.dsa_sign);

	mem->q_buff.len = req->q_len;
	mem->r_buff.len = req->r_len;
	mem->g_buff.len = req->g_len;
	mem->priv_key_buff.len = req->priv_key_len;
	mem->m_buff.len = req->m_len;
	mem->c_buff.len = req->d_len;
	mem->d_buff.len = req->d_len;
	mem->tmp_buff.len = 2 * req->d_len;

	if (ecdsa) {
		mem->ab_buff.len = req->ab_len;
		mem->desc_buff.len = sizeof(struct ecdsa_sign_desc_s);
	} else {
		mem->ab_buff.len = 0;
		mem->desc_buff.len = sizeof(struct dsa_sign_desc_s);
	}
}

static void dsa_verify_init_len(struct dsa_verify_req_s *req,
				crypto_mem_info_t *mem_info, bool ecdsa)
{
	dsa_verify_buffers_t *mem = &(mem_info->c_buffers.dsa_verify);

	mem->q_buff.len = req->q_len;
	mem->r_buff.len = req->r_len;
	mem->g_buff.len = req->g_len;
	mem->pub_key_buff.len = req->pub_key_len;
	mem->m_buff.len = req->m_len;
	mem->c_buff.len = req->d_len;
	mem->d_buff.len = req->d_len;
	if (ecdsa) {
		mem->tmp_buff.len = 2 * req->q_len;
		mem->ab_buff.len = req->ab_len;
		mem->desc_buff.len = sizeof(struct ecdsa_verify_desc_s);
	} else {
		mem->tmp_buff.len = req->q_len;
		mem->ab_buff.len = 0;
		mem->desc_buff.len = sizeof(struct dsa_verify_desc_s);
	}
}

static void dsa_keygen_init_len(struct dsa_keygen_req_s *req,
				crypto_mem_info_t *mem_info, bool ecdsa)
{
	dsa_keygen_buffers_t *mem = &(mem_info->c_buffers.dsa_keygen);

	mem->q_buff.len = req->q_len;
	mem->r_buff.len = req->r_len;
	mem->g_buff.len = req->g_len;
	mem->prvkey_buff.len = req->prvkey_len;
	mem->pubkey_buff.len = req->pubkey_len;

	if (ecdsa) {
		mem->ab_buff.len = req->ab_len;
		mem->desc_buff.len = sizeof(struct ecdsa_keygen_desc_s);
	} else {
		mem->ab_buff.len = 0;
		mem->desc_buff.len = sizeof(struct dsa_keygen_desc_s);
	}
}

static int dsa_sign_cp_req(struct dsa_sign_req_s *req,
			   crypto_mem_info_t *mem_info, bool ecdsa)
{
	dsa_sign_buffers_t *mem = &(mem_info->c_buffers.dsa_sign);
	dsa_sign_init_len(req, mem_info, ecdsa);

	print_debug("Calling alloc_crypto_mem\n");
	mem_info->buffers = (buffer_info_t *) mem;
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

#ifdef USE_HOST_DMA
	memcpy(mem->q_buff.h_v_addr, req->q, mem->q_buff.len);
	memcpy(mem->r_buff.h_v_addr, req->r, mem->r_buff.len);
	memcpy(mem->g_buff.h_v_addr, req->g, mem->g_buff.len);
	memcpy(mem->priv_key_buff.h_v_addr, req->priv_key, mem->priv_key_buff.len);
	memcpy(mem->m_buff.h_v_addr, req->m, mem->m_buff.len);

	if (ecdsa)
		memcpy(mem->ab_buff.h_v_addr, req->ab, mem->ab_buff.len);
	else
		mem->ab_buff.h_v_addr = NULL;
#else
	mem->q_buff.req_ptr = req->q;
	mem->r_buff.req_ptr = req->r;
	mem->g_buff.req_ptr = req->g;
	mem->priv_key_buff.req_ptr = req->priv_key;
	mem->m_buff.req_ptr = req->m;
	mem->tmp_buff.req_ptr = mem->tmp_buff.h_v_addr;

	if (ecdsa) {
		mem->ab_buff.req_ptr = req->ab;
	} else {
		mem->ab_buff.req_ptr = NULL;
	}
#endif
	mem->c_buff.h_v_addr = req->c;
	mem->d_buff.h_v_addr = req->d;

	return 0;
}

static int dsa_verify_cp_req(struct dsa_verify_req_s *req,
			     crypto_mem_info_t *mem_info, bool ecdsa)
{
	dsa_verify_buffers_t *mem = &(mem_info->c_buffers.dsa_verify);
	dsa_verify_init_len(req, mem_info, ecdsa);

	print_debug("Calling alloc_crypto_mem\n");
	mem_info->buffers = (buffer_info_t *) mem;
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

#ifdef USE_HOST_DMA
	memcpy(mem->q_buff.h_v_addr, req->q, mem->q_buff.len);
	memcpy(mem->r_buff.h_v_addr, req->r, mem->r_buff.len);
	memcpy(mem->g_buff.h_v_addr, req->g, mem->g_buff.len);
	memcpy(mem->pub_key_buff.h_v_addr, req->pub_key, mem->pub_key_buff.len);
	memcpy(mem->m_buff.h_v_addr, req->m, mem->m_buff.len);
	memcpy(mem->c_buff.h_v_addr, req->c, mem->c_buff.len);
	memcpy(mem->d_buff.h_v_addr, req->d, mem->d_buff.len);

	if (ecdsa)
		memcpy(mem->ab_buff.h_v_addr, req->ab, mem->ab_buff.len);
	else
		mem->ab_buff.h_v_addr = NULL;

#else
	mem->q_buff.req_ptr = req->q;
	mem->r_buff.req_ptr = req->r;
	mem->g_buff.req_ptr = req->g;
	mem->pub_key_buff.req_ptr = req->pub_key;
	mem->m_buff.req_ptr = req->m;
	mem->c_buff.req_ptr = req->c;
	mem->d_buff.req_ptr = req->d;
	mem->tmp_buff.req_ptr = mem->tmp_buff.h_v_addr;

	if (ecdsa) {
		mem->ab_buff.req_ptr = req->ab;
	} else {
		mem->ab_buff.req_ptr = NULL;
	}
#endif
	return 0;
}

static int dsa_keygen_cp_req(struct dsa_keygen_req_s *req,
			     crypto_mem_info_t *mem_info, bool ecdsa)
{
	dsa_keygen_buffers_t *mem = &(mem_info->c_buffers.dsa_keygen);

	dsa_keygen_init_len(req, mem_info, ecdsa);
	print_debug("Calling alloc_crypto_mem\n");
	mem_info->buffers = (buffer_info_t *) mem;
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

#ifdef USE_HOST_DMA
	memcpy(mem->q_buff.h_v_addr, req->q, mem->q_buff.len);
	memcpy(mem->r_buff.h_v_addr, req->r, mem->r_buff.len);
	memcpy(mem->g_buff.h_v_addr, req->g, mem->g_buff.len);

	if (ecdsa)
		memcpy(mem->ab_buff.h_v_addr, req->ab, mem->ab_buff.len);
	else
		mem->ab_buff.h_v_addr = NULL;
#else
	mem->q_buff.req_ptr = req->q;
	mem->r_buff.req_ptr = req->r;
	mem->g_buff.req_ptr = req->g;

	if (ecdsa) {
		mem->ab_buff.req_ptr = req->ab;
	} else {
		mem->ab_buff.req_ptr = NULL;
	}
#endif
	mem->prvkey_buff.h_v_addr = req->prvkey;
	mem->pubkey_buff.h_v_addr = req->pubkey;

	return 0;
}

static void constr_dsa_sign_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size = sizeof(struct dsa_sign_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 12;

	dsa_sign_buffers_t *mem = &(mem_info->c_buffers.dsa_sign);
	struct dsa_sign_desc_s *dsa_sign_desc =
	    (struct dsa_sign_desc_s *)mem->desc_buff.h_v_addr;
#ifdef SEC_DMA
        dev_p_addr_t offset = mem_info->dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;
#endif
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&dsa_sign_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) |
		      (desc_size & HDR_DESCLEN_MASK) |
		      HDR_ONE);

#ifdef SEC_DMA
	ASSIGN64(dsa_sign_desc->q_dma, (mem->q_buff.h_p_addr + offset));
	ASSIGN64(dsa_sign_desc->r_dma, (mem->r_buff.h_p_addr + offset));
	ASSIGN64(dsa_sign_desc->g_dma, (mem->g_buff.h_p_addr + offset));
	ASSIGN64(dsa_sign_desc->s_dma, (mem->priv_key_buff.h_p_addr + offset));
	ASSIGN64(dsa_sign_desc->f_dma, (mem->m_buff.h_p_addr + offset));
#else
	ASSIGN64(dsa_sign_desc->q_dma, mem->q_buff.d_p_addr);
	ASSIGN64(dsa_sign_desc->r_dma, mem->r_buff.d_p_addr);
	ASSIGN64(dsa_sign_desc->g_dma, mem->g_buff.d_p_addr);
	ASSIGN64(dsa_sign_desc->s_dma, mem->priv_key_buff.d_p_addr);
	ASSIGN64(dsa_sign_desc->f_dma, mem->m_buff.d_p_addr);
#endif
	ASSIGN64(dsa_sign_desc->c_dma, mem->tmp_buff.d_p_addr);
	ASSIGN64(dsa_sign_desc->d_dma, (mem->tmp_buff.d_p_addr + mem->r_buff.len));

	iowrite32be((mem->q_buff.len << 7) | mem->r_buff.len, &dsa_sign_desc->sgf_ln);
	iowrite32be(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_DSASIGN, &dsa_sign_desc->op[0]);
	iowrite32be(CMD_MOVE | MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO |
			(2 * mem->r_buff.len), &dsa_sign_desc->op[1]);
	iowrite32be(CMD_JUMP | JUMP_COND_NOP | 1, &dsa_sign_desc->op[2]);
	iowrite32be(CMD_FIFO_LOAD | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_TYPEMASK
		  | (2 * mem->r_buff.len), &dsa_sign_desc->op[3]);
	ASSIGN64(dsa_sign_desc->op[4], mem->tmp_buff.d_p_addr);
	iowrite32be(CMD_FIFO_STORE | FIFOST_CONT_MASK | FIFOST_TYPE_MESSAGE_DATA |
		  mem->r_buff.len, &dsa_sign_desc->op[6]);
	ASSIGN64(dsa_sign_desc->op[7], mem->c_buff.d_p_addr);
	iowrite32be(CMD_FIFO_STORE | FIFOST_TYPE_MESSAGE_DATA | mem->r_buff.len,
			&dsa_sign_desc->op[9]);
	ASSIGN64(dsa_sign_desc->op[10], mem->d_buff.d_p_addr);

#ifdef PRINT_DEBUG
	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("R DMA: %llx\n", (uint64_t)mem->r_buff.d_p_addr);
	print_debug("G DMA: %llx\n", (uint64_t)mem->g_buff.d_p_addr);
	print_debug("S DMA: %llx\n", (uint64_t)mem->priv_key_buff.d_p_addr);
	print_debug("F DMA: %llx\n", (uint64_t)mem->m_buff.d_p_addr);
	print_debug("C DMA: %llx\n", (uint64_t)mem->c_buff.d_p_addr);
	print_debug("D DMA: %llx\n", (uint64_t)mem->d_buff.d_p_addr);
#endif

#ifdef DEBUG_DESC
	print_error("[DSA_SIGN] Descriptor words\n");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void constr_dsa_verify_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size = sizeof(struct dsa_verify_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	dsa_verify_buffers_t *mem = &(mem_info->c_buffers.dsa_verify);
	struct dsa_verify_desc_s *dsa_verify_desc =
	    (struct dsa_verify_desc_s *)mem->desc_buff.h_v_addr;
#ifdef SEC_DMA
        dev_p_addr_t offset = mem_info->dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;
#endif
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&dsa_verify_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) |
		      (desc_size & HDR_DESCLEN_MASK) |
		      HDR_ONE);

#ifdef SEC_DMA
	ASSIGN64(dsa_verify_desc->q_dma, (mem->q_buff.h_p_addr + offset));
	ASSIGN64(dsa_verify_desc->r_dma, (mem->r_buff.h_p_addr + offset));
	ASSIGN64(dsa_verify_desc->g_dma, (mem->g_buff.h_p_addr + offset));
	ASSIGN64(dsa_verify_desc->w_dma, (mem->pub_key_buff.h_p_addr + offset));
	ASSIGN64(dsa_verify_desc->f_dma, (mem->m_buff.h_p_addr + offset));
	ASSIGN64(dsa_verify_desc->c_dma, (mem->c_buff.h_p_addr + offset));
	ASSIGN64(dsa_verify_desc->d_dma, (mem->d_buff.h_p_addr + offset));
#else
	ASSIGN64(dsa_verify_desc->q_dma, mem->q_buff.d_p_addr);
	ASSIGN64(dsa_verify_desc->r_dma, mem->r_buff.d_p_addr);
	ASSIGN64(dsa_verify_desc->g_dma, mem->g_buff.d_p_addr);
	ASSIGN64(dsa_verify_desc->w_dma, mem->pub_key_buff.d_p_addr);
	ASSIGN64(dsa_verify_desc->f_dma, mem->m_buff.d_p_addr);
	ASSIGN64(dsa_verify_desc->c_dma, mem->c_buff.d_p_addr);
	ASSIGN64(dsa_verify_desc->d_dma, mem->d_buff.d_p_addr);
#endif
	ASSIGN64(dsa_verify_desc->tmp_dma, mem->tmp_buff.d_p_addr);

	iowrite32be((mem->q_buff.len << 7) | mem->r_buff.len, &dsa_verify_desc->sgf_ln);
	iowrite32be(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_DSAVERIFY, &dsa_verify_desc->op);

#ifdef PRINT_DEBUG

	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("R DMA: %llx\n", (uint64_t)mem->r_buff.d_p_addr);
	print_debug("G DMA: %llx\n", (uint64_t)mem->g_buff.d_p_addr);
	print_debug("W DMA: %llx\n", (uint64_t)mem->pub_key_buff.d_p_addr);
	print_debug("F DMA: %llx\n", (uint64_t)mem->m_buff.d_p_addr);
	print_debug("C DMA: %llx\n", (uint64_t)mem->c_buff.d_p_addr);
	print_debug("D DMA: %llx\n", (uint64_t)mem->d_buff.d_p_addr);
	print_debug("TMP DMA: %llx\n", (uint64_t)mem->tmp_buff.d_p_addr);
#endif

#ifdef DEBUG_DESC
	print_error("[DSA_VERIFY] Descriptor words\n");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void constr_dsa_keygen_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size = sizeof(struct dsa_keygen_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	dsa_keygen_buffers_t *mem = &(mem_info->c_buffers.dsa_keygen);
	struct dsa_keygen_desc_s *dsa_keygen_desc =
	    (struct dsa_keygen_desc_s *)mem->desc_buff.h_v_addr;

#ifdef SEC_DMA
        dev_p_addr_t offset = mem_info->dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;
#endif
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&dsa_keygen_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) |
		      (desc_size & HDR_DESCLEN_MASK) | HDR_ONE);

#ifdef SEC_DMA
        ASSIGN64(dsa_keygen_desc->q_dma, (mem->q_buff.h_p_addr + offset));
        ASSIGN64(dsa_keygen_desc->r_dma, (mem->r_buff.h_p_addr + offset));
        ASSIGN64(dsa_keygen_desc->g_dma, (mem->g_buff.h_p_addr + offset));
#else
	ASSIGN64(dsa_keygen_desc->q_dma, mem->q_buff.d_p_addr);
	ASSIGN64(dsa_keygen_desc->r_dma, mem->r_buff.d_p_addr);
	ASSIGN64(dsa_keygen_desc->g_dma, mem->g_buff.d_p_addr);
#endif
	ASSIGN64(dsa_keygen_desc->s_dma, mem->prvkey_buff.d_p_addr);
	ASSIGN64(dsa_keygen_desc->w_dma, mem->pubkey_buff.d_p_addr);

	iowrite32be((mem->q_buff.len << 7) | mem->r_buff.len, &dsa_keygen_desc->sgf_ln);
	iowrite32be(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_PUBLICKEYPAIR,
			&dsa_keygen_desc->op);

#ifdef PRINT_DEBUG
	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("R DMA: %llx\n", (uint64_t)mem->r_buff.d_p_addr);
	print_debug("G DMA: %llx\n", (uint64_t)mem->g_buff.d_p_addr);
	print_debug("S DMA: %llx\n", (uint64_t)mem->prvkey_buff.d_p_addr);
	print_debug("W DMA: %llx\n", (uint64_t)mem->pubkey_buff.d_p_addr);
#endif

#ifdef DEBUG_DESC
	print_error("[DSA_KEYGEN] Descriptor words\n");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void constr_ecdsa_sign_desc(crypto_mem_info_t *mem_info, bool ecc_bin)
{
	uint32_t desc_size = sizeof(struct ecdsa_sign_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 12;

	dsa_sign_buffers_t *mem = (dsa_sign_buffers_t *) (mem_info->buffers);
	struct ecdsa_sign_desc_s *ecdsa_sign_desc =
	    (struct ecdsa_sign_desc_s *)mem->desc_buff.h_v_addr;
#ifdef SEC_DMA
        dev_p_addr_t offset = mem_info->dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;
#endif
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&ecdsa_sign_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) |
		      (desc_size & HDR_DESCLEN_MASK) |
		      HDR_ONE);

#ifdef SEC_DMA
	ASSIGN64(ecdsa_sign_desc->q_dma, (mem->q_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_sign_desc->r_dma, (mem->r_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_sign_desc->g_dma, (mem->g_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_sign_desc->s_dma, (mem->priv_key_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_sign_desc->f_dma, (mem->m_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_sign_desc->ab_dma, (mem->ab_buff.h_p_addr + offset));
#else
	ASSIGN64(ecdsa_sign_desc->q_dma, mem->q_buff.d_p_addr);
	ASSIGN64(ecdsa_sign_desc->r_dma, mem->r_buff.d_p_addr);
	ASSIGN64(ecdsa_sign_desc->g_dma, mem->g_buff.d_p_addr);
	ASSIGN64(ecdsa_sign_desc->s_dma, mem->priv_key_buff.d_p_addr);
	ASSIGN64(ecdsa_sign_desc->f_dma, mem->m_buff.d_p_addr);
	ASSIGN64(ecdsa_sign_desc->ab_dma, mem->ab_buff.d_p_addr);
#endif
	ASSIGN64(ecdsa_sign_desc->c_dma, mem->tmp_buff.d_p_addr);
	ASSIGN64(ecdsa_sign_desc->d_dma,
		 (mem->tmp_buff.d_p_addr + mem->r_buff.len));

	iowrite32be((mem->q_buff.len << 7) | mem->r_buff.len, &ecdsa_sign_desc->sgf_ln);
	if (ecc_bin) {
		iowrite32be(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			  OP_PCLID_DSASIGN | OP_PCL_PKPROT_ECC |
			  OP_PCL_PKPROT_F2M, &ecdsa_sign_desc->op[0]);
	} else {
		iowrite32be(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			  OP_PCLID_DSASIGN | OP_PCL_PKPROT_ECC, &ecdsa_sign_desc->op[0]);
	}

	iowrite32be(CMD_MOVE | MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO |
		  (2 * mem->r_buff.len), &ecdsa_sign_desc->op[1]);
	iowrite32be(CMD_JUMP | JUMP_COND_NOP | 1, &ecdsa_sign_desc->op[2]);
	iowrite32be(CMD_FIFO_LOAD | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_TYPEMASK
		  | (2 * mem->r_buff.len), &ecdsa_sign_desc->op[3]);
	ASSIGN64(ecdsa_sign_desc->op[4], mem->tmp_buff.d_p_addr);
	iowrite32be(CMD_FIFO_STORE | FIFOST_CONT_MASK | FIFOST_TYPE_MESSAGE_DATA |
		  mem->r_buff.len, &ecdsa_sign_desc->op[6]);
	ASSIGN64(ecdsa_sign_desc->op[7], mem->c_buff.d_p_addr);
	iowrite32be(CMD_FIFO_STORE | FIFOST_TYPE_MESSAGE_DATA | mem->r_buff.len,
			&ecdsa_sign_desc->op[9]);
	ASSIGN64(ecdsa_sign_desc->op[10], mem->d_buff.d_p_addr);

#ifdef PRINT_DEBUG
	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("R DMA: %llx\n", (uint64_t)mem->r_buff.d_p_addr);
	print_debug("G DMA: %llx\n", (uint64_t)mem->g_buff.d_p_addr);
	print_debug("S DMA: %llx\n", (uint64_t)mem->priv_key_buff.d_p_addr);
	print_debug("F DMA: %llx\n", (uint64_t)mem->m_buff.d_p_addr);
	print_debug("C DMA: %llx\n", (uint64_t)mem->c_buff.d_p_addr);
	print_debug("D DMA: %llx\n", (uint64_t)mem->d_buff.d_p_addr);
	print_debug("AB DMA: %llx\n", (uint64_t)mem->ab_buff.d_p_addr);
#endif

#ifdef DEBUG_DESC
	print_error("[ECDSA_SIGN] Descriptor words\n");
	dump_desc((uint32_t *) mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void constr_ecdsa_verify_desc(crypto_mem_info_t *mem_info, bool ecc_bin)
{
	uint32_t desc_size = sizeof(struct ecdsa_verify_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	dsa_verify_buffers_t *mem = (dsa_verify_buffers_t *) (mem_info->buffers);
	struct ecdsa_verify_desc_s *ecdsa_verify_desc =
		(struct ecdsa_verify_desc_s *)mem->desc_buff.h_v_addr;

#ifdef SEC_DMA
        dev_p_addr_t offset = mem_info->dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;
#endif
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&ecdsa_verify_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) |
		      (desc_size & HDR_DESCLEN_MASK) |
		      HDR_ONE);

#ifdef SEC_DMA
	ASSIGN64(ecdsa_verify_desc->q_dma, (mem->q_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_verify_desc->r_dma, (mem->r_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_verify_desc->g_dma, (mem->g_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_verify_desc->w_dma, (mem->pub_key_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_verify_desc->f_dma, (mem->m_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_verify_desc->ab_dma, (mem->ab_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_verify_desc->c_dma, (mem->c_buff.h_p_addr + offset));
	ASSIGN64(ecdsa_verify_desc->d_dma, (mem->d_buff.h_p_addr + offset));
#else
	ASSIGN64(ecdsa_verify_desc->q_dma, mem->q_buff.d_p_addr);
	ASSIGN64(ecdsa_verify_desc->r_dma, mem->r_buff.d_p_addr);
	ASSIGN64(ecdsa_verify_desc->g_dma, mem->g_buff.d_p_addr);
	ASSIGN64(ecdsa_verify_desc->w_dma, mem->pub_key_buff.d_p_addr);
	ASSIGN64(ecdsa_verify_desc->f_dma, mem->m_buff.d_p_addr);
	ASSIGN64(ecdsa_verify_desc->ab_dma, mem->ab_buff.d_p_addr);
	ASSIGN64(ecdsa_verify_desc->c_dma, mem->c_buff.d_p_addr);
	ASSIGN64(ecdsa_verify_desc->d_dma, mem->d_buff.d_p_addr);
#endif
	ASSIGN64(ecdsa_verify_desc->tmp_dma, mem->tmp_buff.d_p_addr);

	iowrite32be((mem->q_buff.len << 7) | mem->r_buff.len, &ecdsa_verify_desc->sgf_ln);

	if (ecc_bin) {
		iowrite32be(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			  OP_PCLID_DSAVERIFY | OP_PCL_PKPROT_ECC |
			  OP_PCL_PKPROT_F2M, &ecdsa_verify_desc->op);
	} else {
		iowrite32be(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			  OP_PCLID_DSAVERIFY | OP_PCL_PKPROT_ECC,
			  &ecdsa_verify_desc->op);
	}

#ifdef PRINT_DEBUG
	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("R DMA: %llx\n", (uint64_t)mem->r_buff.d_p_addr);
	print_debug("G DMA: %llx\n", (uint64_t)mem->g_buff.d_p_addr);
	print_debug("W DMA: %llx\n", (uint64_t)mem->pub_key_buff.d_p_addr);
	print_debug("F DMA: %llx\n", (uint64_t)mem->m_buff.d_p_addr);
	print_debug("C DMA: %llx\n", (uint64_t)mem->c_buff.d_p_addr);
	print_debug("D DMA: %llx\n", (uint64_t)mem->d_buff.d_p_addr);
	print_debug("TMP DMA: %llx\n", (uint64_t)mem->tmp_buff.d_p_addr);
	print_debug("AB DMA: %llx\n", (uint64_t)mem->ab_buff.d_p_addr);
#endif

#ifdef DEBUG_DESC
	print_error("[ECDSA_VERIFY]  Descriptor words\n");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void constr_ecdsa_keygen_desc(crypto_mem_info_t *mem_info, bool ecc_bin)
{
	uint32_t desc_size = sizeof(struct ecdsa_keygen_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;
	dsa_keygen_buffers_t *mem = (dsa_keygen_buffers_t *) (mem_info->buffers);
	struct ecdsa_keygen_desc_s *ecdsa_keygen_desc =
	    (struct ecdsa_keygen_desc_s *)mem->desc_buff.h_v_addr;

#ifdef SEC_DMA
        dev_p_addr_t offset = mem_info->dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;
#endif

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&ecdsa_keygen_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) |
		      (desc_size & HDR_DESCLEN_MASK) | HDR_ONE);

#ifdef SEC_DMA
        ASSIGN64(ecdsa_keygen_desc->q_dma, (mem->q_buff.h_p_addr + offset));
        ASSIGN64(ecdsa_keygen_desc->r_dma, (mem->r_buff.h_p_addr + offset));
        ASSIGN64(ecdsa_keygen_desc->ab_dma, (mem->ab_buff.h_p_addr + offset));
        ASSIGN64(ecdsa_keygen_desc->g_dma, (mem->g_buff.h_p_addr + offset));
#else
	ASSIGN64(ecdsa_keygen_desc->q_dma, mem->q_buff.d_p_addr);
	ASSIGN64(ecdsa_keygen_desc->r_dma, mem->r_buff.d_p_addr);
	ASSIGN64(ecdsa_keygen_desc->ab_dma, mem->ab_buff.d_p_addr);
	ASSIGN64(ecdsa_keygen_desc->g_dma, mem->g_buff.d_p_addr);
#endif
	ASSIGN64(ecdsa_keygen_desc->s_dma, mem->prvkey_buff.d_p_addr);
	ASSIGN64(ecdsa_keygen_desc->w_dma, mem->pubkey_buff.d_p_addr);

	iowrite32be((mem->q_buff.len << 7) | mem->r_buff.len, &ecdsa_keygen_desc->sgf_ln);
	if (ecc_bin) {
		iowrite32be(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_PUBLICKEYPAIR |
			OP_PCL_PKPROT_ECC | OP_PCL_PKPROT_F2M, &ecdsa_keygen_desc->op);
	} else {
		iowrite32be(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_PUBLICKEYPAIR |
			OP_PCL_PKPROT_ECC, &ecdsa_keygen_desc->op);
	}

#ifdef PRINT_DEBUG
	print_debug("Q DMA :%llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("R DMA :%llx\n", (uint64_t)mem->r_buff.d_p_addr);
	print_debug("G DMA :%llx\n", (uint64_t)mem->g_buff.d_p_addr);
	print_debug("S DMA :%llx\n", (uint64_t)mem->prvkey_buff.d_p_addr);
	print_debug("W DMA :%llx\n", (uint64_t)mem->pubkey_buff.d_p_addr);
	print_debug("AB DMA:%llx\n", (uint64_t)mem->ab_buff.d_p_addr);
#endif

#ifdef DEBUG_DESC
	print_error("[DSA_KEYGEN] Descriptor words\n");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void dsa_sign_init_crypto_mem(crypto_mem_info_t *crypto_mem, bool ecdsa)
{
	dsa_sign_buffers_t *dsa_sign_buffs;

	crypto_mem->count = sizeof(dsa_sign_buffers_t) / sizeof(buffer_info_t);
	if (!ecdsa) {
		crypto_mem->count -= 1;
	}

	dsa_sign_buffs = &(crypto_mem->c_buffers.dsa_sign);
	memset(dsa_sign_buffs, 0, sizeof(dsa_sign_buffers_t));

	dsa_sign_buffs->q_buff.bt = BT_IP;
	dsa_sign_buffs->r_buff.bt = BT_IP;
	dsa_sign_buffs->g_buff.bt = BT_IP;
	dsa_sign_buffs->tmp_buff.bt = BT_IP;
	dsa_sign_buffs->priv_key_buff.bt = BT_IP;
	dsa_sign_buffs->m_buff.bt = BT_IP;
	dsa_sign_buffs->ab_buff.bt = BT_IP;
	dsa_sign_buffs->c_buff.bt = BT_OP;
	dsa_sign_buffs->d_buff.bt = BT_OP;
}

static void dsa_verify_init_crypto_mem(crypto_mem_info_t *crypto_mem,
				       bool ecdsa)
{
	dsa_verify_buffers_t *dsa_verify_buffs;

	crypto_mem->count = sizeof(dsa_verify_buffers_t) / sizeof(buffer_info_t);
	if (!ecdsa) {
		crypto_mem->count -= 1;
	}

	dsa_verify_buffs = &(crypto_mem->c_buffers.dsa_verify);
	memset(dsa_verify_buffs, 0, sizeof(dsa_verify_buffers_t));

	dsa_verify_buffs->q_buff.bt = BT_IP;
	dsa_verify_buffs->r_buff.bt = BT_IP;
	dsa_verify_buffs->g_buff.bt = BT_IP;
	dsa_verify_buffs->pub_key_buff.bt = BT_IP;
	dsa_verify_buffs->m_buff.bt = BT_IP;
	dsa_verify_buffs->ab_buff.bt = BT_IP;
	dsa_verify_buffs->tmp_buff.bt = BT_IP;
	dsa_verify_buffs->c_buff.bt = BT_IP;
	dsa_verify_buffs->d_buff.bt = BT_IP;
}

static void dsa_keygen_init_crypto_mem(crypto_mem_info_t *crypto_mem,
				       bool ecdsa)
{
	dsa_keygen_buffers_t *dsa_keygen_buffs;

	crypto_mem->count = sizeof(dsa_keygen_buffers_t) / sizeof(buffer_info_t);
	if (!ecdsa) {
		crypto_mem->count -= 1;
	}

	dsa_keygen_buffs = &(crypto_mem->c_buffers.dsa_keygen);
	memset(dsa_keygen_buffs, 0, sizeof(dsa_keygen_buffers_t));

	dsa_keygen_buffs->q_buff.bt = BT_IP;
	dsa_keygen_buffs->r_buff.bt = BT_IP;
	dsa_keygen_buffs->ab_buff.bt = BT_IP;
	dsa_keygen_buffs->g_buff.bt = BT_IP;
	dsa_keygen_buffs->prvkey_buff.bt = BT_OP;
	dsa_keygen_buffs->pubkey_buff.bt = BT_OP;
}

#ifdef VIRTIO_C2X0
int dsa_op(struct pkc_request *req, struct virtio_c2x0_job_ctx *virtio_job)
#else
int dsa_op(struct pkc_request *req)
#endif
{
	int32_t ret = 0;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	uint32_t r_id = 0;
	dsa_sign_buffers_t *dsa_sign_buffs = NULL;
	dsa_verify_buffers_t *dsa_verify_buffs = NULL;
	dsa_keygen_buffers_t *dsa_keygen_buffs = NULL;
	bool ecdsa = false;
	bool ecc_bin = false;

#ifdef SEC_DMA
        dev_p_addr_t offset;
#endif

#ifndef VIRTIO_C2X0
	if (NULL != req->base.tfm) {
		crypto_dev_sess_t *c_sess;
		dsa_completion_cb = pkc_request_complete;
		ecdsa_completion_cb = pkc_request_complete;
		/* Get the session context from input request */
		c_sess = crypto_pkc_ctx(crypto_pkc_reqtfm(req));
		c_dev = c_sess->c_dev;
		r_id = c_sess->r_id;
#ifndef HIGH_PERF
		if (-1 == check_device(c_dev))
			return -1;
#endif
	}
	else
#endif
	{
		/* By default using first device --
		 * Logic here will be replaced with LB */
#ifdef VIRTIO_C2X0
		if(NULL == (c_dev = get_device_rr()))
			return -1;
#else
		c_dev = get_crypto_dev(1);
		if (!c_dev) {
			print_error("Could not retrieve the device structure.\n");
			return -1;
		}

#endif
#ifndef HIGH_PERF	
		if(0 == (r_id = get_ring_rr(c_dev)))
			return -1;

		atomic_inc(&c_dev->active_jobs);
#else
        r_id = atomic_inc_return(&c_dev->crypto_dev_sess_cnt);
        r_id = 1 + r_id % (c_dev->num_of_rings - 1);

#endif
	}
#ifdef SEC_DMA
        offset = c_dev->priv_dev->bars[MEM_TYPE_DRIVER].dev_p_addr;
#endif
	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("crypto_ctx addr: %p\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_error("Mem alloc failed....\n");
		ret = -ENOMEM;
		goto error;
	}

	print_debug("Ring selected: %d\n", r_id);
	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.buf_pool = c_dev->ring_pairs[r_id].buf_pool;
	print_debug("IP Buffer pool address: %p\n", crypto_ctx->crypto_mem.buf_pool);

	if ((ECDSA_KEYGEN == req->type) ||
	    (ECDSA_SIGN == req->type) || (ECDSA_VERIFY == req->type)) {
		ecdsa = true;
		if (ECC_BINARY == req->curve_type) {
			ecc_bin = true;
		}
	}

	switch (req->type) {
	case DSA_KEYGEN:
	case ECDSA_KEYGEN:
		dsa_keygen_init_crypto_mem(&crypto_ctx->crypto_mem, ecdsa);
		if (-ENOMEM ==
		    dsa_keygen_cp_req(&req->req_u.dsa_keygen,
				      &crypto_ctx->crypto_mem, ecdsa)) {
			ret = -ENOMEM;
			goto error;
		}
		print_debug("DSA keygen init mem complete.....\n");
		host_to_dev(&crypto_ctx->crypto_mem);
		print_debug("Host to dev convert complete....\n");
#ifdef SEC_DMA
                map_crypto_mem(&(crypto_ctx->crypto_mem));
#endif
		if (ecdsa) {
			constr_ecdsa_keygen_desc(&crypto_ctx->crypto_mem, ecc_bin);
		} else {
			constr_dsa_keygen_desc(&crypto_ctx->crypto_mem);
		}
		print_debug("Desc constr complete...\n");
		dsa_keygen_buffs =  &(crypto_ctx->crypto_mem.c_buffers.dsa_keygen);
#ifdef SEC_DMA
                sec_dma = dsa_keygen_buffs->desc_buff.h_p_addr + offset;
#else
		sec_dma = dsa_keygen_buffs->desc_buff.d_p_addr;
#endif
		print_debug("[Enq] Desc addr: %llx Hbuffer addr:%p Crypto ctx: %p\n",
			    (uint64_t)dsa_keygen_buffs->desc_buff.d_p_addr,
			    dsa_keygen_buffs->desc_buff.h_v_addr, crypto_ctx);
		store_priv_data(dsa_keygen_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);
		break;
	case DSA_SIGN:
	case ECDSA_SIGN:
		dsa_sign_init_crypto_mem(&crypto_ctx->crypto_mem, ecdsa);
		if (-ENOMEM ==
		    dsa_sign_cp_req(&req->req_u.dsa_sign,
				    &crypto_ctx->crypto_mem, ecdsa)) {
			ret = -ENOMEM;
			goto error;
		}
		print_debug("DSA Sign init mem complete.....\n");
		host_to_dev(&crypto_ctx->crypto_mem);
#ifdef SEC_DMA
                map_crypto_mem(&(crypto_ctx->crypto_mem));
#endif

		print_debug("Host to dev convert complete....\n");
		if (ecdsa) {
			constr_ecdsa_sign_desc(&crypto_ctx->crypto_mem, ecc_bin);
		} else {
			constr_dsa_sign_desc(&crypto_ctx->crypto_mem);
		}
		print_debug("Desc constr complete...\n");
		dsa_sign_buffs = &(crypto_ctx->crypto_mem.c_buffers.dsa_sign);
#ifdef SEC_DMA
		sec_dma = dsa_sign_buffs->desc_buff.h_p_addr + offset;
#else
		sec_dma = dsa_sign_buffs->desc_buff.d_p_addr;
#endif
		print_debug("[Enq] Desc addr: %llx Hbuffer addr: %p	Crypto ctx: %p\n",
			    (uint64_t)dsa_sign_buffs->desc_buff.d_p_addr,
			    dsa_sign_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(dsa_sign_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);
		break;
	case DSA_VERIFY:
	case ECDSA_VERIFY:
		dsa_verify_init_crypto_mem(&crypto_ctx->crypto_mem, ecdsa);
		if (-ENOMEM ==
		    dsa_verify_cp_req(&req->req_u.dsa_verify,
				      &crypto_ctx->crypto_mem, ecdsa)) {
			ret = -ENOMEM;
			goto error;
		}
		print_debug("DSA Verify init mem complete.....\n");
		host_to_dev(&crypto_ctx->crypto_mem);
#ifdef SEC_DMA
                map_crypto_mem(&(crypto_ctx->crypto_mem));
#endif
		print_debug("Host to dev convert complete....\n");
		if (ecdsa) {
			constr_ecdsa_verify_desc(&crypto_ctx->crypto_mem, ecc_bin);
		} else {
			constr_dsa_verify_desc(&crypto_ctx->crypto_mem);
		}
		print_debug("Desc constr complete...\n");
		dsa_verify_buffs = &(crypto_ctx->crypto_mem.c_buffers.dsa_verify);
#ifdef SEC_DMA
		sec_dma = dsa_verify_buffs->desc_buff.h_p_addr + offset;
#else
		sec_dma = dsa_verify_buffs->desc_buff.d_p_addr;
#endif
		print_debug("[Enq] Desc addr: %llx Hbuffer addr: %p Crypto ctx :%p\n",
		     (uint64_t)dsa_verify_buffs->desc_buff.d_p_addr,
		     dsa_verify_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(dsa_verify_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);
		break;

	default:
		ret = -EINVAL;
		break;
	}
#ifdef USE_HOST_DMA
	/* Since the desc is first memory inthe contig chunk which needs to be
	 * transferred, hence taking its p addr as the
	 * source for the complete transfer.
	 */
	crypto_ctx->crypto_mem.dest_buff_dma =
	    crypto_ctx->crypto_mem.buffers[BT_DESC].h_map_p_addr;
#endif

#ifndef SEC_DMA
#ifndef USE_HOST_DMA
	memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif
#endif

	crypto_ctx->req.pkc = req;
	crypto_ctx->oprn = DSA;
	crypto_ctx->rid = r_id;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;

	if (ecdsa) {
		crypto_ctx->op_done = ecdsa_op_done;
	} else {
		crypto_ctx->op_done = dsa_op_done;
	}
#ifdef VIRTIO_C2X0
	/* Initialise card status as Unfinished */
	crypto_ctx->card_status = -1;

	/* Updating crypto context to virtio job
	   structure for further refernce */
	virtio_job->ctx = crypto_ctx;
#endif
#ifdef USE_HOST_DMA
	if (-1 ==
	    dma_to_dev(get_dma_chnl(), &crypto_ctx->crypto_mem,
		       dma_tx_complete_cb, crypto_ctx)) {
		print_error("DMA to dev failed....\n");
		ret = -1;
		goto error;
	}
#else

	print_debug("Before app_ring_enqueue\n");

	sec_dma = set_sec_affinity(c_dev, r_id, sec_dma);
#ifndef HIGH_PERF
	atomic_dec(&c_dev->active_jobs);
#endif
	/* Now enqueue the job into the app ring */
	if (app_ring_enqueue(c_dev, r_id, sec_dma)) {
		ret = -1;
		goto error1;
	}
#endif
	return -EINPROGRESS;

error:
#ifndef HIGH_PERF
	atomic_dec(&c_dev->active_jobs);
#endif
#ifndef USE_HOST_DMA
error1:
#endif
	if (crypto_ctx) {
		if (crypto_ctx->crypto_mem.buffers) {
			dealloc_crypto_mem(&crypto_ctx->crypto_mem);
			/*kfree(crypto_ctx->crypto_mem.buffers); */
		}
		free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
		/*kfree(crypto_ctx); */
	}
	return ret;
}

#ifdef VIRTIO_C2X0
int test_dsa_op(struct pkc_request *req,
		void (*cb) (struct pkc_request *, int32_t result),
		struct virtio_c2x0_job_ctx *virtio_job)
#else
int test_dsa_op(struct pkc_request *req,
		void (*cb) (struct pkc_request *, int32_t result))
#endif
{
    int32_t ret = 0;
	switch (req->type) {
	case DSA_KEYGEN:
	case DSA_SIGN:
	case DSA_VERIFY:
		dsa_completion_cb = cb;
		break;
	case ECDSA_KEYGEN:
	case ECDSA_SIGN:
	case ECDSA_VERIFY:
		ecdsa_completion_cb = cb;
		break;
	default:
		break;
	}
#ifdef VIRTIO_C2X0
	ret = dsa_op(req, virtio_job);
#else
	ret = dsa_op(req);
#endif
    if (-EINPROGRESS == ret) {
	    ret = 0;
    }
    if (0 > ret) {
	    ret = -1;
    }

    return ret;
}

EXPORT_SYMBOL(test_dsa_op);
