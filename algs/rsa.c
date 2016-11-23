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

#include "debug_print.h"
#include "fsl_c2x0_driver.h"
#include "rsa.h"
#include "pkc_desc.h"
#include "desc_constr.h"
#include "algs.h"

/* TODO: Remove this global callback. It is a broken implementation for testing */
rsa_op_cb rsa_completion_cb;

static void rsa_op_done(void *ctx, uint32_t res)
{
	struct crypto_op_ctx *crypto_ctx = ctx;

	print_debug("[RSA OP DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));
	rsa_completion_cb(crypto_ctx->req.pkc, res);
	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
}

/* Memory copy functions */
static void rsa_pub_op_init_len(struct rsa_pub_req_s *pub_req,
				rsa_pub_op_buffers_t *mem)
{
	mem->n_buff.len = pub_req->n_len;
	mem->e_buff.len = pub_req->e_len;
	mem->f_buff.len = pub_req->f_len;
	mem->g_buff.len = pub_req->g_len;
	mem->desc_buff.len = sizeof(struct rsa_pub_desc_s);
}

static int rsa_pub_op_cp_req(struct rsa_pub_req_s *pub_req,
			     crypto_mem_info_t *mem_info)
{
	rsa_pub_op_buffers_t *mem = &(mem_info->buffers.rsa_pub_op);

	rsa_pub_op_init_len(pub_req, mem);
	print_debug("Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

	mem->n_buff.h_v_addr = pub_req->n;
	mem->e_buff.h_v_addr = pub_req->e;
	mem->f_buff.h_v_addr = pub_req->f;
	mem->g_buff.h_v_addr = pub_req->g;

	print_debug("[RSA PUB OP] Request details:\n");
	print_debug("N Len: %d\n", mem->n_buff.len);
	print_debug("E Len: %d\n", mem->e_buff.len);
	print_debug("F Len: %d\n", mem->f_buff.len);
	print_debug("G Len: %d\n", mem->g_buff.len);
	print_debug("Desc Len: %d\n", mem->desc_buff.len);
	print_debug("G Buff addr: %p\n", mem->g_buff.h_v_addr);
	print_debug("[RSA PUB OP]\n");

	return 0;
}

/* Desc constr functions */
static void constr_rsa_pub_op_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size = sizeof(struct rsa_pub_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	rsa_pub_op_buffers_t *mem = &(mem_info->buffers.rsa_pub_op);
	struct rsa_pub_desc_s *rsa_pub_desc = mem->desc_buff.h_v_addr;

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&rsa_pub_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

	rsa_pub_desc->n_dma = cpu_to_be64(mem->n_buff.d_p_addr);
	rsa_pub_desc->e_dma = cpu_to_be64(mem->e_buff.d_p_addr);
	rsa_pub_desc->f_dma = cpu_to_be64(mem->f_buff.d_p_addr);
	rsa_pub_desc->g_dma = cpu_to_be64(mem->g_buff.d_p_addr);

	rsa_pub_desc->sgf_flg = cpu_to_be32((mem->e_buff.len << 12) | mem->n_buff.len);
	rsa_pub_desc->msg_len = cpu_to_be32(mem->f_buff.len);
	rsa_pub_desc->op = cpu_to_be32(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			OP_PCLID_RSAENC_PUBKEY);

#ifdef PRINT_DEBUG

	print_debug("N DMA			:%llx\n",
		    mem->n_buff.d_p_addr);
	print_debug("E DMA			:%llx\n",
		    mem->e_buff.d_p_addr);
	print_debug("F DMA			:%llx\n",
		    mem->f_buff.d_p_addr);
	print_debug("G DMA			:%llx\n",
		    mem->g_buff.d_p_addr);
#endif

#ifdef DEBUG_DESC
	print_error("[RSA_PUB_OP]	Descriptor words");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void rsa_pub_op_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rsa_pub_op_buffers_t *pub_op_buffs = &(crypto_mem->buffers.rsa_pub_op);

	crypto_mem->count = sizeof(rsa_pub_op_buffers_t) / sizeof(buffer_info_t);
	memset(pub_op_buffs, 0, sizeof(rsa_pub_op_buffers_t));

	/* Mark the op buffer */
	pub_op_buffs->n_buff.bt = BT_IP;
	pub_op_buffs->e_buff.bt = BT_IP;
	pub_op_buffs->f_buff.bt = BT_IP;
	pub_op_buffs->g_buff.bt = BT_OP;
}

/* PRIV FORM1 functions */
static void constr_rsa_priv1_op_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size =
	    sizeof(struct rsa_priv_frm1_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;
	uint32_t desc_hdr = 0;

	rsa_priv1_op_buffers_t *mem = &(mem_info->buffers.rsa_priv1_op);
	struct rsa_priv_frm1_desc_s *rsa_priv_desc = mem->desc_buff.h_v_addr;

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

	rsa_priv_desc->n_dma = cpu_to_be64(mem->n_buff.d_p_addr);
	rsa_priv_desc->d_dma = cpu_to_be64(mem->d_buff.d_p_addr);
	rsa_priv_desc->g_dma = cpu_to_be64(mem->g_buff.d_p_addr);
	rsa_priv_desc->f_dma = cpu_to_be64(mem->f_buff.d_p_addr);

	rsa_priv_desc->sgf_flg = cpu_to_be32((mem->d_buff.len << 12) | mem->n_buff.len);
	rsa_priv_desc->op = cpu_to_be32(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			OP_PCLID_RSADEC_PRVKEY | RSA_PRIV_KEY_FRM_1);
}

static void rsa_priv1_op_init_len(struct rsa_priv_frm1_req_s *priv1_req,
				  crypto_mem_info_t *mem_info)
{
	rsa_priv1_op_buffers_t *mem = &(mem_info->buffers.rsa_priv1_op);

	mem->n_buff.len = priv1_req->n_len;
	mem->d_buff.len = priv1_req->d_len;
	mem->g_buff.len = priv1_req->g_len;
	mem->f_buff.len = priv1_req->f_len;

	mem->desc_buff.len = sizeof(struct rsa_priv_frm1_desc_s);
}

static int rsa_priv1_op_cp_req(struct rsa_priv_frm1_req_s *priv1_req,
			       crypto_mem_info_t *mem_info)
{
	rsa_priv1_op_buffers_t *mem = &(mem_info->buffers.rsa_priv1_op);
	rsa_priv1_op_init_len(priv1_req, mem_info);

	/* Alloc mem requrd for crypto operation */
	print_debug("Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

	mem->n_buff.h_v_addr = priv1_req->n;
	mem->d_buff.h_v_addr = priv1_req->d;
	mem->g_buff.h_v_addr = priv1_req->g;
	mem->f_buff.h_v_addr = priv1_req->f;

#ifdef PRINT_DEBUG
	print_debug("[RSA PUB OP] Request details:\n");
	print_debug("N Len: %d\n", mem->n_buff.len);
	print_debug("D Len: %d\n", mem->d_buff.len);
	print_debug("G Len: %d\n", mem->g_buff.len);
	print_debug("F Len: %d\n", mem->f_buff.len);
	print_debug("Desc Len: %d\n", mem->desc_buff.len);
	print_debug("F Buff addr: %p\n", mem->f_buff.h_v_addr);
	print_debug("[RSA PUB OP]\n");
#endif
	return 0;
}

static void rsa_priv1_op_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rsa_priv1_op_buffers_t *priv1_op_buffs = &(crypto_mem->buffers.rsa_priv1_op);

	crypto_mem->count = sizeof(rsa_priv1_op_buffers_t) / sizeof(buffer_info_t);
	memset(priv1_op_buffs, 0, sizeof(rsa_priv1_op_buffers_t));

	/* Mark the op buffer */
	priv1_op_buffs->n_buff.bt = BT_IP;
	priv1_op_buffs->d_buff.bt = BT_IP;
	priv1_op_buffs->g_buff.bt = BT_IP;
	priv1_op_buffs->f_buff.bt = BT_OP;
}

/* PRIV FORM2 functions */
static void constr_rsa_priv2_op_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size =
	    sizeof(struct rsa_priv_frm2_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	rsa_priv2_op_buffers_t *mem = &(mem_info->buffers.rsa_priv2_op);
	struct rsa_priv_frm2_desc_s *rsa_priv_desc = mem->desc_buff.h_v_addr;
	uint32_t *desc_buff = (uint32_t *) mem->desc_buff.h_v_addr;

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(desc_buff,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

	rsa_priv_desc->p_dma = cpu_to_be64(mem->p_buff.d_p_addr);
	rsa_priv_desc->q_dma = cpu_to_be64(mem->q_buff.d_p_addr);
	rsa_priv_desc->d_dma = cpu_to_be64(mem->d_buff.d_p_addr);
	rsa_priv_desc->f_dma =cpu_to_be64(mem->f_buff.d_p_addr);
	rsa_priv_desc->g_dma = cpu_to_be64(mem->g_buff.d_p_addr);
	rsa_priv_desc->tmp1_dma = cpu_to_be64(mem->tmp1_buff.d_p_addr);
	rsa_priv_desc->tmp2_dma = cpu_to_be64(mem->tmp2_buff.d_p_addr);

	rsa_priv_desc->sgf_flg = cpu_to_be32((mem->d_buff.len << 12) | mem->f_buff.len);
	rsa_priv_desc->p_q_len = cpu_to_be32((mem->q_buff.len << 12) | mem->p_buff.len);
	rsa_priv_desc->op = cpu_to_be32(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			OP_PCLID_RSADEC_PRVKEY | RSA_PRIV_KEY_FRM_2);
}

static void rsa_priv2_op_init_len(struct rsa_priv_frm2_req_s *priv2_req,
				  crypto_mem_info_t *mem_info)
{
	rsa_priv2_op_buffers_t *mem = &(mem_info->buffers.rsa_priv2_op);

	mem->p_buff.len = priv2_req->p_len;
	mem->q_buff.len = priv2_req->q_len;
	mem->d_buff.len = priv2_req->d_len;
	mem->f_buff.len = priv2_req->f_len;
	mem->g_buff.len = priv2_req->g_len;
	mem->tmp1_buff.len = priv2_req->p_len;
	mem->tmp2_buff.len = priv2_req->q_len;

	mem->desc_buff.len = sizeof(struct rsa_priv_frm2_desc_s);
}

static int rsa_priv2_op_cp_req(struct rsa_priv_frm2_req_s *priv2_req,
			       crypto_mem_info_t *mem_info)
{
	rsa_priv2_op_buffers_t *mem = &(mem_info->buffers.rsa_priv2_op);
#ifdef PRINT_DEBUG
	rsa_priv2_op_buffers_t *priv2_op_buffs = mem;
#endif
	rsa_priv2_op_init_len(priv2_req, mem_info);

	/* Alloc mem requrd for crypto operation */
	print_debug("Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

	mem->p_buff.h_v_addr = priv2_req->p;
	mem->q_buff.h_v_addr = priv2_req->q;
	mem->d_buff.h_v_addr = priv2_req->d;
	mem->g_buff.h_v_addr = priv2_req->g;
	mem->f_buff.h_v_addr = priv2_req->f;

#ifdef PRINT_DEBUG
	print_debug("[RSA PRIV2 OP] Request details:\n");
	print_debug("P Len: %d\n", mem->p_buff.len);
	print_debug("Q Len: %d\n", mem->q_buff.len);
	print_debug("D Len: %d\n", mem->d_buff.len);
	print_debug("G Len: %d\n", mem->g_buff.len);
	print_debug("TMP1 Len: %d\n", mem->tmp1_buff.len);
	print_debug("TMP2 Len: %d\n", mem->tmp2_buff.len);
	print_debug("Desc Len: %d\n", mem->desc_buff.len);
	print_debug("F Buff addr: %p\n", mem->f_buff.h_v_addr);
	print_debug("[RSA PRIV2 OP]\n");

	print_debug("[RSA_PUB_OP] Allocated memory details:\n");
	print_debug("P Buffer: %p\n", priv2_op_buffs->p_buff.h_v_addr);
	print_debug("Q Buffer: %p\n", priv2_op_buffs->q_buff.h_v_addr);
	print_debug("D Buffer: %p\n", priv2_op_buffs->d_buff.h_v_addr);
	print_debug("G Buffer: %p\n", priv2_op_buffs->g_buff.h_v_addr);
	print_debug("TMP1 Buffer: %p\n", priv2_op_buffs->tmp1_buff.h_v_addr);
	print_debug("TMP2 Buffer: %p\n", priv2_op_buffs->tmp2_buff.h_v_addr);
	print_debug("F Buffer: %p\n", priv2_op_buffs->f_buff.h_v_addr);
	print_debug("DESC Buffer: %p\n", priv2_op_buffs->desc_buff.h_v_addr);
#endif
	return 0;
}

static void rsa_priv2_op_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rsa_priv2_op_buffers_t *priv2_op_buffs = &(crypto_mem->buffers.rsa_priv2_op);

	crypto_mem->count = sizeof(rsa_priv2_op_buffers_t) / sizeof(buffer_info_t);
	memset(priv2_op_buffs, 0, sizeof(rsa_priv2_op_buffers_t));

	/* Mark the op buffer */
	priv2_op_buffs->p_buff.bt = BT_IP;
	priv2_op_buffs->q_buff.bt = BT_IP;
	priv2_op_buffs->d_buff.bt = BT_IP;
	priv2_op_buffs->g_buff.bt = BT_IP;
	priv2_op_buffs->tmp1_buff.bt = BT_TMP;
	priv2_op_buffs->tmp2_buff.bt = BT_TMP;
	priv2_op_buffs->f_buff.bt = BT_OP;
}

/* RSA PRIV FORM3 */
static void constr_rsa_priv3_op_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size =
	    sizeof(struct rsa_priv_frm3_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	rsa_priv3_op_buffers_t *mem = &(mem_info->buffers.rsa_priv3_op);
	struct rsa_priv_frm3_desc_s *rsa_priv_desc = mem->desc_buff.h_v_addr;
	uint32_t *desc_buff = (uint32_t *) mem->desc_buff.h_v_addr;

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(desc_buff,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

	rsa_priv_desc->p_dma = cpu_to_be64(mem->p_buff.d_p_addr);
	rsa_priv_desc->q_dma = cpu_to_be64(mem->q_buff.d_p_addr);
	rsa_priv_desc->dp_dma = cpu_to_be64(mem->dp_buff.d_p_addr);
	rsa_priv_desc->dq_dma = cpu_to_be64(mem->dq_buff.d_p_addr);
	rsa_priv_desc->c_dma = cpu_to_be64(mem->c_buff.d_p_addr);
	rsa_priv_desc->g_dma = cpu_to_be64(mem->g_buff.d_p_addr);
	rsa_priv_desc->tmp1_dma = cpu_to_be64(mem->tmp1_buff.d_p_addr);
	rsa_priv_desc->tmp2_dma = cpu_to_be64(mem->tmp2_buff.d_p_addr);
	rsa_priv_desc->f_dma = cpu_to_be64(mem->f_buff.d_p_addr);

	rsa_priv_desc->sgf_flg = cpu_to_be32(mem->f_buff.len);
	rsa_priv_desc->p_q_len = cpu_to_be32((mem->q_buff.len << 12) | mem->p_buff.len);
	rsa_priv_desc->op = cpu_to_be32(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL |
			OP_PCLID_RSADEC_PRVKEY | RSA_PRIV_KEY_FRM_3);

#ifdef DEBUG_DESC
	print_error("[RSA_PRV3_OP]   Descriptor words\n");
	dump_desc(desc_buff, desc_size, __func__);
#endif
}

static void rsa_priv3_op_init_len(struct rsa_priv_frm3_req_s *priv3_req,
				  crypto_mem_info_t *mem_info)
{
	rsa_priv3_op_buffers_t *mem = &(mem_info->buffers.rsa_priv3_op);

	mem->p_buff.len = priv3_req->p_len;
	mem->q_buff.len = priv3_req->q_len;
	mem->c_buff.len = priv3_req->c_len;
	mem->dp_buff.len = priv3_req->dp_len;
	mem->dq_buff.len = priv3_req->dq_len;
	mem->f_buff.len = priv3_req->f_len;
	mem->g_buff.len = priv3_req->g_len;
	mem->tmp1_buff.len = priv3_req->p_len;
	mem->tmp2_buff.len = priv3_req->q_len;

	mem->desc_buff.len = sizeof(struct rsa_priv_frm3_desc_s);
}

static int rsa_priv3_op_cp_req(struct rsa_priv_frm3_req_s *priv3_req,
			       crypto_mem_info_t *mem_info)
{
	rsa_priv3_op_buffers_t *mem = &(mem_info->buffers.rsa_priv3_op);

	rsa_priv3_op_init_len(priv3_req, mem_info);

	/* Alloc mem requrd for crypto operation */
	print_debug("Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

	mem->p_buff.h_v_addr = priv3_req->p;
	mem->q_buff.h_v_addr = priv3_req->q;
	mem->dp_buff.h_v_addr = priv3_req->dp;
	mem->dq_buff.h_v_addr = priv3_req->dq;
	mem->g_buff.h_v_addr = priv3_req->g;
	mem->c_buff.h_v_addr = priv3_req->c;
	mem->f_buff.h_v_addr = priv3_req->f;

#ifdef PRINT_DEBUG
	print_debug("[RSA PRIV3 OP] Request details:\n");
	print_debug("P Len: %d\n", mem->p_buff.len);
	print_debug("Q Len: %d\n", mem->q_buff.len);
	print_debug("G Len: %d\n", mem->g_buff.len);
	print_debug("C Len: %d\n", mem->c_buff.len);
	print_debug("DPLen: %d\n", mem->dp_buff.len);
	print_debug("DQLen: %d\n", mem->dq_buff.len);
	print_debug("TMP1 Len: %d\n", mem->tmp1_buff.len);
	print_debug("TMP2 Len: %d\n", mem->tmp2_buff.len);
	print_debug("Desc Len: %d\n", mem->desc_buff.len);
	print_debug("F Buff addr: %p\n", mem->f_buff.h_v_addr);
	print_debug("[RSA PRIV3 OP]\n");
#endif
	return 0;
}

static void rsa_priv3_op_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rsa_priv3_op_buffers_t *priv3_op_buffs = &(crypto_mem->buffers.rsa_priv3_op);

	crypto_mem->count = sizeof(rsa_priv3_op_buffers_t) / sizeof(buffer_info_t);
	memset(priv3_op_buffs, 0, sizeof(rsa_priv3_op_buffers_t));

	/* Mark the op buffer */
	priv3_op_buffs->p_buff.bt = BT_IP;
	priv3_op_buffs->q_buff.bt = BT_IP;
	priv3_op_buffs->dp_buff.bt = BT_IP;
	priv3_op_buffs->dq_buff.bt = BT_IP;
	priv3_op_buffs->c_buff.bt = BT_IP;
	priv3_op_buffs->g_buff.bt = BT_IP;
	priv3_op_buffs->tmp1_buff.bt = BT_TMP;
	priv3_op_buffs->tmp2_buff.bt = BT_TMP;
	priv3_op_buffs->f_buff.bt = BT_OP;
}

int rsa_op(struct pkc_request *req)
{
	int32_t ret = 0;
	struct crypto_op_ctx *crypto_ctx = NULL;
	struct c29x_dev *c_dev = NULL;

	dev_dma_addr_t sec_dma = 0;
	uint32_t sess_cnt;
	uint32_t r_id = 0;
	rsa_pub_op_buffers_t *pub_op_buffs = NULL;
	rsa_priv1_op_buffers_t *priv1_op_buffs = NULL;
	rsa_priv2_op_buffers_t *priv2_op_buffs = NULL;
	rsa_priv3_op_buffers_t *priv3_op_buffs = NULL;
	struct ctx_pool *ctx_pool;

	if (NULL != req->base.tfm) {
		struct crypto_dev_sess *c_sess;

		rsa_completion_cb = pkc_request_complete;
		/* Get the session context from input request */
		c_sess = (struct crypto_dev_sess *) crypto_pkc_ctx(crypto_pkc_reqtfm(req));
		c_dev = c_sess->c_dev;
		r_id = c_sess->r_id;
		sess_cnt = atomic_read(&c_dev->crypto_dev_sess_cnt);
	} else {
	/* By default using first device --
	 * Logic here will be replaced with LB */
	c_dev = get_crypto_dev(1);
	if (!c_dev)
		return -1;

	sess_cnt = atomic_inc_return(&c_dev->crypto_dev_sess_cnt);
	r_id = sess_cnt % c_dev->config.num_of_rps;
	}

	ctx_pool = &c_dev->ctx_pool[r_id];
	crypto_ctx = get_crypto_ctx(ctx_pool);
	print_debug("crypto_ctx addr: %p\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_debug("Mem alloc failed....\n");
		return -ENOMEM;
	}

	print_debug("Ring selected			:%d\n", r_id);
	crypto_ctx->ctx_pool = ctx_pool;
	crypto_ctx->crypto_mem.c_dev = c_dev;
	crypto_ctx->crypto_mem.buf_pool = &(c_dev->buf_pool[0]);
	print_debug("IP Buffer pool address: %p\n", crypto_ctx->crypto_mem.buf_pool);

	switch (req->type) {
	case RSA_PUB:
		rsa_pub_op_init_crypto_mem(&crypto_ctx->crypto_mem);
		ret = rsa_pub_op_cp_req(&req->req_u.rsa_pub_req, &crypto_ctx->crypto_mem);
		if (ret != 0) {
			goto out_nop;
		}

		print_debug("Rsa pub op init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);
		print_debug("Host to dev convert complete....\n");

		/* Constr the hw desc */
		constr_rsa_pub_op_desc(&crypto_ctx->crypto_mem);
		print_debug("Desc constr complete...\n");

		pub_op_buffs = &(crypto_ctx->crypto_mem.buffers.rsa_pub_op);
		sec_dma = pub_op_buffs->desc_buff.d_p_addr;

		/* Store the context */
		print_debug("[Enq] Desc addr:%llx Hbuffer addr:%p Crypto ctx: %p\n",
		     (uint64_t)pub_op_buffs->desc_buff.d_p_addr,
		     pub_op_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(pub_op_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);
		break;
	case RSA_PRIV_FORM1:
		rsa_priv1_op_init_crypto_mem(&crypto_ctx->crypto_mem);
		ret = rsa_priv1_op_cp_req(&req->req_u.rsa_priv_f1, &crypto_ctx->crypto_mem);
		if (ret != 0) {
			goto out_nop;
		}
		print_debug("Rsa pub op init mem complete....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("Host to dev convert complete....\n");

		/* Constr the hw desc */
		constr_rsa_priv1_op_desc(&crypto_ctx->crypto_mem);
		print_debug("Desc constr complete...\n");

		priv1_op_buffs = &(crypto_ctx->crypto_mem.buffers.rsa_priv1_op);
		sec_dma = priv1_op_buffs->desc_buff.d_p_addr;

		/* Store the context */
		print_debug("[Enq] Desc addr: %llx Hbuffer addr: %p Crypto ctx: %p\n",
			    (uint64_t)priv1_op_buffs->desc_buff.d_p_addr,
			    priv1_op_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(priv1_op_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);
		break;

	case RSA_PRIV_FORM2:
		rsa_priv2_op_init_crypto_mem(&crypto_ctx->crypto_mem);
		ret = rsa_priv2_op_cp_req(&req->req_u.rsa_priv_f2, &crypto_ctx->crypto_mem);
		if (ret != 0) {
			goto out_nop;
		}
		print_debug("Rsa pub op init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("Host to dev convert complete....\n");

		/* Constr the hw desc */
		constr_rsa_priv2_op_desc(&crypto_ctx->crypto_mem);
		print_debug("Desc constr complete...\n");

		priv2_op_buffs = &(crypto_ctx->crypto_mem.buffers.rsa_priv2_op);
		sec_dma = priv2_op_buffs->desc_buff.d_p_addr;

		/* Store the context */
		print_debug("[Enq] Desc addr: %llx Hbuffer addr: %p Crypto ctx: %p\n",
			    (uint64_t)priv2_op_buffs->desc_buff.d_p_addr,
			    priv2_op_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(priv2_op_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);
		break;

	case RSA_PRIV_FORM3:
		rsa_priv3_op_init_crypto_mem(&crypto_ctx->crypto_mem);
		ret = rsa_priv3_op_cp_req(&req->req_u.rsa_priv_f3, &crypto_ctx->crypto_mem);
		if (ret != 0) {
			goto out_nop;
		}
		print_debug("Rsa pub op init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);
		print_debug("Host to dev convert complete....\n");

		/* Constr the hw desc */
		constr_rsa_priv3_op_desc(&crypto_ctx->crypto_mem);
		print_debug("Desc constr complete...\n");

		priv3_op_buffs = &(crypto_ctx->crypto_mem.buffers.rsa_priv3_op);
		sec_dma = priv3_op_buffs->desc_buff.d_p_addr;

		/* Store the context */
		print_debug("[Enq] Desc addr: %llx Hbuffer addr: %p Crypto ctx: %p\n",
		     (uint64_t)priv3_op_buffs->desc_buff.d_p_addr,
		     priv3_op_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(priv3_op_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);

		break;
	default:
		ret = -EINVAL;
		goto out_nop;
	}


	crypto_ctx->req.pkc = req;
	crypto_ctx->oprn = RSA;
	crypto_ctx->op_done = rsa_op_done;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;

	print_debug("Before app_ring_enqueue\n");
	/* Now enqueue the job into the app ring */
	if (ring_enqueue(c_dev, r_id, sec_dma)) {
		ret = -1;
		goto out_err;
	}

	ret = -EINPROGRESS;
	goto out_no_ctx;

out_err:
	dealloc_crypto_mem(&crypto_ctx->crypto_mem);
out_nop:
	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
out_no_ctx:
	return ret;
}
