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
#include "debug_print.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "dh.h"
#include "pkc_desc.h"
#include "desc.h"
#include "algs.h"

/* TODO: Remove this global callback. It is a broken implementation for testing */
dh_op_cb dh_completion_cb;
dh_op_cb ecdh_completion_cb;

static void dh_op_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[DH OP DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));
	dh_completion_cb(crypto_ctx->req.pkc, res);
	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
}

static void ecdh_op_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[ECDH OP DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));
	ecdh_completion_cb(crypto_ctx->req.pkc, res);
	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
}

/* Memory copy functions */
static void dh_key_init_len(struct dh_key_req_s *req,
			    crypto_mem_info_t *mem_info, bool ecdh)
{
	dh_key_buffers_t *mem = (dh_key_buffers_t *) (mem_info->buffers);

	mem->q_buff.len = req->q_len;
	mem->w_buff.len = req->pub_key_len;
	mem->s_buff.len = req->s_len;
	mem->z_buff.len = req->z_len;
	if (ecdh) {
		mem->ab_buff.len = req->ab_len;
		mem->desc_buff.len = sizeof(struct ecdh_key_desc_s);
	} else {
		mem->ab_buff.len = 0;
		mem->desc_buff.len = sizeof(struct dh_key_desc_s);
	}
}

static void dh_keygen_init_len(struct dh_keygen_req_s *req, crypto_mem_info_t *mem_info, bool ecdh)
{
    dh_keygen_buffers_t    *mem    =   (dh_keygen_buffers_t *)(mem_info->buffers);

    mem->q_buff.len         =   req->q_len;
    mem->r_buff.len         =   req->r_len;
    mem->g_buff.len         =   req->g_len;
    mem->prvkey_buff.len    =   req->prvkey_len;
    mem->pubkey_buff.len    =   req->pubkey_len;
    if(ecdh){
        mem->ab_buff.len    =   req->ab_len;
        mem->desc_buff.len  =   sizeof(struct ecdh_keygen_desc_s);
    }
    else{
        mem->ab_buff.len    =   0;
        mem->desc_buff.len  =   sizeof(struct dh_keygen_desc_s);
    }
}

static int dh_key_cp_req(struct dh_key_req_s *req, crypto_mem_info_t *mem_info,
			 bool ecdh)
{
	dh_key_buffers_t *mem = (dh_key_buffers_t *) (mem_info->buffers);
	dh_key_init_len(req, mem_info, ecdh);

	/* Alloc mem requrd for crypto operation */
	print_debug("Calling alloc_crypto_mem\n");
	if (-ENOMEM == alloc_crypto_mem(mem_info))
		return -ENOMEM;

	mem->q_buff.h_v_addr = req->q;
	mem->w_buff.h_v_addr = req->pub_key;
	mem->s_buff.h_v_addr = req->s;

	if (ecdh) {
		mem->ab_buff.h_v_addr = req->ab;
	} else {
		mem->ab_buff.h_v_addr = NULL;
	}
	mem->z_buff.h_v_addr = req->z;
	return 0;
}

static int dh_keygen_cp_req(struct dh_keygen_req_s *req, crypto_mem_info_t *mem_info, bool ecdh)
{
    dh_keygen_buffers_t *mem    =   (dh_keygen_buffers_t *)(mem_info->buffers);
    dh_keygen_init_len(req, mem_info, ecdh);

    /* Alloc mem requrd for crypto operation */
    print_debug("Calling alloc_crypto_mem\n");
    if(-ENOMEM == alloc_crypto_mem(mem_info))
        return -ENOMEM;

    mem->q_buff.h_v_addr         =   req->q;
    mem->r_buff.h_v_addr         =   req->r;
    mem->g_buff.h_v_addr         =   req->g;

    if(ecdh) {
       mem->ab_buff.h_v_addr     =   req->ab;
    } else {
       mem->ab_buff.h_v_addr     =   NULL;
    }

    mem->prvkey_buff.h_v_addr     =   req->prvkey;
    mem->pubkey_buff.h_v_addr     =   req->pubkey;
    return 0;
}

/* Desc constr functions */
static void constr_dh_key_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size = sizeof(struct dh_key_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	dh_key_buffers_t *mem = (dh_key_buffers_t *) (mem_info->buffers);
	struct dh_key_desc_s *dh_key_desc =
	    (struct dh_key_desc_s *)mem->desc_buff.h_v_addr;

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&dh_key_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

	dh_key_desc->q_dma = cpu_to_be64(mem->q_buff.d_p_addr);
	dh_key_desc->w_dma = cpu_to_be64(mem->w_buff.d_p_addr);
	dh_key_desc->s_dma = cpu_to_be64(mem->s_buff.d_p_addr);
	dh_key_desc->z_dma = cpu_to_be64(mem->z_buff.d_p_addr);

	dh_key_desc->sgf_ln = cpu_to_be32((mem->q_buff.len << 7) | mem->s_buff.len);
	dh_key_desc->op = cpu_to_be32(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_DH);

	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("W DMA: %llx\n", (uint64_t)mem->w_buff.d_p_addr);
	print_debug("S DMA: %llx\n", (uint64_t)mem->s_buff.d_p_addr);
	print_debug("Z DMA: %llx\n", (uint64_t)mem->z_buff.d_p_addr);

#ifdef DEBUG_DESC
	print_error("[DH] Descriptor words\n");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void constr_ecdh_key_desc(crypto_mem_info_t *mem_info, bool ecc_bin)
{
	uint32_t desc_size = sizeof(struct ecdh_key_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	dh_key_buffers_t *mem = (dh_key_buffers_t *) (mem_info->buffers);
	struct ecdh_key_desc_s *ecdh_key_desc =
	    (struct ecdh_key_desc_s *)mem->desc_buff.h_v_addr;

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&ecdh_key_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

	ecdh_key_desc->q_dma = cpu_to_be64(mem->q_buff.d_p_addr);
	ecdh_key_desc->w_dma = cpu_to_be64(mem->w_buff.d_p_addr);
	ecdh_key_desc->s_dma = cpu_to_be64(mem->s_buff.d_p_addr);
	ecdh_key_desc->ab_dma = cpu_to_be64(mem->ab_buff.d_p_addr);
	ecdh_key_desc->z_dma = cpu_to_be64(mem->z_buff.d_p_addr);

	ecdh_key_desc->sgf_ln = cpu_to_be32((mem->q_buff.len << 7) | mem->s_buff.len);
	if (ecc_bin) {
		ecdh_key_desc->op = cpu_to_be32(CMD_OPERATION |
			OP_TYPE_UNI_PROTOCOL | OP_PCLID_DH |
			OP_PCL_PKPROT_ECC | OP_PCL_PKPROT_F2M);
	} else {
		ecdh_key_desc->op = cpu_to_be32(CMD_OPERATION |
			OP_TYPE_UNI_PROTOCOL | OP_PCLID_DH |
			OP_PCL_PKPROT_ECC);
	}

	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("W DMA: %llx\n", (uint64_t)mem->w_buff.d_p_addr);
	print_debug("S DMA: %llx\n", (uint64_t)mem->s_buff.d_p_addr);
	print_debug("Z DMA: %llx\n", (uint64_t)mem->z_buff.d_p_addr);
	print_debug("AB DMA: %llx\n", (uint64_t)mem->ab_buff.d_p_addr);

#ifdef DEBUG_DESC
	print_error("[ECDH] Descriptor words\n");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void constr_ecdh_keygen_desc(crypto_mem_info_t *mem_info, bool ecc_bin)
{
	uint32_t desc_size = sizeof(struct ecdh_keygen_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	dh_keygen_buffers_t *mem = (dh_keygen_buffers_t *)(mem_info->buffers);
	struct ecdh_keygen_desc_s *ecdh_keygen_desc = (struct ecdh_keygen_desc_s *)mem->desc_buff.h_v_addr;

	start_idx   &=  HDR_START_IDX_MASK;
	init_job_desc(&ecdh_keygen_desc->desc_hdr,
		(start_idx << HDR_START_IDX_SHIFT) |
		(desc_size & HDR_DESCLEN_MASK) | HDR_ONE);

	ecdh_keygen_desc->q_dma = cpu_to_be64(mem->q_buff.d_p_addr);
	ecdh_keygen_desc->r_dma = cpu_to_be64(mem->r_buff.d_p_addr);
	ecdh_keygen_desc->g_dma = cpu_to_be64(mem->g_buff.d_p_addr);
	ecdh_keygen_desc->ab_dma = cpu_to_be64(mem->ab_buff.d_p_addr);
	ecdh_keygen_desc->pubkey_dma = cpu_to_be64(mem->pubkey_buff.d_p_addr);
	ecdh_keygen_desc->prvkey_dma = cpu_to_be64(mem->prvkey_buff.d_p_addr);

	ecdh_keygen_desc->sgf_ln = cpu_to_be32((mem->q_buff.len<<7) | mem->r_buff.len);
	if(ecc_bin) {
		ecdh_keygen_desc->op = cpu_to_be32(CMD_OPERATION |
			OP_TYPE_UNI_PROTOCOL | OP_PCLID_PUBLICKEYPAIR |
			OP_PCL_PKPROT_ECC | OP_PCL_PKPROT_F2M);
	}
	else {
		ecdh_keygen_desc->op = cpu_to_be32(CMD_OPERATION |
			OP_TYPE_UNI_PROTOCOL | OP_PCLID_PUBLICKEYPAIR |
			OP_PCL_PKPROT_ECC);
	}

	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("R DMA: %llx\n", (uint64_t)mem->r_buff.d_p_addr);
	print_debug("G DMA: %llx\n", (uint64_t)mem->g_buff.d_p_addr);
	print_debug("PUBKEY DMA: %llx\n", (uint64_t)mem->pubkey_buff.d_p_addr);
	print_debug("PRVKEY DMA: %llx\n",(uint64_t) mem->prvkey_buff.d_p_addr);
	print_debug("AB DMA: %llx\n", (uint64_t)mem->ab_buff.d_p_addr);

#ifdef DEBUG_DESC
	print_error("[ECDH] Descriptor words\n");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}

static void constr_dh_keygen_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size = sizeof(struct dh_keygen_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	dh_keygen_buffers_t *mem = (dh_keygen_buffers_t *)(mem_info->buffers);
	struct dh_keygen_desc_s *dh_keygen_desc = (struct dh_keygen_desc_s *)mem->desc_buff.h_v_addr;

	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&dh_keygen_desc->desc_hdr,
		(start_idx << HDR_START_IDX_SHIFT) |
		(desc_size & HDR_DESCLEN_MASK) | HDR_ONE);

	dh_keygen_desc->q_dma = cpu_to_be64(mem->q_buff.d_p_addr);
	dh_keygen_desc->r_dma = cpu_to_be64(mem->r_buff.d_p_addr);
	dh_keygen_desc->g_dma = cpu_to_be64(mem->g_buff.d_p_addr);
	dh_keygen_desc->pubkey_dma = cpu_to_be64(mem->pubkey_buff.d_p_addr);
	dh_keygen_desc->prvkey_dma = cpu_to_be64(mem->prvkey_buff.d_p_addr);

	dh_keygen_desc->sgf_ln = cpu_to_be32((mem->q_buff.len<<7) | mem->r_buff.len);
	dh_keygen_desc->op = cpu_to_be32(CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_PUBLICKEYPAIR);

	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.d_p_addr);
	print_debug("R DMA: %llx\n", (uint64_t)mem->r_buff.d_p_addr);
	print_debug("G DMA: %llx\n", (uint64_t)mem->g_buff.d_p_addr);
	print_debug("PUBKEY DMA: %llx\n", (uint64_t)mem->pubkey_buff.d_p_addr);
	print_debug("PRVKEY DMA: %llx\n", (uint64_t)mem->prvkey_buff.d_p_addr);

#ifdef DEBUG_DESC
	print_error("[DH] Descriptor words\n");
	dump_desc(mem->desc_buff.h_v_addr, desc_size, __func__);
#endif
}


static void dh_key_init_crypto_mem(crypto_mem_info_t *crypto_mem, bool ecdh)
{
	dh_key_buffers_t *dh_key_buffs = NULL;

	crypto_mem->count = sizeof(dh_key_buffers_t) / sizeof(buffer_info_t);
	if (!ecdh) {
		crypto_mem->count -= 1;
	}

	crypto_mem->buffers =
	    (buffer_info_t *) (&(crypto_mem->c_buffers.dh_key));
	memset(crypto_mem->buffers, 0, sizeof(dh_key_buffers_t));

	/* Mark the op buffer */
	dh_key_buffs = (dh_key_buffers_t *) crypto_mem->buffers;
	dh_key_buffs->q_buff.bt = dh_key_buffs->w_buff.bt =
	    dh_key_buffs->s_buff.bt = dh_key_buffs->ab_buff.bt = BT_IP;
	dh_key_buffs->z_buff.bt = BT_OP;
}

static void dh_keygen_init_crypto_mem(crypto_mem_info_t *crypto_mem, bool ecdh)
{
    dh_keygen_buffers_t    *dh_key_buffs   =   NULL;

    crypto_mem->count       =   sizeof(dh_keygen_buffers_t)/sizeof(buffer_info_t);
    if(!ecdh) {
	    crypto_mem->count -= 1;
    }

    crypto_mem->buffers     =   (buffer_info_t *)(&(crypto_mem->c_buffers.dh_keygen));
    memset(crypto_mem->buffers, 0, sizeof(dh_keygen_buffers_t));
    /*crypto_ctx->crypto_mem.buffers        =   kzalloc(sizeof(rsa_pub_op_buffers_t), GFP_KERNEL);*/

    /* Mark the op buffer */
    dh_key_buffs    =   (dh_keygen_buffers_t *)crypto_mem->buffers;
    dh_key_buffs->q_buff.bt =   dh_key_buffs->r_buff.bt = dh_key_buffs->g_buff.bt = dh_key_buffs->ab_buff.bt = BT_IP;
    dh_key_buffs->prvkey_buff.bt    =   dh_key_buffs->pubkey_buff.bt    =   BT_OP;
}

int dh_op(struct pkc_request *req)
{
	int32_t ret = 0;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;
	dev_dma_addr_t sec_dma = 0;
	uint32_t r_id = 0;
	dh_key_buffers_t *dh_key_buffs = NULL;
	dh_keygen_buffers_t *dh_keygen_buffs = NULL;
	bool ecdh = false;
	bool ecc_bin = false;
	ctx_pool_t *ctx_pool;
	uint32_t ctx_pool_id;
	uint32_t sess_cnt;

	if (NULL != req->base.tfm) {
		crypto_dev_sess_t *c_sess;
		dh_completion_cb = pkc_request_complete;
		ecdh_completion_cb = pkc_request_complete;
		/* Get the session context from input request */
		c_sess = crypto_pkc_ctx(crypto_pkc_reqtfm(req));
		c_dev = c_sess->c_dev;
		r_id = c_sess->r_id;
		sess_cnt = atomic_read(&c_dev->crypto_dev_sess_cnt);
	}
	else
    {
        /* By default using first device --
         * Logic here will be replaced with LB */
        c_dev = get_crypto_dev(1);
        if (!c_dev) {
                print_error("Could not retrieve the device structure.\n");
                return -1;
        }

	sess_cnt = atomic_inc_return(&c_dev->crypto_dev_sess_cnt);
	r_id = 1 + sess_cnt % (c_dev->num_of_rings - 1);
    }
	ctx_pool_id = sess_cnt % NR_CTX_POOLS;
	ctx_pool = &c_dev->ctx_pool[ctx_pool_id];
	crypto_ctx = get_crypto_ctx(ctx_pool);
	print_debug("crypto_ctx addr: %p\n", crypto_ctx);

	/*TODO: Implement some kind of back-of mechanism with the driver
	 * returning EBUSY instead of generic errors.
	 */
	if (unlikely(!crypto_ctx)) {
		print_debug("Mem alloc failed....\n");
		return -ENOMEM;
	}

	print_debug("Ring selected: %d\n", r_id);
	crypto_ctx->ctx_pool = ctx_pool;
	crypto_ctx->crypto_mem.dev = c_dev;
	crypto_ctx->crypto_mem.buf_pool = c_dev->ring_pairs[r_id].buf_pool;
	print_debug("IP Buffer pool address: %p\n", crypto_ctx->crypto_mem.buf_pool);

	if (ECDH_COMPUTE_KEY == req->type || ECDH_KEYGEN == req->type) {
		ecdh = true;
		if (ECC_BINARY == req->curve_type) {
			ecc_bin = true;
		}
	}

	switch (req->type) {
	case DH_KEYGEN:
	case ECDH_KEYGEN:
		dh_keygen_init_crypto_mem(&crypto_ctx->crypto_mem, ecdh);
		dh_keygen_buffs = (dh_keygen_buffers_t *)crypto_ctx->crypto_mem.buffers;

		ret = dh_keygen_cp_req(&req->req_u.dh_keygenreq, &crypto_ctx->crypto_mem, ecdh);
		if (ret != 0) {
			goto out_nop;
		}
		print_debug("DH init mem complete..... \n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);
		print_debug("Host to dev convert complete.... \n");

		/* Constr the hw desc */
		if(ecdh) {
			constr_ecdh_keygen_desc(&crypto_ctx->crypto_mem, ecc_bin);
		} else {
			constr_dh_keygen_desc(&crypto_ctx->crypto_mem);
		}
		print_debug("Desc constr complete... \n");

		sec_dma =   dh_keygen_buffs->desc_buff.d_p_addr;

		/* Store the context */
		print_debug("[Enq] Desc addr: %llx Hbuffer addr: %p    Crypto ctx: %p \n",
				(uint64_t)dh_keygen_buffs->desc_buff.d_p_addr,
				dh_keygen_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(dh_keygen_buffs->desc_buff.h_v_addr, (unsigned long)crypto_ctx);
		break;
	case DH_COMPUTE_KEY:
	case ECDH_COMPUTE_KEY:
		dh_key_init_crypto_mem(&crypto_ctx->crypto_mem, ecdh);
		dh_key_buffs =
		    (dh_key_buffers_t *) crypto_ctx->crypto_mem.buffers;

		ret = dh_key_cp_req(&req->req_u.dh_req, &crypto_ctx->crypto_mem, ecdh);
		if (ret != 0) {
			goto out_nop;
		}
		print_debug("DH init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("Host to dev convert complete....\n");

		/* Constr the hw desc */
		if (ecdh) {
			constr_ecdh_key_desc(&crypto_ctx->crypto_mem, ecc_bin);
		} else{
			constr_dh_key_desc(&crypto_ctx->crypto_mem);
		}
		print_debug("Desc constr complete...\n");

		sec_dma = dh_key_buffs->desc_buff.d_p_addr;

		/* Store the context */
		print_debug("[Enq] Desc addr: %llx Hbuffer addr: %p	Crypto ctx: %p\n",
			    (uint64_t)dh_key_buffs->desc_buff.d_p_addr,
			    dh_key_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(dh_key_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);
		break;

	default:
		ret = -EINVAL;
		goto out_nop;
	}

	crypto_ctx->req.pkc = req;
	crypto_ctx->oprn = DH;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;

	if (ecdh) {
		crypto_ctx->op_done = ecdh_op_done;
	} else {
		crypto_ctx->op_done = dh_op_done;
	}
	print_debug("Before app_ring_enqueue\n");

	/* Now enqueue the job into the app ring */
	if (app_ring_enqueue(c_dev, r_id, sec_dma)) {
		ret = -1;
		goto error;
	}
	return -EINPROGRESS;

error:
	dealloc_crypto_mem(&crypto_ctx->crypto_mem);
out_nop:
	free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	return ret;
}
