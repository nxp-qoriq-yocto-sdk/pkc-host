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
#include "algs.h"
#include "pkc_desc.h"
#include "desc.h"
#include "memmgr.h"
#include "crypto_ctx.h"
#ifdef VIRTIO_C2X0
#include "fsl_c2x0_virtio.h"
#endif
#include "dma.h"

/*
#define DUMP_DESC_WORDS
#define PERFORMANCE_BUILD
#define DUMP_DEBUG_V_INFO
*/

/* Callback test functions */
typedef void (*dh_op_cb) (struct pkc_request *, int32_t result);
/* #ifdef KCAPI_INTEG_BUILD
dh_op_cb dh_completion_cb = pkc_request_complete;
dh_op_cb ecdh_completion_cb = pkc_request_complete;
#else  */
dh_op_cb dh_completion_cb;
dh_op_cb ecdh_completion_cb;
/* #endif */

static void dh_op_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[DH OP DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));

#ifndef VIRTIO_C2X0
	dh_completion_cb(crypto_ctx->req.pkc, res);

	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
#endif
#ifdef VIRTIO_C2X0
	/* Update the sec result to crypto job context */
	crypto_ctx->card_status = res;
	print_debug("Updated card status to %d\n", crypto_ctx->card_status);
#endif
}

static void ecdh_op_done(void *ctx, int32_t res)
{
	crypto_op_ctx_t *crypto_ctx = ctx;

	print_debug("[ECDH OP DONE ]\n");

	dealloc_crypto_mem(&(crypto_ctx->crypto_mem));

#ifndef VIRTIO_C2X0
	ecdh_completion_cb(crypto_ctx->req.pkc, res);

	free_crypto_ctx(crypto_ctx->ctx_pool, crypto_ctx);
#endif
#ifdef VIRTIO_C2X0
	/* Update the sec result to crypto job context */
	crypto_ctx->card_status = res;
	print_debug("Updated card status to %d\n", crypto_ctx->card_status);
#endif
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
#ifdef USE_HOST_DMA
	memcpy(mem->q_buff.v_mem, req->q, mem->q_buff.len);
	memcpy(mem->w_buff.v_mem, req->pub_key, mem->w_buff.len);
	memcpy(mem->s_buff.v_mem, req->s, mem->s_buff.len);

	if (ecdh)
		memcpy(mem->ab_buff.v_mem, req->ab, mem->ab_buff.len);
	else
		mem->ab_buff.v_mem = NULL;
#else
	mem->q_buff.req_ptr = req->q;
	mem->w_buff.req_ptr = req->pub_key;
	mem->s_buff.req_ptr = req->s;

	if (ecdh)
		mem->ab_buff.req_ptr = req->ab;
	else
		mem->ab_buff.req_ptr = NULL;
#endif
	mem->z_buff.v_mem = req->z;
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
#ifdef USE_HOST_DMA
    memcpy(mem->q_buff.v_mem, req->q, mem->q_buff.len);
    memcpy(mem->r_buff.v_mem, req->r, mem->r_buff.len);
    memcpy(mem->g_buff.v_mem, req->g, mem->g_buff.len);

    if(ecdh)
       memcpy(mem->ab_buff.v_mem, req->ab, mem->ab_buff.len);
    else
       mem->ab_buff.v_mem     =   NULL;
#else
    mem->q_buff.req_ptr         =   req->q;
    mem->r_buff.req_ptr         =   req->r;
    mem->g_buff.req_ptr         =   req->g;

    if(ecdh)
       mem->ab_buff.req_ptr     =   req->ab;
    else
       mem->ab_buff.req_ptr     =   NULL;
#endif
    mem->prvkey_buff.v_mem     =   req->prvkey;
    mem->pubkey_buff.v_mem     =   req->pubkey;
    return 0;
}

/* Desc constr functions */
static void constr_dh_key_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size = sizeof(struct dh_key_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	dh_key_buffers_t *mem = (dh_key_buffers_t *) (mem_info->buffers);
	struct dh_key_desc_s *dh_key_desc =
	    (struct dh_key_desc_s *)mem->desc_buff.v_mem;
#ifdef SEC_DMA
        dev_p_addr_t offset = mem_info->dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
#endif
#ifdef DUMP_DEBUG_V_INFO
	uint32_t *desc_buff = (uint32_t *) mem->desc_buff.v_mem;
#endif
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&dh_key_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

#ifdef SEC_DMA
        ASSIGN64(dh_key_desc->q_dma, (mem->q_buff.dev_buffer.h_p_addr + offset));
        ASSIGN64(dh_key_desc->w_dma, (mem->w_buff.dev_buffer.h_p_addr + offset));
        ASSIGN64(dh_key_desc->s_dma, (mem->s_buff.dev_buffer.h_p_addr + offset));
#else
	ASSIGN64(dh_key_desc->q_dma, mem->q_buff.dev_buffer.d_p_addr);
	ASSIGN64(dh_key_desc->w_dma, mem->w_buff.dev_buffer.d_p_addr);
	ASSIGN64(dh_key_desc->s_dma, mem->s_buff.dev_buffer.d_p_addr);
#endif
	ASSIGN64(dh_key_desc->z_dma, mem->z_buff.dev_buffer.d_p_addr);

	ASSIGN32(dh_key_desc->sgf_ln,
		 ((mem->q_buff.len << 7) | mem->s_buff.len));
	ASSIGN32(dh_key_desc->op,
		 (CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_DH));

#ifdef DUMP_DEBUG_V_INFO

	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.dev_buffer.d_p_addr);
	print_debug("W DMA: %llx\n", (uint64_t)mem->w_buff.dev_buffer.d_p_addr);
	print_debug("S DMA: %llx\n", (uint64_t)mem->s_buff.dev_buffer.d_p_addr);
	print_debug("Z DMA: %llx\n", (uint64_t)mem->z_buff.dev_buffer.d_p_addr);

	print_debug("[DH] Descriptor words\n");
	{
		uint32_t *words = (uint32_t *) desc_buff;
		uint32_t i = 0;
		for (i = 0; i < desc_size; i++)
			print_debug("Word %d: %x\n", i, words[i]);
	}
#endif
}

static void constr_ecdh_key_desc(crypto_mem_info_t *mem_info, bool ecc_bin)
{
	uint32_t desc_size = sizeof(struct ecdh_key_desc_s) / sizeof(uint32_t);
	uint32_t start_idx = desc_size - 1;

	dh_key_buffers_t *mem = (dh_key_buffers_t *) (mem_info->buffers);
	struct ecdh_key_desc_s *ecdh_key_desc =
	    (struct ecdh_key_desc_s *)mem->desc_buff.v_mem;
#ifdef SEC_DMA
        dev_p_addr_t offset = mem_info->dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
#endif
#ifdef DUMP_DEBUG_V_INFO
	uint32_t *desc_buff = (uint32_t *) mem->desc_buff.v_mem;
#endif
	start_idx &= HDR_START_IDX_MASK;
	init_job_desc(&ecdh_key_desc->desc_hdr,
		      (start_idx << HDR_START_IDX_SHIFT) | (desc_size &
							    HDR_DESCLEN_MASK) |
		      HDR_ONE);

#ifdef SEC_DMA
        ASSIGN64(ecdh_key_desc->q_dma, (mem->q_buff.dev_buffer.h_p_addr + offset));
        ASSIGN64(ecdh_key_desc->w_dma, (mem->w_buff.dev_buffer.h_p_addr + offset));
        ASSIGN64(ecdh_key_desc->s_dma, (mem->s_buff.dev_buffer.h_p_addr + offset));
        ASSIGN64(ecdh_key_desc->ab_dma, (mem->ab_buff.dev_buffer.h_p_addr + offset));
#else
	ASSIGN64(ecdh_key_desc->q_dma, mem->q_buff.dev_buffer.d_p_addr);
	ASSIGN64(ecdh_key_desc->w_dma, mem->w_buff.dev_buffer.d_p_addr);
	ASSIGN64(ecdh_key_desc->s_dma, mem->s_buff.dev_buffer.d_p_addr);
	ASSIGN64(ecdh_key_desc->ab_dma, mem->ab_buff.dev_buffer.d_p_addr);
#endif
	ASSIGN64(ecdh_key_desc->z_dma, mem->z_buff.dev_buffer.d_p_addr);

	ASSIGN32(ecdh_key_desc->sgf_ln,
		 ((mem->q_buff.len << 7) | mem->s_buff.len));
	if (ecc_bin)
		ASSIGN32(ecdh_key_desc->op,
			 (CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_DH |
			  OP_PCL_PKPROT_ECC | OP_PCL_PKPROT_F2M));
	else
		ASSIGN32(ecdh_key_desc->op,
			 (CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_DH |
			  OP_PCL_PKPROT_ECC));

#ifdef DUMP_DEBUG_V_INFO
	print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.dev_buffer.d_p_addr);
	print_debug("W DMA: %llx\n", (uint64_t)mem->w_buff.dev_buffer.d_p_addr);
	print_debug("S DMA: %llx\n", (uint64_t)mem->s_buff.dev_buffer.d_p_addr);
	print_debug("Z DMA: %llx\n", (uint64_t)mem->z_buff.dev_buffer.d_p_addr);
	print_debug("AB DMA: %llx\n", (uint64_t)mem->ab_buff.dev_buffer.d_p_addr);

	print_debug("[ECDH] Descriptor words\n");
	{
		uint32_t *words = (uint32_t *) desc_buff;
		uint32_t i = 0;
		for (i = 0; i < desc_size; i++)
			print_debug("Word %d: %x\n", i, words[i]);
	}
#endif
}

static void constr_ecdh_keygen_desc(crypto_mem_info_t *mem_info, bool ecc_bin)
{
    uint32_t    desc_size   =   sizeof(struct ecdh_keygen_desc_s) / sizeof(uint32_t);
    uint32_t    start_idx   =   desc_size - 1;

    dh_keygen_buffers_t   *mem            =   (dh_keygen_buffers_t *)(mem_info->buffers);
    struct ecdh_keygen_desc_s  *ecdh_keygen_desc  =   (struct ecdh_keygen_desc_s *)mem->desc_buff.v_mem;
#ifdef SEC_DMA
    dev_p_addr_t offset = mem_info->dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
#endif
#ifdef DUMP_DEBUG_V_INFO    
    uint32_t                *desc_buff      =   (uint32_t *)mem->desc_buff.v_mem;
#endif
    start_idx   &=  HDR_START_IDX_MASK;
    init_job_desc(&ecdh_keygen_desc->desc_hdr, (start_idx << HDR_START_IDX_SHIFT) | (desc_size & HDR_DESCLEN_MASK) | HDR_ONE);

#ifdef SEC_DMA
    ASSIGN64(ecdh_keygen_desc->q_dma, (mem->q_buff.dev_buffer.h_p_addr + offset));
    ASSIGN64(ecdh_keygen_desc->r_dma, (mem->r_buff.dev_buffer.h_p_addr + offset));
    ASSIGN64(ecdh_keygen_desc->g_dma, (mem->g_buff.dev_buffer.h_p_addr + offset));
    ASSIGN64(ecdh_keygen_desc->ab_dma, (mem->ab_buff.dev_buffer.h_p_addr + offset));
#else
    ASSIGN64(ecdh_keygen_desc->q_dma, mem->q_buff.dev_buffer.d_p_addr);
    ASSIGN64(ecdh_keygen_desc->r_dma, mem->r_buff.dev_buffer.d_p_addr);
    ASSIGN64(ecdh_keygen_desc->g_dma, mem->g_buff.dev_buffer.d_p_addr);
    ASSIGN64(ecdh_keygen_desc->ab_dma, mem->ab_buff.dev_buffer.d_p_addr);
#endif
    ASSIGN64(ecdh_keygen_desc->pubkey_dma, mem->pubkey_buff.dev_buffer.d_p_addr);
    ASSIGN64(ecdh_keygen_desc->prvkey_dma, mem->prvkey_buff.dev_buffer.d_p_addr);

    ASSIGN32(ecdh_keygen_desc->sgf_ln, ((mem->q_buff.len<<7) | mem->r_buff.len));
    if(ecc_bin) {
        ASSIGN32(ecdh_keygen_desc->op, (CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | 
                                        OP_PCLID_PUBLICKEYPAIR | OP_PCL_PKPROT_ECC | 
                                        OP_PCL_PKPROT_F2M));
    }
    else {
        ASSIGN32(ecdh_keygen_desc->op, (CMD_OPERATION | 
                        OP_TYPE_UNI_PROTOCOL | OP_PCLID_PUBLICKEYPAIR | 
                        OP_PCL_PKPROT_ECC));
    }

#ifdef DUMP_DEBUG_V_INFO

    print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.dev_buffer.d_p_addr);
    print_debug("R DMA: %llx\n", (uint64_t)mem->r_buff.dev_buffer.d_p_addr);
    print_debug("G DMA: %llx\n", (uint64_t)mem->g_buff.dev_buffer.d_p_addr);
    print_debug("PUBKEY DMA: %llx\n", (uint64_t)mem->pubkey_buff.dev_buffer.d_p_addr);
    print_debug("PRVKEY DMA: %llx\n",(uint64_t) mem->prvkey_buff.dev_buffer.d_p_addr);
    print_debug("AB DMA: %llx\n", (uint64_t)mem->ab_buff.dev_buffer.d_p_addr);
    print_debug("[ECDH] Descriptor words\n");
    {
        uint32_t    *words = (uint32_t *)desc_buff;
        uint32_t    i   =   0;
        for(i=0; i<desc_size; i++)
            print_debug("Word %d: %x\n", i, words[i]);
    }
#endif
}

static void constr_dh_keygen_desc(crypto_mem_info_t *mem_info)
{
    uint32_t    desc_size   =   sizeof(struct dh_keygen_desc_s) / sizeof(uint32_t);
    uint32_t    start_idx   =   desc_size - 1;

    dh_keygen_buffers_t *mem            =   (dh_keygen_buffers_t *)(mem_info->buffers);
    struct dh_keygen_desc_s *dh_keygen_desc =   (struct dh_keygen_desc_s *)mem->desc_buff.v_mem;
#ifdef SEC_DMA
    dev_p_addr_t offset = mem_info->dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
#endif
#ifdef DUMP_DEBUG_V_INFO    
    uint32_t                *desc_buff      =   (uint32_t *)mem->desc_buff.v_mem;
#endif
    start_idx   &=  HDR_START_IDX_MASK;
    init_job_desc(&dh_keygen_desc->desc_hdr, (start_idx << HDR_START_IDX_SHIFT) | (desc_size & HDR_DESCLEN_MASK) | HDR_ONE);

#ifdef SEC_DMA
    ASSIGN64(dh_keygen_desc->q_dma, (mem->q_buff.dev_buffer.h_p_addr + offset));
    ASSIGN64(dh_keygen_desc->r_dma, (mem->r_buff.dev_buffer.h_p_addr + offset));
    ASSIGN64(dh_keygen_desc->g_dma, (mem->g_buff.dev_buffer.h_p_addr + offset));
#else
    ASSIGN64(dh_keygen_desc->q_dma, mem->q_buff.dev_buffer.d_p_addr);
    ASSIGN64(dh_keygen_desc->r_dma, mem->r_buff.dev_buffer.d_p_addr);
    ASSIGN64(dh_keygen_desc->g_dma, mem->g_buff.dev_buffer.d_p_addr);
#endif
    ASSIGN64(dh_keygen_desc->pubkey_dma, mem->pubkey_buff.dev_buffer.d_p_addr);
    ASSIGN64(dh_keygen_desc->prvkey_dma, mem->prvkey_buff.dev_buffer.d_p_addr);

    ASSIGN32(dh_keygen_desc->sgf_ln, ((mem->q_buff.len<<7) | mem->r_buff.len));
    ASSIGN32(dh_keygen_desc->op, (CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | OP_PCLID_PUBLICKEYPAIR));

#ifdef DUMP_DEBUG_V_INFO

    print_debug("Q DMA: %llx\n", (uint64_t)mem->q_buff.dev_buffer.d_p_addr);
    print_debug("R DMA: %llx\n", (uint64_t)mem->r_buff.dev_buffer.d_p_addr);
    print_debug("G DMA: %llx\n", (uint64_t)mem->g_buff.dev_buffer.d_p_addr);
    print_debug("PUBKEY DMA: %llx\n", (uint64_t)mem->pubkey_buff.dev_buffer.d_p_addr);
    print_debug("PRVKEY DMA: %llx\n", (uint64_t)mem->prvkey_buff.dev_buffer.d_p_addr);

    print_debug("[DH] Descriptor words\n");
    {
        uint32_t    *words = (uint32_t *)desc_buff;
        uint32_t    i   =   0;
        for(i=0; i<desc_size; i++)
            print_debug("Word %d: %x\n", i, IO_BE_READ32(&words[i]));
    }
#endif
}


static void dh_key_init_crypto_mem(crypto_mem_info_t *crypto_mem, bool ecdh)
{
	dh_key_buffers_t *dh_key_buffs = NULL;

	crypto_mem->count = sizeof(dh_key_buffers_t) / sizeof(buffer_info_t);
	if (!ecdh)
		crypto_mem->count -= 1;

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
    if(!ecdh)
        crypto_mem->count -= 1;

    crypto_mem->buffers     =   (buffer_info_t *)(&(crypto_mem->c_buffers.dh_keygen));
    memset(crypto_mem->buffers, 0, sizeof(dh_keygen_buffers_t));
    /*crypto_ctx->crypto_mem.buffers        =   kzalloc(sizeof(rsa_pub_op_buffers_t), GFP_KERNEL);*/

    /* Mark the op buffer */
    dh_key_buffs    =   (dh_keygen_buffers_t *)crypto_mem->buffers;
    dh_key_buffs->q_buff.bt =   dh_key_buffs->r_buff.bt = dh_key_buffs->g_buff.bt = dh_key_buffs->ab_buff.bt = BT_IP;
    dh_key_buffs->prvkey_buff.bt    =   dh_key_buffs->pubkey_buff.bt    =   BT_OP;
}


#ifdef VIRTIO_C2X0
int dh_op(struct pkc_request *req, struct virtio_c2x0_job_ctx *virtio_job)
#else
int dh_op(struct pkc_request *req)
#endif
{
	int32_t ret = 0;
	crypto_dev_sess_t *c_sess = NULL;
	crypto_op_ctx_t *crypto_ctx = NULL;
	fsl_crypto_dev_t *c_dev = NULL;

	dev_dma_addr_t sec_dma = 0;
	uint32_t r_id = 0;
	dh_key_buffers_t *dh_key_buffs = NULL;
    dh_keygen_buffers_t   *dh_keygen_buffs  = NULL;
	bool ecdh = false;
	bool ecc_bin = false;

#ifdef SEC_DMA
        dev_p_addr_t offset;
#endif

#ifndef VIRTIO_C2X0
	if (NULL != req->base.tfm) {
		dh_completion_cb = pkc_request_complete;
		ecdh_completion_cb = pkc_request_complete;
		/* Get the session context from input request */
		c_sess =
		    (crypto_dev_sess_t *)
		    crypto_pkc_ctx(crypto_pkc_reqtfm(req));
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
        c_sess = c_sess;
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
        r_id =
            ((atomic_inc_return(&c_dev->crypto_dev_sess_cnt) -
                1) % (c_dev->num_of_rings - 1)) + 1;
#endif

    }

#ifdef SEC_DMA
        offset = c_dev->mem[MEM_TYPE_DRIVER].dev_p_addr;
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
	crypto_ctx->crypto_mem.pool = c_dev->ring_pairs[r_id].ip_pool;
	print_debug("IP Buffer pool address: %p\n", crypto_ctx->crypto_mem.pool);

	if (ECDH_COMPUTE_KEY == req->type || ECDH_KEYGEN == req->type) {
		ecdh = true;
		if (ECC_BINARY == req->curve_type)
			ecc_bin = true;
	}

	switch (req->type) {

    case DH_KEYGEN:
    case ECDH_KEYGEN:
            dh_keygen_init_crypto_mem(&crypto_ctx->crypto_mem, ecdh);
            dh_keygen_buffs    =   (dh_keygen_buffers_t *)crypto_ctx->crypto_mem.buffers;

            if(-ENOMEM == dh_keygen_cp_req(&req->req_u.dh_keygenreq, &crypto_ctx->crypto_mem, ecdh)) {
				ret = -ENOMEM;
                goto error;
			}
            print_debug("DH init mem complete..... \n");

            /* Convert the buffers to dev */
            host_to_dev(&crypto_ctx->crypto_mem);

            print_debug("Host to dev convert complete.... \n");

#ifdef SEC_DMA
            map_crypto_mem(&(crypto_ctx->crypto_mem));
#endif

            /* Constr the hw desc */
            if(ecdh)
                constr_ecdh_keygen_desc(&crypto_ctx->crypto_mem, ecc_bin);
            else
                constr_dh_keygen_desc(&crypto_ctx->crypto_mem);
            print_debug("Desc constr complete... \n");

#ifdef SEC_DMA
            sec_dma = dh_keygen_buffs->desc_buff.dev_buffer.h_p_addr + offset;
#else
            sec_dma =   dh_keygen_buffs->desc_buff.dev_buffer.d_p_addr;
#endif

            /* Store the context */
            print_debug("[Enq] Desc addr: %llx Hbuffer addr: %p    Crypto ctx: %p \n",
		(uint64_t)dh_keygen_buffs->desc_buff.dev_buffer.d_p_addr,
		dh_keygen_buffs->desc_buff.v_mem, crypto_ctx);

            store_priv_data(crypto_ctx->crypto_mem.pool, dh_keygen_buffs->desc_buff.v_mem, (unsigned long)crypto_ctx);

            break;

	case DH_COMPUTE_KEY:
	case ECDH_COMPUTE_KEY:
		dh_key_init_crypto_mem(&crypto_ctx->crypto_mem, ecdh);
		dh_key_buffs =
		    (dh_key_buffers_t *) crypto_ctx->crypto_mem.buffers;

		if (-ENOMEM ==
		    dh_key_cp_req(&req->req_u.dh_req, &crypto_ctx->crypto_mem,
				  ecdh)) {
			ret = -ENOMEM;
			goto error;
		}
		print_debug("DH init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("Host to dev convert complete....\n");

#ifdef SEC_DMA
            map_crypto_mem(&(crypto_ctx->crypto_mem));
#endif

		/* Constr the hw desc */
		if (ecdh)
			constr_ecdh_key_desc(&crypto_ctx->crypto_mem, ecc_bin);
		else
			constr_dh_key_desc(&crypto_ctx->crypto_mem);
		print_debug("Desc constr complete...\n");

#ifdef SEC_DMA
                sec_dma = dh_key_buffs->desc_buff.dev_buffer.h_p_addr + offset;
#else
		sec_dma = dh_key_buffs->desc_buff.dev_buffer.d_p_addr;
#endif

		/* Store the context */
		print_debug("[Enq] Desc addr: %llx Hbuffer addr: %p	Crypto ctx: %p\n",
			    (uint64_t)dh_key_buffs->desc_buff.dev_buffer.d_p_addr,
			    dh_key_buffs->desc_buff.v_mem, crypto_ctx);

		store_priv_data(crypto_ctx->crypto_mem.pool,
				dh_key_buffs->desc_buff.v_mem,
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
	    crypto_ctx->crypto_mem.buffers[BT_DESC].dev_buffer.h_map_p_addr;
#endif

#ifndef SEC_DMA
#ifndef USE_HOST_DMA
	memcpy_to_dev(&crypto_ctx->crypto_mem);
#endif
#endif

	crypto_ctx->req.pkc = req;
	crypto_ctx->oprn = DH;
	crypto_ctx->rid = r_id;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;

	if (ecdh)
		crypto_ctx->op_done = ecdh_op_done;
	else
		crypto_ctx->op_done = dh_op_done;
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
int test_dh_op(struct pkc_request *req,
	       void (*cb) (struct pkc_request *, int32_t result),
	       struct virtio_c2x0_job_ctx *virtio_job)
#else
int test_dh_op(struct pkc_request *req,
	       void (*cb) (struct pkc_request *, int32_t result))
#endif
{
    int32_t ret = 0;
	switch (req->type) {
	case DH_COMPUTE_KEY:
    case DH_KEYGEN:
		dh_completion_cb = cb;
		break;
	case ECDH_COMPUTE_KEY:
    case ECDH_KEYGEN:
		ecdh_completion_cb = cb;
		break;
	default:
		break;
	}
#ifdef VIRTIO_C2X0
	ret = dh_op(req, virtio_job);
#else
	ret = dh_op(req);
#endif
    if (-EINPROGRESS == ret)
        ret = 0;
    if (0 > ret)
        ret = -1;

    return ret;    
}

EXPORT_SYMBOL(test_dh_op);
