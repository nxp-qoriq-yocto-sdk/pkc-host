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

#include "debug_print.h"
#include "fsl_c2x0_driver.h"
#include "desc_constr.h"
#include "algs.h"

struct rng_init_compl {
	struct completion completion;
	uint32_t result;
};

static int32_t self_test_chk_res(uint32_t *output)
{
	int i = 0;
	uint32_t exp_res[8];
	int status = 0;

	uint32_t expected_result[8] = {
		0x3afe2c87,
		0xccb64449,
		0x19169a74,
		0xa1318bef,
		0xf4860bb9,
		0x5eeeae91,
		0x92f4a98f,
		0xb03718a4
	};
	change_desc_endianness(exp_res, expected_result, 8);

	for (i = 0; i < 8; i += 1)
		status |= (exp_res[i] ^ output[i]);

	if (status != 0) {
		print_error("RNG generated the incorrect results\n");
	}

	return status;
}

static void rng_init_done(void *ctx, uint32_t res)
{
	struct crypto_op_ctx *crypto_ctx = ctx;

	print_debug("[RNG INIT DONE ]\n");
	crypto_ctx->req.rng_init->result = res;
	complete(&crypto_ctx->req.rng_init->completion);
}


static int rng_self_test_cp_output(uint32_t *output, uint32_t length,
				   crypto_mem_info_t *mem_info)
{
	rng_self_test_buffers_t *mem = &mem_info->c_buffers.rng_self_test;

	mem->desc_buff.len = 55 * sizeof(uint32_t);
	mem->output_buff.len = length;

	if (-ENOMEM == alloc_crypto_mem(mem_info)) {
		return -ENOMEM;
	}

	mem->output_buff.h_v_addr = (uint8_t *) output;
	return 0;
}

static int rng_init_cp_pers_str(uint32_t *pers_str, uint32_t length,
				crypto_mem_info_t *mem_info)
{
	rng_init_buffers_t *mem = &mem_info->c_buffers.rng_init;

	mem->desc_buff.len = 11 * sizeof(uint32_t);
	mem->pers_str_buff.len = length;

	if (-ENOMEM == alloc_crypto_mem(mem_info)) {
		return -ENOMEM;
	}
	mem->pers_str_buff.h_v_addr = pers_str;
	return 0;
}

static void constr_rng_self_test_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size = 0;

	rng_self_test_buffers_t *mem =
	    (rng_self_test_buffers_t *) (mem_info->buffers);
	uint32_t *desc_buff = (uint32_t *) mem->desc_buff.h_v_addr;

	uint32_t l_desc[55] = {
		0xB0800037,
		0x04800010,
		0x5BA1853C,
		0xB1D0A950,
		0xEE9FA071,
		0x0BF2EC2E,
		0x02800020,
		0x2E2967B2,
		0x2D71BF85,
		0x3AF45FE8,
		0xFBB716A7,
		0x28B50BC4,
		0x64F5B627,
		0x5DCB2188,
		0x266C5F9B,
		0x12A00020,
		0x17DE200A,
		0x7E352965,
		0xAB776231,
		0x4E254628,
		0xA53BD234,
		0x329C5E6F,
		0xBBC1BD7A,
		0x85A39701,
		0x82500405,
		0xA2000001,
		0x10880004,
		0x00000005,
		0x12820004,
		0x00000020,
		0x82500001,
		0xA2000001,
		0x10880004,
		0x40000045,
		0x02800020,
		0xC79C388F,
		0xB0CBF7E7,
		0x3D07F26B,
		0x6D0B38FC,
		0x1A9D2EB2,
		0xB7FC64EE,
		0x498DB4A2,
		0xA4C39BDF,
		0x82500009,
		0xA2000001,
		0x10880004,
		0x00000005,
		0x82500001,
		0x60340020,
		0x00000000,
		0x00000000,
		0xA2000001,
		0x10880004,
		0x00000005,
		0x8250000D
	};

	l_desc[49] = (uint32_t) (mem->output_buff.d_p_addr >> 32);
	l_desc[50] = (uint32_t) mem->output_buff.d_p_addr;
	desc_size = desc_len(l_desc);
	change_desc_endianness(desc_buff, l_desc, desc_size);

#ifdef PRINT_DEBUG
	print_debug("OUTPUT DMA: %llx\n", (uint64_t)mem->output_buff.d_p_addr);
	print_debug("[RNG INIT] Descriptor words\n");
	{
		uint32_t *words = (uint32_t *) desc_buff;
		uint32_t i = 0;
		for (i = 0; i < desc_size; i++)
			print_debug("Word %d: %x\n", i, be32_to_cpu(words[i]));
	}
#endif
}

static void constr_rng_init_desc(crypto_mem_info_t *mem_info)
{
	uint32_t desc_size = 0;

	rng_init_buffers_t *mem = (rng_init_buffers_t *) (mem_info->buffers);
	uint32_t *desc_buff = (uint32_t *) mem->desc_buff.h_v_addr;

	uint32_t desc[11] = {
		0xB080000B,
		0x12200008,
		0x00000000,
		0x00000000,
		0x12810004,
		0x00000000,
		0x82500404,
		0xA2000001,
		0x10880004,
		0x00000001,
		0x82501000
	};

	desc[2] = (uint32_t) (mem->pers_str_buff.d_p_addr >> 32);
	desc[3] = (uint32_t) mem->pers_str_buff.d_p_addr;

	desc_size = desc_len(desc);
	change_desc_endianness(desc_buff, desc, desc_size);

#ifdef PRINT_DEBUG
	print_debug("PERS_STR DMA: %llx\n", (uint64_t)mem->pers_str_buff.d_p_addr);
	print_debug("[RNG INIT] Descriptor words\n");
	{
		uint32_t *words = (uint32_t *) desc_buff;
		uint32_t i = 0;
		for (i = 0; i < desc_size; i++)
			print_debug("Word %d: %x\n", i, be32_to_cpu(words[i]));
	}
#endif
}

static void rng_self_test_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rng_self_test_buffers_t *rng_self_test_buffs = NULL;

	crypto_mem->count =
	    sizeof(rng_self_test_buffers_t) / sizeof(buffer_info_t);

	crypto_mem->buffers =
	    (buffer_info_t *) (&(crypto_mem->c_buffers.rng_self_test));
	memset(crypto_mem->buffers, 0, sizeof(rng_self_test_buffers_t));

	rng_self_test_buffs = (rng_self_test_buffers_t *) crypto_mem->buffers;
	rng_self_test_buffs->output_buff.bt = BT_OP;
}

static void rng_init_init_crypto_mem(crypto_mem_info_t *crypto_mem)
{
	rng_init_buffers_t *rng_init_buffs = NULL;

	crypto_mem->count = sizeof(rng_init_buffers_t) / sizeof(buffer_info_t);

	crypto_mem->buffers =
	    (buffer_info_t *) (&(crypto_mem->c_buffers.rng_init));
	memset(crypto_mem->buffers, 0, sizeof(rng_init_buffers_t));

	rng_init_buffs = (rng_init_buffers_t *) crypto_mem->buffers;
	rng_init_buffs->pers_str_buff.bt = BT_IP;
}

int rng_op(struct c29x_dev *c_dev, uint32_t sec_no, crypto_op_t op)
{
	struct crypto_op_ctx *crypto_ctx = NULL;

	dev_dma_addr_t sec_dma = 0;
	uint32_t r_id;

	rng_init_buffers_t *rng_init_buffs = NULL;
	rng_self_test_buffers_t *rng_self_test_buffs = NULL;
	uint32_t *pers_str = NULL;
	uint32_t *output = NULL;
	uint32_t output_len;
	uint32_t pers_len;
	int32_t ret = 0;
	struct rng_init_compl r_init;

	init_completion(&r_init.completion);

	r_id = 0;

	crypto_ctx = get_crypto_ctx(c_dev->ctx_pool);
	print_debug("crypto_ctx addr: %p\n", crypto_ctx);

	if (unlikely(!crypto_ctx)) {
		print_debug("Mem alloc failed....\n");
		return -ENOMEM;
	}

	print_debug("Ring selected: %d\n", r_id);
	crypto_ctx->ctx_pool = c_dev->ctx_pool;
	crypto_ctx->crypto_mem.c_dev = c_dev;
	crypto_ctx->crypto_mem.buf_pool = &(c_dev->buf_pool[0]);
	print_debug("IP Buffer pool address: %p\n", crypto_ctx->crypto_mem.buf_pool);

	switch (op) {
	case RNG_INIT:
		rng_init_init_crypto_mem(&crypto_ctx->crypto_mem);
		rng_init_buffs =
		    (rng_init_buffers_t *) crypto_ctx->crypto_mem.buffers;
		pers_len = 8 * sizeof(uint32_t);
		pers_str = kzalloc(pers_len, GFP_KERNEL | GFP_DMA);
		if (pers_str == NULL) {
			ret = -ENOMEM;
			goto out_nop;
		}
		pers_str[0] = sec_no;
		ret = rng_init_cp_pers_str(pers_str, pers_len,
						&crypto_ctx->crypto_mem);
		if (ret != 0) {
			goto out_err_alloc;
		}

		print_debug("RNG init mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("Host to dev convert complete....\n");

		/* Constr the hw desc */
		constr_rng_init_desc(&crypto_ctx->crypto_mem);
		print_debug("Desc constr complete...\n");

		sec_dma = rng_init_buffs->desc_buff.d_p_addr;

		/* Store the context */
		print_debug("[Enq]Desc addr: %llx Hbuff addr: %p Crypto ctx: %p\n",
		     (uint64_t)rng_init_buffs->desc_buff.d_p_addr,
		     rng_init_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(rng_init_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);
		break;
	case RNG_SELF_TEST:
		rng_self_test_init_crypto_mem(&crypto_ctx->crypto_mem);
		rng_self_test_buffs =
		    (rng_self_test_buffers_t *) crypto_ctx->crypto_mem.buffers;

		output_len = 16 * sizeof(uint32_t);
		output = kzalloc(output_len, GFP_KERNEL | GFP_DMA);
		if (!output) {
			ret = -ENOMEM;
			goto out_nop;
		}

		ret = rng_self_test_cp_output(output, output_len,
						&crypto_ctx->crypto_mem);
		if (ret != 0) {
			goto out_err_alloc;
		}

		print_debug("RNG self test mem complete.....\n");

		/* Convert the buffers to dev */
		host_to_dev(&crypto_ctx->crypto_mem);

		print_debug("Host to dev convert complete....\n");

		/* Constr the hw desc */
		constr_rng_self_test_desc(&crypto_ctx->crypto_mem);
		print_debug("Desc constr complete...\n");

		sec_dma = rng_self_test_buffs->desc_buff.d_p_addr;

		/* Store the context */
		print_debug("[Enq]Desc addr: %llx Hbuff addr: %p Crypto ctx: %p\n",
		     (uint64_t) rng_self_test_buffs->desc_buff.d_p_addr,
		     rng_self_test_buffs->desc_buff.h_v_addr, crypto_ctx);

		store_priv_data(rng_self_test_buffs->desc_buff.h_v_addr,
				(unsigned long)crypto_ctx);
		break;
	default:
		ret = -EINVAL;
		goto out_nop;
	}

	crypto_ctx->oprn = op;
	crypto_ctx->req.rng_init = &r_init;
	crypto_ctx->desc = sec_dma;
	crypto_ctx->c_dev = c_dev;
	crypto_ctx->op_done = rng_init_done;

	sec_dma = sec_dma | (uint64_t) sec_no;
	if (ring_enqueue(c_dev, r_id, sec_dma)) {
		ret = -1;
		goto out_enq_fail;
	}
	wait_for_completion_interruptible(&r_init.completion);

	ret = r_init.result;
	if (crypto_ctx->oprn == RNG_SELF_TEST) {
		if (ret) {
			print_error("RNG SELF TEST Failed\n");
		} else {
			ret = self_test_chk_res(output);
		}
	} else {
		if (ret) {
			print_error("RNG INIT Failed\n");
		}
	}

out_enq_fail:
	dealloc_crypto_mem(&crypto_ctx->crypto_mem);
out_err_alloc:
	if (crypto_ctx->oprn == RNG_INIT) {
		kfree(pers_str);
	}
	if (crypto_ctx->oprn == RNG_SELF_TEST) {
		kfree(output);
	}
out_nop:
	free_crypto_ctx(c_dev->ctx_pool, crypto_ctx);
	return ret;
}

int32_t rng_instantiation(struct c29x_dev *c_dev)
{
	uint32_t no_of_secs;
	uint32_t i;
	int32_t err = -ENODEV;

	no_of_secs = be32_to_cpu(c_dev->hs_mem->data.device.no_secs);

	for (i = 1; i <= no_of_secs; i++) {
		err = rng_op(c_dev, i, RNG_SELF_TEST);
		if (err) {
			break;
		}
		err = rng_op(c_dev, i, RNG_INIT);
		if (err) {
			break;
		}
	}
	return err;
}
