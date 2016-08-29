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

#ifndef FSL_PKC_DESC_BUFFS_H
#define FSL_PKC_DESC_BUFFS_H

#include "types.h"

typedef struct fsl_crypto_dev fsl_crypto_dev_t;

typedef enum buffer_type {
	BT_DESC,
	BT_IP,
	BT_OP,
	BT_TMP,
} buffer_type_t;

struct buffer_info {
	buffer_type_t bt;

	uint32_t len;
	void *h_v_addr;
	dma_addr_t h_dma_addr;

	dev_p_addr_t d_p_addr;
} __packed;

typedef struct buffer_info buffer_info_t;

typedef struct rsa_pub_op_buffers {
	buffer_info_t desc_buff;
	buffer_info_t n_buff;
	buffer_info_t e_buff;
	buffer_info_t f_buff;
	buffer_info_t g_buff;
} rsa_pub_op_buffers_t;

typedef struct rsa_priv1_op_buffers {
	buffer_info_t desc_buff;
	buffer_info_t n_buff;
	buffer_info_t d_buff;
	buffer_info_t g_buff;
	buffer_info_t f_buff;
} rsa_priv1_op_buffers_t;

typedef struct rsa_priv2_op_buffers {
	buffer_info_t desc_buff;
	buffer_info_t p_buff;
	buffer_info_t q_buff;
	buffer_info_t d_buff;
	buffer_info_t f_buff;
	buffer_info_t g_buff;
	buffer_info_t tmp1_buff;
	buffer_info_t tmp2_buff;
} rsa_priv2_op_buffers_t;

typedef struct rsa_priv3_op_buffers {
	buffer_info_t desc_buff;
	buffer_info_t p_buff;
	buffer_info_t q_buff;
	buffer_info_t dp_buff;
	buffer_info_t dq_buff;
	buffer_info_t f_buff;
	buffer_info_t g_buff;
	buffer_info_t c_buff;
	buffer_info_t tmp1_buff;
	buffer_info_t tmp2_buff;
} rsa_priv3_op_buffers_t;

typedef struct dsa_sign_buffers {
	buffer_info_t desc_buff;
	buffer_info_t q_buff;
	buffer_info_t r_buff;
	buffer_info_t g_buff;
	buffer_info_t priv_key_buff;
	buffer_info_t m_buff;
	buffer_info_t tmp_buff;
	buffer_info_t c_buff;
	buffer_info_t d_buff;
	buffer_info_t ab_buff;
} dsa_sign_buffers_t;

typedef struct dsa_verify_buffers {
	buffer_info_t desc_buff;
	buffer_info_t q_buff;
	buffer_info_t r_buff;
	buffer_info_t g_buff;
	buffer_info_t pub_key_buff;
	buffer_info_t m_buff;
	buffer_info_t tmp_buff;
	buffer_info_t c_buff;
	buffer_info_t d_buff;
	buffer_info_t ab_buff;
} dsa_verify_buffers_t;

typedef struct dsa_keygen_buffers {
	buffer_info_t desc_buff;
	buffer_info_t q_buff;
	buffer_info_t r_buff;
	buffer_info_t g_buff;
	buffer_info_t prvkey_buff;
	buffer_info_t pubkey_buff;
	buffer_info_t ab_buff;
} dsa_keygen_buffers_t;

typedef struct dh_key_buffers {
	buffer_info_t desc_buff;
	buffer_info_t q_buff;
	buffer_info_t w_buff;
	buffer_info_t s_buff;
	buffer_info_t z_buff;
	buffer_info_t ab_buff;
} dh_key_buffers_t;

typedef struct dh_keygen_buffers {
    buffer_info_t   desc_buff;
    buffer_info_t   q_buff;
    buffer_info_t   r_buff;
    buffer_info_t   g_buff;
    buffer_info_t   prvkey_buff;
    buffer_info_t   pubkey_buff;
    buffer_info_t   ab_buff;
}dh_keygen_buffers_t;

typedef struct rng_init_buffers {
	buffer_info_t desc_buff;
	buffer_info_t pers_str_buff;
} rng_init_buffers_t;

typedef struct rng_self_test_buffers {
	buffer_info_t desc_buff;
	buffer_info_t output_buff;
} rng_self_test_buffers_t;

typedef struct rng_buffers {
	buffer_info_t desc_buff;
	buffer_info_t output_buff;
	buffer_info_t sh_desc_buff;
} rng_buffers_t;

typedef union crypto_buffers {
	rsa_pub_op_buffers_t rsa_pub_op;
	rsa_priv1_op_buffers_t rsa_priv1_op;
	rsa_priv2_op_buffers_t rsa_priv2_op;
	rsa_priv3_op_buffers_t rsa_priv3_op;
	dsa_sign_buffers_t dsa_sign;
	dsa_verify_buffers_t dsa_verify;
	dsa_keygen_buffers_t dsa_keygen;
	dh_key_buffers_t dh_key;
	dh_keygen_buffers_t dh_keygen;
	rng_init_buffers_t rng_init;
	rng_self_test_buffers_t rng_self_test;
	rng_buffers_t rng;
} crypto_buffers_t;

typedef struct crypto_mem_info {
	uint32_t count;
	void *src_buff;
	buffer_info_t *buffers;
	struct buffer_pool *buf_pool;
	fsl_crypto_dev_t *dev;
	crypto_buffers_t c_buffers;
} crypto_mem_info_t;

void host_to_dev(crypto_mem_info_t *mem_info);
int32_t dealloc_crypto_mem(crypto_mem_info_t *mem_info);
int32_t alloc_crypto_mem(crypto_mem_info_t *mem_info);
#endif
