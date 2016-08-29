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

#ifndef FSL_PKC_ALG_H
#define FSL_PKC_ALG_H

#include "desc_buffs.h"
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include "common.h"
#include "desc_constr.h"
#include "rsa.h"
#include "dsa.h"
#include "dh.h"

/* extern struct instantiate_result; */
/* Enum identifying the type of operation :- Symmetric/Asymmetric */
typedef enum crypto_op_type {
	SYMMETRIC,
	ASYMMETRIC
} crypto_op_type_t;

/* Enum identifying the Crypto operations */
typedef enum crypto_op {
	RSA,
	DSA,
	DH,
	RNG,
	RNG_INIT,
	RNG_SELF_TEST,
} crypto_op_t;


/*struct list_head alg_list;*/

struct fsl_crypto_alg {
	struct list_head entry;
	uint32_t op_type;
	uint32_t alg_type;
	uint32_t alg_op;
	uint32_t class1_alg_type;
	uint32_t class2_alg_type;
	struct crypto_alg crypto_alg;
};

/*******************************************************************************
Description :   Defines the crypto dev session context. This context is created
		at the time of new crypto dev session.
Fields      :   c_dev:	Crypto device instance to which this session belongs
		r_id :	Id of the ring to which this session belongs
		sec_eng:Id of the sec engine to which this session belongs.
			Used only in case of Symmetric algorithms
*******************************************************************************/
typedef struct crypto_dev_sess {
	fsl_crypto_dev_t *c_dev;
	uint32_t r_id;
	uint8_t sec_eng;
} crypto_dev_sess_t;

/******************************************************************************
Description :	Defines the context for the crypto job
Fields      :	pci_dev:PCI device instance to which this job belongs to.
		pool   :Buffer pool from which memory for this job is
			allocated
		req_mem:Pointer to the complete request memory
		oprn   :Identifies the crypto operation
		req    :Union of different crypto req mem from KCAPI
		dev_mem:Union of different crypto
		done   :Callback to be called on completion of the request
*******************************************************************************/
typedef struct crypto_job_ctx {
	void *pci_dev;		
	void *pool;
	void *req_mem;

	crypto_op_t oprn;
	union {
		struct pkc_request *pkc;
	} req;
	union {
		rsa_dev_mem_t *rsa;
		dsa_dev_mem_t *dsa;
		dh_key_dev_mem_t *dh;
		struct instantiate_result *rng_init;
		struct buf_data *rng;
	} dev_mem;
	struct split_key_result *result;
	void (*done) (struct pkc_request *req, int32_t result);
} crypto_job_ctx_t;

typedef struct crypto_op_ctx {
	void *ctx_pool; /* pointer to the enclosing pool */
	crypto_mem_info_t crypto_mem;
	crypto_op_t oprn;
	dev_dma_addr_t desc;
	fsl_crypto_dev_t *c_dev;
	union {
		struct pkc_request *pkc;
		struct rng_init_compl *rng_init;
		struct buf_data *rng;
	} req;
	void (*op_done) (void *ctx, int32_t result);
	struct crypto_op_ctx *next;
} crypto_op_ctx_t;

/*******************************************************************************
Description :   Defines the context for application request entry.
		This will be use by firmware in response processing.
Fields      :   r_offset:	Offset of the ring to which this req belongs.
*******************************************************************************/
typedef struct app_req_job_ctx {
	dev_p_addr_t r_offset;
} app_req_job_ctx_t;

void dump_desc(void *buff, uint32_t desc_size, const uint8_t *func);
void change_desc_endianness(uint32_t *dev_mem,
			    uint32_t *host_mem, int32_t words);
#endif
