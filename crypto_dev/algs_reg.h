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

#ifndef __ALGS_REG_H__
#define __ALGS_REG_H__

#include "compat.h"
#include "desc.h"

#define FSL_CRA_PRIORITY 4000

#ifndef VIRTIO_C2X0
extern int32_t fsl_algapi_init(void);
extern void fsl_algapi_exit(void);

extern int rsa_op(struct pkc_request *req);
extern int dsa_op(struct pkc_request *req);
extern int dh_op(struct pkc_request *req);

extern int ahash_import(struct ahash_request *req, const void *in);
extern int ahash_export(struct ahash_request *req, void *out);
extern int ahash_final(struct ahash_request *req);
extern int ahash_finup(struct ahash_request *req);
extern int ahash_update(struct ahash_request *req);
extern int ahash_init(struct ahash_request *req);
extern int ahash_digest(struct ahash_request *req);
extern int ahash_setkey(struct crypto_ahash *ahash,
			const uint8_t *key, unsigned int keylen);

extern int fsl_ablkcipher_setkey(struct crypto_ablkcipher *ablkcipher,
				 const u8 *key, unsigned int keylen);
extern int fsl_ablkcipher_decrypt(struct ablkcipher_request *req);
extern int fsl_ablkcipher_encrypt(struct ablkcipher_request *req);
#endif

/*struct list_head alg_list;*/

struct fsl_crypto_alg {
	struct list_head entry;
	int op_type;
	int alg_type;
	int alg_op;
	int class1_alg_type;
	int class2_alg_type;
	bool ahash;
	union {
		struct crypto_alg crypto_alg;
		struct ahash_alg ahash_alg;
	} u;
};

struct alg_template {
	char name[CRYPTO_MAX_ALG_NAME];
	char driver_name[CRYPTO_MAX_ALG_NAME];
	char hmac_name[CRYPTO_MAX_ALG_NAME];
	char hmac_driver_name[CRYPTO_MAX_ALG_NAME];

	uint32_t blocksize;
	uint32_t type;
	union {
		struct pkc_alg pkc;
		struct ahash_alg ahash;
		struct aead_alg aead;
		struct ablkcipher_alg blkcipher;
	} u;
	uint32_t alg_type;
	uint32_t alg_op;
	uint32_t class1_alg_type;
	uint32_t class2_alg_type;
};

#endif
