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

#include "algs_reg.h"
#include "common.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"

atomic_t selected_devices;
struct list_head alg_list;

/*****************************************************************************
 * Function     : fill_crypto_dev_sess_ctx
 *
 * Arguments    : ctx
 *              : op_type
 *
 * Return Value : void
 *
 * Description  : Fill the cryptodev context.
 *
 *****************************************************************************/
int fill_crypto_dev_sess_ctx(crypto_dev_sess_t *ctx, uint32_t op_type)
{
	uint32_t no_of_app_rings = 0;
	uint32_t no_of_devices = 0;
#ifndef HIGH_PERF
	uint32_t  new_device = 0;
	int device_status = 0, count = 0, cpu = 0;
	per_dev_struct_t *dev_stat = NULL;
	uint32_t loop_cnt = 0;
#endif

	no_of_devices = get_no_of_devices();
	if (0 >= no_of_devices) {
		print_error("No Device configured\n");
		return -1;
	}

#ifndef HIGH_PERF
	while (!device_status && count < no_of_devices) {
		new_device =
		    ((atomic_inc_return(&selected_devices) -
		      1) % no_of_devices) + 1;
		ctx->c_dev = get_crypto_dev(new_device);
		if (!ctx->c_dev) {
			print_error
			    ("Could not retrieve the device structure.\n");
			return -1;
		}
		cpu = get_cpu();
		dev_stat = per_cpu_ptr(ctx->c_dev->dev_status, cpu);
		put_cpu();

		device_status = atomic_read(&(dev_stat->device_status));
		if (device_status) {
			count = 0;
			break;
		}
		count++;
		if (++loop_cnt > 1000000) {
			print_error("Could not get an active device\n");
			return -1;
		}
	}
	if (!device_status) {
		print_error("No Device is ALIVE\n");
		return -1;
	}
#else
	ctx->c_dev = get_crypto_dev(1);
	if (!ctx->c_dev) {
		print_error("Could not retrieve the device structure.\n");
		return -1;
	}
#endif

	no_of_app_rings = ctx->c_dev->num_of_rings - 1;

	/* Select the ring in which this job has to be posted. */

	if (0 < no_of_app_rings) {
		ctx->r_id = atomic_inc_return(&ctx->c_dev->crypto_dev_sess_cnt);
		ctx->r_id = (ctx->r_id - 1) % no_of_app_rings + 1;
	} else {
		print_error("No application ring configured\n");
		return -1;
	}

	print_debug("C dev num of rings [%d] r_id [%d]\n",
		    ctx->c_dev->num_of_rings, ctx->r_id);

	/* For symmetric algos all the job under same session should
	 * go to same sec engine. Hence selecting one of the sec engine
	 * for the ring pair. This sec engine selection will be passed
	 * to firmware and firmware will enqueue the job to selected sec engine
	 */
/*
#define NO_SEC_ENGINE_ASSIGNED          -1
	if (SYMMETRIC == op_type) {
		if (ctx->sec_eng == NO_SEC_ENGINE_ASSIGNED) {
			fsl_h_rsrc_ring_pair_t *rp;
			rp = &ctx->c_dev->ring_pairs[ctx->r_id];
			ctx->sec_eng =
			    atomic_inc_return(&(rp->sec_eng_sel)) &
			    (rp->num_of_sec_engines);
		}
	}
*/
	return 0;
}

#ifndef VIRTIO_C2X0
#ifdef SYMMETRIC_OFFLOAD
static int sym_cra_init(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	struct fsl_crypto_alg *fsl_alg =
	    container_of(alg, struct fsl_crypto_alg, u.crypto_alg);

	crypto_dev_sess_t *ctx = crypto_tfm_ctx(tfm);
	struct sym_ctx *sym_ctx = &(ctx->u.symm);

	print_debug("SYM_CRA_INIT\n");

	if (-1 == fill_crypto_dev_sess_ctx(ctx, fsl_alg->op_type))
		return -1;

	/* copy descriptor header template value */
	sym_ctx->class1_alg_type =
	    OP_TYPE_CLASS1_ALG | fsl_alg->class1_alg_type;
	sym_ctx->class2_alg_type =
	    OP_TYPE_CLASS2_ALG | fsl_alg->class2_alg_type;
	sym_ctx->alg_op = OP_TYPE_CLASS2_ALG | fsl_alg->alg_op;

	return 0;
}

static void sym_cra_exit(struct crypto_tfm *tfm)
{
	/* Nothing to be done */
}
#endif /* SYMMETRIC_OFFLOAD */

static struct alg_template driver_algs[] = {
	{
	 .name = "pkc(rsa)",
	 .driver_name = "pkc-rsa-fsl",
	 .blocksize = 0,
	 .type = CRYPTO_ALG_TYPE_PKC_RSA,
	 .u.pkc = {
		   .pkc_op = rsa_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },

	{
	 .name = "pkc(dsa)",
	 .driver_name = "pkc-dsa-fsl",
	 .blocksize = 0,
	 .type = CRYPTO_ALG_TYPE_PKC_DSA,
	 .u.pkc = {
		   .pkc_op = dsa_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },
	{
	 .name = "pkc(dh)",
	 .driver_name = "pkc-dh-fsl",
	 .type = CRYPTO_ALG_TYPE_PKC_DH,
	 .u.pkc = {
		   .pkc_op = dh_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },
#ifdef HASH_OFFLOAD
	{
	 .name = "sha1",
	 .driver_name = "sha1-fsl",
	 .hmac_name = "hmac(sha1)",
	 .hmac_driver_name = "hmac-sha1-fsl",
	 .blocksize = SHA1_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_AHASH,
	 .u.ahash = {
		     .init = ahash_init,
		     .update = ahash_update,
		     .final = ahash_final,
		     .finup = ahash_finup,
		     .digest = ahash_digest,
		     .export = ahash_export,
		     .import = ahash_import,
		     .setkey = ahash_setkey,
		     .halg = {
			      .digestsize = SHA1_DIGEST_SIZE,
			      },
		     },
	 .alg_type = OP_ALG_ALGSEL_SHA1,
	 .alg_op = OP_ALG_ALGSEL_SHA1 | OP_ALG_AAI_HMAC,
	 }, {
	     .name = "sha224",
	     .driver_name = "sha224-fsl",
	     .hmac_name = "hmac(sha224)",
	     .hmac_driver_name = "hmac-sha224-fsl",
	     .blocksize = SHA224_BLOCK_SIZE,
	     .type = CRYPTO_ALG_TYPE_AHASH,
	     .u.ahash = {
			 .init = ahash_init,
			 .update = ahash_update,
			 .final = ahash_final,
			 .finup = ahash_finup,
			 .digest = ahash_digest,
			 .export = ahash_export,
			 .import = ahash_import,
			 .setkey = ahash_setkey,
			 .halg = {
				  .digestsize = SHA224_DIGEST_SIZE,
				  },
			 },
	     .alg_type = OP_ALG_ALGSEL_SHA224,
	     .alg_op = OP_ALG_ALGSEL_SHA224 | OP_ALG_AAI_HMAC,
	     }, {
		 .name = "sha256",
		 .driver_name = "sha256-fsl",
		 .hmac_name = "hmac(sha256)",
		 .hmac_driver_name = "hmac-sha256-fsl",
		 .blocksize = SHA256_BLOCK_SIZE,
		 .type = CRYPTO_ALG_TYPE_AHASH,
		 .u.ahash = {
			     .init = ahash_init,
			     .update = ahash_update,
			     .final = ahash_final,
			     .finup = ahash_finup,
			     .digest = ahash_digest,
			     .export = ahash_export,
			     .import = ahash_import,
			     .setkey = ahash_setkey,
			     .halg = {
				      .digestsize = SHA256_DIGEST_SIZE,
				      },
			     },
		 .alg_type = OP_ALG_ALGSEL_SHA256,
		 .alg_op = OP_ALG_ALGSEL_SHA256 | OP_ALG_AAI_HMAC,
		 }, {
		     .name = "sha384",
		     .driver_name = "sha384-fsl",
		     .hmac_name = "hmac(sha384)",
		     .hmac_driver_name = "hmac-sha384-fsl",
		     .blocksize = SHA384_BLOCK_SIZE,
		     .type = CRYPTO_ALG_TYPE_AHASH,
		     .u.ahash = {
				 .init = ahash_init,
				 .update = ahash_update,
				 .final = ahash_final,
				 .finup = ahash_finup,
				 .digest = ahash_digest,
				 .export = ahash_export,
				 .import = ahash_import,
				 .setkey = ahash_setkey,
				 .halg = {
					  .digestsize = SHA384_DIGEST_SIZE,
					  },
				 },
		     .alg_type = OP_ALG_ALGSEL_SHA384,
		     .alg_op = OP_ALG_ALGSEL_SHA384 | OP_ALG_AAI_HMAC,
		     }, {
			 .name = "sha512",
			 .driver_name = "sha512-fsl",
			 .hmac_name = "hmac(sha512)",
			 .hmac_driver_name = "hmac-sha512-fsl",
			 .blocksize = SHA512_BLOCK_SIZE,
			 .type = CRYPTO_ALG_TYPE_AHASH,
			 .u.ahash = {
				     .init = ahash_init,
				     .update = ahash_update,
				     .final = ahash_final,
				     .finup = ahash_finup,
				     .digest = ahash_digest,
				     .export = ahash_export,
				     .import = ahash_import,
				     .setkey = ahash_setkey,
				     .halg = {
					      .digestsize = SHA512_DIGEST_SIZE,
					      },
				     },
			 .alg_type = OP_ALG_ALGSEL_SHA512,
			 .alg_op = OP_ALG_ALGSEL_SHA512 | OP_ALG_AAI_HMAC,
			 }, {
			     .name = "md5",
			     .driver_name = "md5-fsl",
			     .hmac_name = "hmac(md5)",
			     .hmac_driver_name = "hmac-md5-fsl",
			     .blocksize = MD5_BLOCK_WORDS * 4,
			     .type = CRYPTO_ALG_TYPE_AHASH,
			     .u.ahash = {
					 .init = ahash_init,
					 .update = ahash_update,
					 .final = ahash_final,
					 .finup = ahash_finup,
					 .digest = ahash_digest,
					 .export = ahash_export,
					 .import = ahash_import,
					 .setkey = ahash_setkey,
					 .halg = {
						  .digestsize = MD5_DIGEST_SIZE,
						  },
					 },
			     .alg_type = OP_ALG_ALGSEL_MD5,
			     .alg_op = OP_ALG_ALGSEL_MD5 | OP_ALG_AAI_HMAC,
			     },
#endif
#ifdef SYMMETRIC_OFFLOAD
	/* ablkcipher descriptor */
	{
	 .name = "cbc(aes)",
	 .driver_name = "cbc-aes-fsl",
	 .blocksize = AES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	 .u.blkcipher = {
			 .setkey = fsl_ablkcipher_setkey,
			 .encrypt = fsl_ablkcipher_encrypt,
			 .decrypt = fsl_ablkcipher_decrypt,
			 .geniv = "eseqiv",
			 .min_keysize = AES_MIN_KEY_SIZE,
			 .max_keysize = AES_MAX_KEY_SIZE,
			 .ivsize = AES_BLOCK_SIZE,
			 },
	 .class1_alg_type = OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC,
	 },
	{
	 .name = "cbc(des3_ede)",
	 .driver_name = "cbc-3des-fsl",
	 .blocksize = DES3_EDE_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	 .u.blkcipher = {
			 .setkey = fsl_ablkcipher_setkey,
			 .encrypt = fsl_ablkcipher_encrypt,
			 .decrypt = fsl_ablkcipher_decrypt,
			 .geniv = "eseqiv",
			 .min_keysize = DES3_EDE_KEY_SIZE,
			 .max_keysize = DES3_EDE_KEY_SIZE,
			 .ivsize = DES3_EDE_BLOCK_SIZE,
			 },
	 .class1_alg_type = OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC,
	 },
	{
	 .name = "cbc(des)",
	 .driver_name = "cbc-des-fsl",
	 .blocksize = DES_BLOCK_SIZE,
	 .type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	 .u.blkcipher = {
			 .setkey = fsl_ablkcipher_setkey,
			 .encrypt = fsl_ablkcipher_encrypt,
			 .decrypt = fsl_ablkcipher_decrypt,
			 .geniv = "eseqiv",
			 .min_keysize = DES_KEY_SIZE,
			 .max_keysize = DES_KEY_SIZE,
			 .ivsize = DES_BLOCK_SIZE,
			 },
	 .class1_alg_type = OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC,
	 }
#endif
};

/*******************************************************************************
 * Function     : pkc_cra_init
 *
 * Arguments    : tfm
 *
 * Return Value : Error code
 *
 * Description  : cra_init for crypto_alg to setup the context.
 *
 ******************************************************************************/
static int pkc_cra_init(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	struct fsl_crypto_alg *fsl_alg =
	    container_of(alg, struct fsl_crypto_alg, u.crypto_alg);

	crypto_dev_sess_t *ctx = crypto_tfm_ctx(tfm);
	if (-1 == fill_crypto_dev_sess_ctx(ctx, fsl_alg->op_type))
		return -1;

	return 0;
}

/*******************************************************************************
 * Function     : pkc_cra_exit
 *
 * Arguments    : tfm
 *
 * Return Value : void
 *
 * Description  : cra_exit for crypto_alg.
 *
 ******************************************************************************/
static void pkc_cra_exit(struct crypto_tfm *tfm)
{

	/* Nothing to be done */

}

static struct fsl_crypto_alg *fsl_alg_alloc(struct alg_template *template,
					    bool keyed)
{
	struct crypto_alg *alg = NULL;
	struct fsl_crypto_alg *f_alg =
	    kzalloc(sizeof(struct fsl_crypto_alg), GFP_KERNEL);
	if (!f_alg) {
		print_error("failed to allocate fsl_crypto_alg\n");
		return NULL;
	}

	/* Fill the 'fsl_crypto_alg' */
	if (CRYPTO_ALG_TYPE_AHASH == template->type) {
		f_alg->u.ahash_alg = template->u.ahash;
		alg = &f_alg->u.ahash_alg.halg.base;
	} else {
		alg = &f_alg->u.crypto_alg;
	}

	if (keyed && (CRYPTO_ALG_TYPE_AHASH == template->type)) {
		snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->hmac_name);
		snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->hmac_driver_name);
	} else {
		snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->name);
		snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
			 template->driver_name);
	}
	alg->cra_module = THIS_MODULE;
	alg->cra_priority = FSL_CRA_PRIORITY;
	alg->cra_blocksize = template->blocksize;
	alg->cra_alignmask = 0;
	alg->cra_ctxsize = sizeof(crypto_dev_sess_t);
	alg->cra_flags = CRYPTO_ALG_ASYNC | template->type;

	switch (template->type) {
	case CRYPTO_ALG_TYPE_PKC_RSA:
	case CRYPTO_ALG_TYPE_PKC_DSA:
	case CRYPTO_ALG_TYPE_PKC_DH:
		alg->cra_init = pkc_cra_init;
		alg->cra_exit = pkc_cra_exit;
		alg->cra_type = &crypto_pkc_type;
		alg->cra_u.pkc = template->u.pkc;
		f_alg->ahash = false;
		f_alg->op_type = ASYMMETRIC;
		break;
	case CRYPTO_ALG_TYPE_AHASH:
#ifdef HASH_OFFLOAD
		alg->cra_init = hash_cra_init;
		alg->cra_exit = hash_cra_exit;
		alg->cra_type = &crypto_ahash_type;
		f_alg->alg_type = template->alg_type;
		f_alg->alg_op = template->alg_op;
		f_alg->ahash = true;
		f_alg->op_type = SYMMETRIC;
#endif
		break;

	case CRYPTO_ALG_TYPE_AEAD:
	case CRYPTO_ALG_TYPE_ABLKCIPHER:
#ifdef SYMMETRIC_OFFLOAD
		alg->cra_init = sym_cra_init;
		alg->cra_exit = sym_cra_exit;

		switch (template->type) {
#if 0
		case CRYPTO_ALG_TYPE_AEAD:
			alg->cra_type = &crypto_aead_type;
			alg->cra_aead = template->u.aead;
			break;
#endif
		case CRYPTO_ALG_TYPE_ABLKCIPHER:
			alg->cra_type = &crypto_ablkcipher_type;
			alg->cra_ablkcipher = template->u.blkcipher;
			break;
		}
		f_alg->class1_alg_type = template->class1_alg_type;
		f_alg->class2_alg_type = template->class2_alg_type;
		f_alg->alg_op = template->alg_op;
		f_alg->ahash = false;
		f_alg->op_type = SYMMETRIC;
#endif
		break;
	}

	return f_alg;
}

/*******************************************************************************
 * Function     : fsl_algapi_init
 *
 * Arguments    : void
 *
 * Return Value : Error code
 *
 * Description  : Registering Algorithms with kernel crypto API.
 *
 ******************************************************************************/
int32_t fsl_algapi_init(void)
{
	int loop, err;
	char *driver_alg_name;
	struct fsl_crypto_alg *f_alg;
	/* keyed == false: base algorithm, cipher or digest
	 * keyed == true : hashed digest */
	bool keyed;

	INIT_LIST_HEAD(&alg_list);

	for (loop = 0; loop < ARRAY_SIZE(driver_algs); loop++) {
		keyed = false;
#ifdef HMAC_OFFLOAD
l_start:
#endif
		f_alg = fsl_alg_alloc(&driver_algs[loop], keyed);

		if (!f_alg) {
			err = -ENOMEM;
			print_error("%s alg allocation failed\n",
				    driver_algs[loop].driver_name);
			goto out_err;
		}

		if (keyed) {
			print_debug("%s alg allocation successful\n",
					driver_algs[loop].hmac_driver_name);
		} else {
			print_debug("%s alg allocation successful\n",
					driver_algs[loop].driver_name);
		}

		if (f_alg->ahash) {
			err = crypto_register_ahash(&f_alg->u.ahash_alg);
			driver_alg_name =
			    f_alg->u.ahash_alg.halg.base.cra_driver_name;
		} else {
			err = crypto_register_alg(&f_alg->u.crypto_alg);
			driver_alg_name = f_alg->u.crypto_alg.cra_driver_name;
		}

		if (err) {
			print_error("%s alg registration failed\n",
				    driver_alg_name);
			kfree(f_alg);
			goto out_err;
		}

		print_debug("%s alg registration successful\n", driver_alg_name);
		list_add_tail(&f_alg->entry, &alg_list);

#ifdef HMAC_OFFLOAD
		/* after registering a digest algorithm, loop again to register
		 * the hashed (keyed) version of the same algorithm */
		if (f_alg->ahash && !keyed) {
			keyed = true;
			goto l_start;
		}
#endif
	}

	return 0;

out_err:
	fsl_algapi_exit();
	return err;
}

/*******************************************************************************
 * Function     : fsl_algapi_exit
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Deregistering Algorithms from kernel crypto API.
 *
 ******************************************************************************/
void fsl_algapi_exit(void)
{
	struct fsl_crypto_alg *f_alg, *temp;
	struct crypto_alg *alg = NULL;

	if (!alg_list.next)
		return;

	list_for_each_entry_safe(f_alg, temp, &alg_list, entry) {
		if (f_alg->ahash) {
			alg = &f_alg->u.ahash_alg.halg.base;
		} else {
			alg = &f_alg->u.crypto_alg;
		}
		crypto_unregister_alg(alg);
		list_del(&f_alg->entry);
		kfree(f_alg);
	}
}
#endif /* VIRTIO_C2X0 */
