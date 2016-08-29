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

	no_of_devices = get_no_of_devices();
	if (0 >= no_of_devices) {
		print_error("No Device configured\n");
		return -1;
	}

	ctx->c_dev = get_crypto_dev(1);
	if (!ctx->c_dev) {
		print_error("Could not retrieve the device structure.\n");
		return -1;
	}

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
	return 0;
}

#ifndef VIRTIO_C2X0
static struct alg_template driver_algs[] = {
	{
	 .name = "pkc(rsa)",
	 .driver_name = "pkc-rsa-fsl",
	 .blocksize = 0,
	 .type = CRYPTO_ALG_TYPE_PKC_RSA,
	 .pkc = {
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
	 .pkc = {
		   .pkc_op = dsa_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },
	{
	 .name = "pkc(dh)",
	 .driver_name = "pkc-dh-fsl",
	 .type = CRYPTO_ALG_TYPE_PKC_DH,
	 .pkc = {
		   .pkc_op = dh_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },
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
	    container_of(alg, struct fsl_crypto_alg, crypto_alg);

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

static struct fsl_crypto_alg *fsl_alg_alloc(struct alg_template *template)
{
	struct crypto_alg *alg = NULL;
	struct fsl_crypto_alg *f_alg =
	    kzalloc(sizeof(struct fsl_crypto_alg), GFP_KERNEL);
	if (!f_alg) {
		print_error("failed to allocate fsl_crypto_alg\n");
		return NULL;
	}

	alg = &f_alg->crypto_alg;

	snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s", template->name);
	snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s", template->driver_name);

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
		alg->cra_u.pkc = template->pkc;
		f_alg->op_type = ASYMMETRIC;
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

	INIT_LIST_HEAD(&alg_list);

	for (loop = 0; loop < ARRAY_SIZE(driver_algs); loop++) {
		f_alg = fsl_alg_alloc(&driver_algs[loop]);
		if (!f_alg) {
			err = -ENOMEM;
			print_error("%s alg allocation failed\n",
				    driver_algs[loop].driver_name);
			goto out_err;
		}
		print_debug("%s alg allocation successful\n",
				driver_algs[loop].driver_name);

		err = crypto_register_alg(&f_alg->crypto_alg);
		driver_alg_name = f_alg->crypto_alg.cra_driver_name;

		if (err) {
			print_error("%s alg registration failed\n",
				    driver_alg_name);
			kfree(f_alg);
			goto out_err;
		}

		print_debug("%s alg registration successful\n", driver_alg_name);
		list_add_tail(&f_alg->entry, &alg_list);
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
		alg = &f_alg->crypto_alg;
		crypto_unregister_alg(alg);
		list_del(&f_alg->entry);
		kfree(f_alg);
	}
}
#endif /* VIRTIO_C2X0 */
