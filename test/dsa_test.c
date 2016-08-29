/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
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

#include <linux/completion.h>
#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "pkc_desc.h"
#include "desc.h"

#include "test.h"
#include "dsa_test.h"

int dsa_keygen_sign_test(struct pkc_request *ireq, struct pkc_request *);
int dsa_keygen_verify_test(struct pkc_request *ireq, struct pkc_request *ireq1,
			   struct pkc_request *);

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);
/*
static DECLARE_COMPLETION(jobs_done);
static int count;
*/
atomic_t dsa_enq_count;
atomic_t dsa_deq_count;
extern atomic_t total_enq_cnt;
struct pkc_request g_dsaverifyreq_1k;
struct pkc_request g_dsasignreq_1k;
struct pkc_request g_dsaverifyreq_2k;
struct pkc_request g_dsasignreq_2k;
struct pkc_request g_dsaverifyreq_4k;
struct pkc_request g_dsasignreq_4k;

struct completion serialize_keygen;

void dsa_done(struct pkc_request *req, int32_t sec_result)
{
	common_dec_count();
}

void dsa_keygen_done(struct pkc_request *req, int32_t sec_result)
{
	print_debug("req: %p, result: %x \n", req, sec_result);
	complete(&serialize_keygen);
}

void dsa_sign_verify_sign_done(struct pkc_request *req, int32_t sec_result)
{
	dsa_sign_verify_verify_test(req);

	kfree(req->req_u.dsa_sign.q);
        kfree(req->req_u.dsa_sign.r);
        kfree(req->req_u.dsa_sign.g);
        kfree(req->req_u.dsa_sign.priv_key);
        kfree(req->req_u.dsa_sign.m);
	kfree(req->req_u.dsa_sign.c);
	kfree(req->req_u.dsa_sign.d);
	kfree(req);
}

void dsa_sign_verify_verify_done(struct pkc_request *req, int32_t sec_result)
{
        kfree(req->req_u.dsa_verify.q);
        kfree(req->req_u.dsa_verify.r);
        kfree(req->req_u.dsa_verify.g);
        kfree(req->req_u.dsa_verify.pub_key);
        kfree(req->req_u.dsa_verify.m);
	kfree(req->req_u.dsa_verify.c);
	kfree(req->req_u.dsa_verify.d);
	kfree(req);
	common_dec_count();
}

void init_dsa_verify_test_1k(void)
{
	g_dsaverifyreq_1k.type = DSA_VERIFY;

        g_dsaverifyreq_1k.req_u.dsa_verify.q = kzalloc(q_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_1k.req_u.dsa_verify.q, Q_1024, q_len);

        g_dsaverifyreq_1k.req_u.dsa_verify.r = kzalloc(r_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_1k.req_u.dsa_verify.r, R_1024, r_len);

        g_dsaverifyreq_1k.req_u.dsa_verify.g = kzalloc(g_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_1k.req_u.dsa_verify.g, G_1024, g_len);

        g_dsaverifyreq_1k.req_u.dsa_verify.pub_key = kzalloc(pub_key_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_1k.req_u.dsa_verify.pub_key, PUB_KEY_1024, pub_key_len);

        g_dsaverifyreq_1k.req_u.dsa_verify.m = kzalloc(m_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_1k.req_u.dsa_verify.m, M_1024, m_len);

        g_dsaverifyreq_1k.req_u.dsa_verify.c = kzalloc(q_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_1k.req_u.dsa_verify.c, C, q_len);

        g_dsaverifyreq_1k.req_u.dsa_verify.d = kzalloc(d, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_1k.req_u.dsa_verify.d, D, d);

	g_dsaverifyreq_1k.req_u.dsa_verify.q_len = (q_len);
	g_dsaverifyreq_1k.req_u.dsa_verify.r_len = (r_len);
	g_dsaverifyreq_1k.req_u.dsa_verify.g_len = (g_len);
	g_dsaverifyreq_1k.req_u.dsa_verify.pub_key_len = (pub_key_len);
	g_dsaverifyreq_1k.req_u.dsa_verify.m_len = (m_len);
	g_dsaverifyreq_1k.req_u.dsa_verify.d_len = d;
}

void init_dsa_sign_test_1k(void)
{
	g_dsasignreq_1k.type = DSA_SIGN;

        g_dsasignreq_1k.req_u.dsa_sign.q = kzalloc(q_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_1k.req_u.dsa_sign.q, Q_1024, q_len);

        g_dsasignreq_1k.req_u.dsa_sign.r = kzalloc(r_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_1k.req_u.dsa_sign.r, R_1024, r_len);

        g_dsasignreq_1k.req_u.dsa_sign.g = kzalloc(g_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_1k.req_u.dsa_sign.g, G_1024, g_len);

        g_dsasignreq_1k.req_u.dsa_sign.priv_key = kzalloc(priv_key_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_1k.req_u.dsa_sign.priv_key, PRIV_KEY_1024, priv_key_len);

        g_dsasignreq_1k.req_u.dsa_sign.m = kzalloc(m_len, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_1k.req_u.dsa_sign.m, M_1024, m_len);

	g_dsasignreq_1k.req_u.dsa_sign.c = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
	g_dsasignreq_1k.req_u.dsa_sign.d = kzalloc(d_len, GFP_KERNEL | GFP_DMA);

	g_dsasignreq_1k.req_u.dsa_sign.q_len = (q_len);
	g_dsasignreq_1k.req_u.dsa_sign.r_len = (r_len);
	g_dsasignreq_1k.req_u.dsa_sign.g_len = (g_len);
	g_dsasignreq_1k.req_u.dsa_sign.priv_key_len = (priv_key_len);
	g_dsasignreq_1k.req_u.dsa_sign.m_len = (m_len);
	g_dsasignreq_1k.req_u.dsa_sign.d_len = d_len;
}

void init_dsa_verify_test_2k(void)
{
	g_dsaverifyreq_2k.type = DSA_VERIFY;

        g_dsaverifyreq_2k.req_u.dsa_verify.q = kzalloc(q_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_2k.req_u.dsa_verify.q, Q_2048, q_len_2048);

        g_dsaverifyreq_2k.req_u.dsa_verify.r = kzalloc(r_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_2k.req_u.dsa_verify.r, R_2048, r_len_2048);

        g_dsaverifyreq_2k.req_u.dsa_verify.g = kzalloc(g_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_2k.req_u.dsa_verify.g, G_2048, g_len_2048);

        g_dsaverifyreq_2k.req_u.dsa_verify.pub_key = kzalloc(pub_key_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_2k.req_u.dsa_verify.pub_key, PUB_KEY_2048, pub_key_len_2048);

        g_dsaverifyreq_2k.req_u.dsa_verify.m = kzalloc(m_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_2k.req_u.dsa_verify.m, M_2048, m_len_2048);

        g_dsaverifyreq_2k.req_u.dsa_verify.c = kzalloc(q_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_2k.req_u.dsa_verify.c, C_2048, q_len_2048);

        g_dsaverifyreq_2k.req_u.dsa_verify.d = kzalloc(d_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_2k.req_u.dsa_verify.d, D_2048, d_2048);

	g_dsaverifyreq_2k.req_u.dsa_verify.q_len = (q_len_2048);
	g_dsaverifyreq_2k.req_u.dsa_verify.r_len = (r_len_2048);
	g_dsaverifyreq_2k.req_u.dsa_verify.g_len = (g_len_2048);
	g_dsaverifyreq_2k.req_u.dsa_verify.pub_key_len = (pub_key_len_2048);
	g_dsaverifyreq_2k.req_u.dsa_verify.m_len = (m_len_2048);
	g_dsaverifyreq_2k.req_u.dsa_verify.d_len = d_2048;
}

void init_dsa_sign_test_2k(void)
{
	g_dsasignreq_2k.type = DSA_SIGN;

        g_dsasignreq_2k.req_u.dsa_sign.q = kzalloc(q_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_2k.req_u.dsa_sign.q, Q_2048, q_len_2048);

        g_dsasignreq_2k.req_u.dsa_sign.r = kzalloc(r_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_2k.req_u.dsa_sign.r, R_2048, r_len_2048);

        g_dsasignreq_2k.req_u.dsa_sign.g = kzalloc(g_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_2k.req_u.dsa_sign.g, G_2048, g_len_2048);

        g_dsasignreq_2k.req_u.dsa_sign.priv_key = kzalloc(priv_key_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_2k.req_u.dsa_sign.priv_key, PRIV_KEY_2048, priv_key_len_2048);

        g_dsasignreq_2k.req_u.dsa_sign.m = kzalloc(m_len_2048, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_2k.req_u.dsa_sign.m, M_2048, m_len_2048);

        g_dsasignreq_2k.req_u.dsa_sign.c = kzalloc(d_len_2048, GFP_KERNEL | GFP_DMA);
	g_dsasignreq_2k.req_u.dsa_sign.d = kzalloc(d_len_2048, GFP_KERNEL | GFP_DMA);

	g_dsasignreq_2k.req_u.dsa_sign.q_len = (q_len_2048);
	g_dsasignreq_2k.req_u.dsa_sign.r_len = (r_len_2048);
	g_dsasignreq_2k.req_u.dsa_sign.g_len = (g_len_2048);
	g_dsasignreq_2k.req_u.dsa_sign.priv_key_len = (priv_key_len_2048);
	g_dsasignreq_2k.req_u.dsa_sign.m_len = (m_len_2048);
	g_dsasignreq_2k.req_u.dsa_sign.d_len = d_len_2048;
}

void init_dsa_verify_test_4k(void)
{
	g_dsaverifyreq_4k.type = DSA_VERIFY;

        g_dsaverifyreq_4k.req_u.dsa_verify.q = kzalloc(q_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_4k.req_u.dsa_verify.q, Q_4096, q_len_4096);

        g_dsaverifyreq_4k.req_u.dsa_verify.r = kzalloc(r_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_4k.req_u.dsa_verify.r, R_4096, r_len_4096);

        g_dsaverifyreq_4k.req_u.dsa_verify.g = kzalloc(g_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_4k.req_u.dsa_verify.g, G_4096, g_len_4096);

        g_dsaverifyreq_4k.req_u.dsa_verify.pub_key = kzalloc(pub_key_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_4k.req_u.dsa_verify.pub_key, PUB_KEY_4096, pub_key_len_4096);

        g_dsaverifyreq_4k.req_u.dsa_verify.m = kzalloc(m_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_4k.req_u.dsa_verify.m, M_4096, m_len_4096);

        g_dsaverifyreq_4k.req_u.dsa_verify.c = kzalloc(q_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_4k.req_u.dsa_verify.c, C_4096, q_len_4096);

        g_dsaverifyreq_4k.req_u.dsa_verify.d = kzalloc(d_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsaverifyreq_4k.req_u.dsa_verify.d, D_4096, d_4096);

	g_dsaverifyreq_4k.req_u.dsa_verify.q_len = (q_len_4096);
	g_dsaverifyreq_4k.req_u.dsa_verify.r_len = (r_len_4096);
	g_dsaverifyreq_4k.req_u.dsa_verify.g_len = (g_len_4096);
	g_dsaverifyreq_4k.req_u.dsa_verify.pub_key_len = (pub_key_len_4096);
	g_dsaverifyreq_4k.req_u.dsa_verify.m_len = (m_len_4096);
	g_dsaverifyreq_4k.req_u.dsa_verify.d_len = d_4096;
}

void init_dsa_sign_test_4k(void)
{
	g_dsasignreq_4k.type = DSA_SIGN;

        g_dsasignreq_4k.req_u.dsa_sign.q = kzalloc(q_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_4k.req_u.dsa_sign.q, Q_4096, q_len_4096);

        g_dsasignreq_4k.req_u.dsa_sign.r = kzalloc(r_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_4k.req_u.dsa_sign.r, R_4096, r_len_4096);

        g_dsasignreq_4k.req_u.dsa_sign.g = kzalloc(g_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_4k.req_u.dsa_sign.g, G_4096, g_len_4096);

        g_dsasignreq_4k.req_u.dsa_sign.priv_key = kzalloc(priv_key_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_4k.req_u.dsa_sign.priv_key, PRIV_KEY_4096, priv_key_len_4096);

        g_dsasignreq_4k.req_u.dsa_sign.m = kzalloc(m_len_4096, GFP_KERNEL | GFP_DMA);
        memcpy(g_dsasignreq_4k.req_u.dsa_sign.m, M_4096, m_len_4096);

        g_dsasignreq_4k.req_u.dsa_sign.c = kzalloc(d_len_4096, GFP_KERNEL | GFP_DMA);
	g_dsasignreq_4k.req_u.dsa_sign.d = kzalloc(d_len_4096, GFP_KERNEL | GFP_DMA);

	g_dsasignreq_4k.req_u.dsa_sign.q_len = (q_len_4096);
	g_dsasignreq_4k.req_u.dsa_sign.r_len = (r_len_4096);
	g_dsasignreq_4k.req_u.dsa_sign.g_len = (g_len_4096);
	g_dsasignreq_4k.req_u.dsa_sign.priv_key_len = (priv_key_len_4096);
	g_dsasignreq_4k.req_u.dsa_sign.m_len = (m_len_4096);
	g_dsasignreq_4k.req_u.dsa_sign.d_len = d_len_4096;
}

void cleanup_dsa_test(void)
{
        if (g_dsasignreq_1k.req_u.dsa_sign.q) {
            kfree(g_dsasignreq_1k.req_u.dsa_sign.q);
        }

        if (g_dsasignreq_1k.req_u.dsa_sign.r) {
            kfree(g_dsasignreq_1k.req_u.dsa_sign.r);
        }

        if (g_dsasignreq_1k.req_u.dsa_sign.g) {
            kfree(g_dsasignreq_1k.req_u.dsa_sign.g);
        }

        if (g_dsasignreq_1k.req_u.dsa_sign.priv_key) {
            kfree(g_dsasignreq_1k.req_u.dsa_sign.priv_key);
        }

        if (g_dsasignreq_1k.req_u.dsa_sign.m) {
            kfree(g_dsasignreq_1k.req_u.dsa_sign.m);
        }


        if (g_dsasignreq_2k.req_u.dsa_sign.q) {
            kfree(g_dsasignreq_2k.req_u.dsa_sign.q);
        }

        if (g_dsasignreq_2k.req_u.dsa_sign.r) {
            kfree(g_dsasignreq_2k.req_u.dsa_sign.r);
        }

        if (g_dsasignreq_2k.req_u.dsa_sign.g) {
            kfree(g_dsasignreq_2k.req_u.dsa_sign.g);
        }

        if (g_dsasignreq_2k.req_u.dsa_sign.priv_key) {
            kfree(g_dsasignreq_2k.req_u.dsa_sign.priv_key);
        }

        if (g_dsasignreq_2k.req_u.dsa_sign.m) {
            kfree(g_dsasignreq_2k.req_u.dsa_sign.m);
        }


        if (g_dsasignreq_4k.req_u.dsa_sign.q) {
            kfree(g_dsasignreq_4k.req_u.dsa_sign.q);
        }

        if (g_dsasignreq_4k.req_u.dsa_sign.r) {
            kfree(g_dsasignreq_4k.req_u.dsa_sign.r);
        }

        if (g_dsasignreq_4k.req_u.dsa_sign.g) {
            kfree(g_dsasignreq_4k.req_u.dsa_sign.g);
        }

        if (g_dsasignreq_4k.req_u.dsa_sign.priv_key) {
            kfree(g_dsasignreq_4k.req_u.dsa_sign.priv_key);
        }

        if (g_dsasignreq_4k.req_u.dsa_sign.m) {
            kfree(g_dsasignreq_4k.req_u.dsa_sign.m);
        }



        if (g_dsaverifyreq_1k.req_u.dsa_verify.q) {
            kfree(g_dsaverifyreq_1k.req_u.dsa_verify.q);
        }

        if (g_dsaverifyreq_1k.req_u.dsa_verify.r) {
            kfree(g_dsaverifyreq_1k.req_u.dsa_verify.r);
        }

        if (g_dsaverifyreq_1k.req_u.dsa_verify.g) {
            kfree(g_dsaverifyreq_1k.req_u.dsa_verify.g);
        }

        if (g_dsaverifyreq_1k.req_u.dsa_verify.pub_key) {
            kfree(g_dsaverifyreq_1k.req_u.dsa_verify.pub_key);
        }

        if (g_dsaverifyreq_1k.req_u.dsa_verify.m) {
            kfree(g_dsaverifyreq_1k.req_u.dsa_verify.m);
        }

        if (g_dsaverifyreq_1k.req_u.dsa_verify.c) {
            kfree(g_dsaverifyreq_1k.req_u.dsa_verify.c);
        }

        if (g_dsaverifyreq_1k.req_u.dsa_verify.d) {
            kfree(g_dsaverifyreq_1k.req_u.dsa_verify.d);
        }


        if (g_dsaverifyreq_2k.req_u.dsa_verify.q) {
            kfree(g_dsaverifyreq_2k.req_u.dsa_verify.q);
        }

        if (g_dsaverifyreq_2k.req_u.dsa_verify.r) {
            kfree(g_dsaverifyreq_2k.req_u.dsa_verify.r);
        }

        if (g_dsaverifyreq_2k.req_u.dsa_verify.g) {
            kfree(g_dsaverifyreq_2k.req_u.dsa_verify.g);
        }

        if (g_dsaverifyreq_2k.req_u.dsa_verify.pub_key) {
            kfree(g_dsaverifyreq_2k.req_u.dsa_verify.pub_key);
        }

        if (g_dsaverifyreq_2k.req_u.dsa_verify.m) {
            kfree(g_dsaverifyreq_2k.req_u.dsa_verify.m);
        }

        if (g_dsaverifyreq_2k.req_u.dsa_verify.c) {
            kfree(g_dsaverifyreq_2k.req_u.dsa_verify.c);
        }

        if (g_dsaverifyreq_2k.req_u.dsa_verify.d) {
            kfree(g_dsaverifyreq_2k.req_u.dsa_verify.d);
        }


        if (g_dsaverifyreq_4k.req_u.dsa_verify.q) {
            kfree(g_dsaverifyreq_4k.req_u.dsa_verify.q);
        }

        if (g_dsaverifyreq_4k.req_u.dsa_verify.r) {
            kfree(g_dsaverifyreq_4k.req_u.dsa_verify.r);
        }

        if (g_dsaverifyreq_4k.req_u.dsa_verify.g) {
            kfree(g_dsaverifyreq_4k.req_u.dsa_verify.g);
        }

        if (g_dsaverifyreq_4k.req_u.dsa_verify.pub_key) {
            kfree(g_dsaverifyreq_4k.req_u.dsa_verify.pub_key);
        }

        if (g_dsaverifyreq_4k.req_u.dsa_verify.m) {
            kfree(g_dsaverifyreq_4k.req_u.dsa_verify.m);
        }

        if (g_dsaverifyreq_4k.req_u.dsa_verify.c) {
            kfree(g_dsaverifyreq_4k.req_u.dsa_verify.c);
        }

        if (g_dsaverifyreq_4k.req_u.dsa_verify.d) {
            kfree(g_dsaverifyreq_4k.req_u.dsa_verify.d);
        }

	if(g_dsasignreq_1k.req_u.dsa_sign.c) {
		kfree(g_dsasignreq_1k.req_u.dsa_sign.c);
	}
	if(g_dsasignreq_1k.req_u.dsa_sign.d) {
		kfree(g_dsasignreq_1k.req_u.dsa_sign.d);
	}
	if(g_dsasignreq_2k.req_u.dsa_sign.c) {
		kfree(g_dsasignreq_2k.req_u.dsa_sign.c);
	}
	if(g_dsasignreq_2k.req_u.dsa_sign.d) {
		kfree(g_dsasignreq_2k.req_u.dsa_sign.d);
	}
	if(g_dsasignreq_4k.req_u.dsa_sign.c) {
		kfree(g_dsasignreq_4k.req_u.dsa_sign.c);
	}
	if(g_dsasignreq_4k.req_u.dsa_sign.d) {
		kfree(g_dsasignreq_4k.req_u.dsa_sign.d);
	}

}

int dsa_verify_test_1k(void)
{
	return test_dsa_op(&g_dsaverifyreq_1k, dsa_done);
}

int dsa_sign_test_1k(void)
{
	return test_dsa_op(&g_dsasignreq_1k, dsa_done);
}

int dsa_verify_test_2k(void)
{
	return test_dsa_op(&g_dsaverifyreq_2k, dsa_done);
}

int dsa_sign_test_2k(void)
{
	return test_dsa_op(&g_dsasignreq_2k, dsa_done);
}

int dsa_verify_test_4k(void)
{
	return test_dsa_op(&g_dsaverifyreq_4k, dsa_done);
}

int dsa_sign_test_4k(void)
{
	return test_dsa_op(&g_dsasignreq_4k, dsa_done);
}

int dsa_keygen_verify_test(struct pkc_request *genreq,
			   struct pkc_request *signreq, struct pkc_request *req)
{
	int ret = 0;

	print_debug("genreq: %p, signreq: %p, verify req: %p\n",
			genreq, signreq, req);

	req->type = DSA_VERIFY;

        req->req_u.dsa_verify.q = kzalloc(q_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_verify.q)) {
            goto error;
        }
        memcpy(req->req_u.dsa_verify.q, Q_1024, q_len);

        req->req_u.dsa_verify.r = kzalloc(r_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_verify.r)) {
            goto error;
        }
        memcpy(req->req_u.dsa_verify.r, R_1024, r_len);

        req->req_u.dsa_verify.g = kzalloc(g_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_verify.g)) {
            goto error;
        }
        memcpy(req->req_u.dsa_verify.g, G_1024, g_len);

        req->req_u.dsa_verify.pub_key = kzalloc(pub_key_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_verify.pub_key)) {
            goto error;
        }
        memcpy(req->req_u.dsa_verify.pub_key, genreq->req_u.dsa_keygen.pubkey, pub_key_len);

        req->req_u.dsa_verify.m = kzalloc(m_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_verify.m)) {
            goto error;
        }
        memcpy(req->req_u.dsa_verify.m, M_1024, m_len);

        req->req_u.dsa_verify.c = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_verify.c)) {
            goto error;
        }
        memcpy(req->req_u.dsa_verify.c, signreq->req_u.dsa_sign.c, d_len);

        req->req_u.dsa_verify.d = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_verify.d)) {
            goto error;
        }
        memcpy(req->req_u.dsa_verify.d, signreq->req_u.dsa_sign.d, d_len);

	req->req_u.dsa_verify.q_len = (q_len);
	req->req_u.dsa_verify.r_len = (r_len);
	req->req_u.dsa_verify.g_len = (g_len);
	req->req_u.dsa_verify.pub_key_len = (pub_key_len);
	req->req_u.dsa_verify.m_len = (m_len);
	req->req_u.dsa_verify.d_len = d_len;

	ret = test_dsa_op(req, dsa_keygen_done);
	return ret;
error:
	return -1;
}

int dsa_keygen_sign_test(struct pkc_request *ireq, struct pkc_request *req)
{
	int ret = 0;
	print_debug("genreq: %p req: %p\n", ireq, req);

	req->type = DSA_SIGN;

        req->req_u.dsa_sign.q = kzalloc(q_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_sign.q)) {
            goto error;
        }
        memcpy(req->req_u.dsa_sign.q, Q_1024, q_len);

        req->req_u.dsa_sign.r = kzalloc(r_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_sign.r)) {
            goto error;
        }
        memcpy(req->req_u.dsa_sign.r, R_1024, r_len);

        req->req_u.dsa_sign.g = kzalloc(g_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_sign.g)) {
            goto error;
        }
        memcpy(req->req_u.dsa_sign.g, G_1024, g_len);

        req->req_u.dsa_sign.priv_key = kzalloc(priv_key_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_sign.priv_key)) {
            goto error;
        }
        memcpy(req->req_u.dsa_sign.priv_key, ireq->req_u.dsa_keygen.prvkey, priv_key_len);

        req->req_u.dsa_sign.m = kzalloc(m_len, GFP_KERNEL | GFP_DMA);
        if (!(req->req_u.dsa_sign.m)) {
            goto error;
        }
        memcpy(req->req_u.dsa_sign.m, M_1024, m_len);

	req->req_u.dsa_sign.c = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
	if (!req->req_u.dsa_sign.c)
		goto error;

	req->req_u.dsa_sign.d = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
	if (!req->req_u.dsa_sign.d)
		goto error;

	req->req_u.dsa_sign.q_len = (q_len);
	req->req_u.dsa_sign.r_len = (r_len);
	req->req_u.dsa_sign.g_len = (g_len);
	req->req_u.dsa_sign.priv_key_len = (priv_key_len);
	req->req_u.dsa_sign.m_len = (m_len);
	req->req_u.dsa_sign.d_len = d_len;

	ret = test_dsa_op(req, dsa_keygen_done);

	return ret;
error:
	return -1;
}

int dsa_keygen_test(void)
{
	int ret = -ENOMEM;
	struct pkc_request *genreq, *signreq, *verifyreq;

	genreq = kzalloc(sizeof(struct pkc_request), GFP_KERNEL);
	if (!genreq)
		return ret;

	signreq = kzalloc(sizeof(struct pkc_request), GFP_KERNEL);
	if (!signreq)
		goto signreq_fail;

	verifyreq = kzalloc(sizeof(struct pkc_request), GFP_KERNEL);
	if (!verifyreq)
		goto verifyreq_fail;

	init_completion(&serialize_keygen);

	print_debug("pkc_request size: %zu req ptr: %p \n",
			sizeof(struct pkc_request), genreq);

	genreq->type = DSA_KEYGEN;

        genreq->req_u.dsa_keygen.q = kzalloc(q_len, GFP_KERNEL | GFP_DMA);
        if (!(genreq->req_u.dsa_keygen.q)) {
            goto error;
        }
        memcpy(genreq->req_u.dsa_keygen.q, Q_1024, q_len);

        genreq->req_u.dsa_keygen.r = kzalloc(r_len, GFP_KERNEL | GFP_DMA);
        if (!(genreq->req_u.dsa_keygen.r)) {
            goto error;
        }
        memcpy(genreq->req_u.dsa_keygen.r, R_1024, r_len);

        genreq->req_u.dsa_keygen.g = kzalloc(g_len, GFP_KERNEL | GFP_DMA);
        if (!(genreq->req_u.dsa_keygen.g)) {
            goto error;
        }
        memcpy(genreq->req_u.dsa_keygen.g, G_1024, g_len);

	genreq->req_u.dsa_keygen.pubkey = kzalloc(pub_key_len, GFP_KERNEL | GFP_DMA);
	if (!genreq->req_u.dsa_keygen.pubkey)
		goto error;

	genreq->req_u.dsa_keygen.prvkey = kzalloc(priv_key_len, GFP_KERNEL | GFP_DMA);
	if (!genreq->req_u.dsa_keygen.prvkey)
		goto error;

	genreq->req_u.dsa_keygen.q_len = (q_len);
	genreq->req_u.dsa_keygen.r_len = (r_len);
	genreq->req_u.dsa_keygen.g_len = (g_len);
	genreq->req_u.dsa_keygen.pubkey_len = (pub_key_len);
	genreq->req_u.dsa_keygen.prvkey_len = (priv_key_len);

	ret = test_dsa_op(genreq, dsa_keygen_done);
	if (ret != 0) {
		goto error;
	}

	wait_for_completion(&serialize_keygen);
	ret = dsa_keygen_sign_test(genreq, signreq);
	if (ret != 0) {
		goto error;
	}

	wait_for_completion(&serialize_keygen);
	ret = dsa_keygen_verify_test(genreq, signreq, verifyreq);
	if (ret != 0) {
		goto error;
	}

	wait_for_completion(&serialize_keygen);

	common_dec_count();

/*FIXME: proper clean-up */
error:
	if (genreq) {
                if (genreq->req_u.dsa_keygen.q) {
                    kfree(genreq->req_u.dsa_keygen.q);
                }

                if (genreq->req_u.dsa_keygen.r) {
                    kfree(genreq->req_u.dsa_keygen.r);
                }

                if (genreq->req_u.dsa_keygen.g) {
                    kfree(genreq->req_u.dsa_keygen.g);
                }

                if (genreq->req_u.dsa_keygen.pubkey) {
			kfree(genreq->req_u.dsa_keygen.pubkey);
		}
		if (genreq->req_u.dsa_keygen.prvkey) {
			kfree(genreq->req_u.dsa_keygen.prvkey);
		}
		kfree(genreq);
	}

	if (signreq) {
                if (signreq->req_u.dsa_sign.q) {
                    kfree(signreq->req_u.dsa_sign.q);
                }

                if (signreq->req_u.dsa_sign.r) {
                    kfree(signreq->req_u.dsa_sign.r);
                }

                if (signreq->req_u.dsa_sign.g) {
                    kfree(signreq->req_u.dsa_sign.g);
                }

                if (signreq->req_u.dsa_sign.m) {
                    kfree(signreq->req_u.dsa_sign.m);
                }

                if (signreq->req_u.dsa_sign.c) {
			kfree(signreq->req_u.dsa_sign.c);
		}
		if (signreq->req_u.dsa_sign.d) {
			kfree(signreq->req_u.dsa_sign.d);
		}
		if (signreq->req_u.dsa_sign.priv_key) {
			kfree(signreq->req_u.dsa_sign.priv_key);
		}

		kfree(signreq);
	}
	if (verifyreq) {
                if (verifyreq->req_u.dsa_verify.q) {
                    kfree(verifyreq->req_u.dsa_verify.q);
                }

                if (verifyreq->req_u.dsa_verify.r) {
                    kfree(verifyreq->req_u.dsa_verify.r);
                }

                if (verifyreq->req_u.dsa_verify.g) {
                    kfree(verifyreq->req_u.dsa_verify.g);
                }

                if (verifyreq->req_u.dsa_verify.m) {
                    kfree(verifyreq->req_u.dsa_verify.m);
                }

                if (verifyreq->req_u.dsa_verify.c) {
			kfree(verifyreq->req_u.dsa_verify.c);
		}
		if (verifyreq->req_u.dsa_verify.d) {
			kfree(verifyreq->req_u.dsa_verify.d);
		}
		if (verifyreq->req_u.dsa_verify.pub_key) {
			kfree(verifyreq->req_u.dsa_verify.pub_key);
		}

		kfree(verifyreq);
	}

	return ret;

verifyreq_fail:
	kfree(signreq);
signreq_fail:
	kfree(genreq);
	return ret;
}

int dsa_sign_verify_verify_test(struct pkc_request *ireq)
{
	int ret = 0;
	struct pkc_request *req =
	    kzalloc(sizeof(struct pkc_request), GFP_KERNEL);

	req->type = DSA_VERIFY;

        req->req_u.dsa_verify.q = kzalloc(q_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_verify.q, Q_1024, q_len);

        req->req_u.dsa_verify.r = kzalloc(r_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_verify.r, R_1024, r_len);

        req->req_u.dsa_verify.g = kzalloc(g_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_verify.g, G_1024, g_len);

        req->req_u.dsa_verify.pub_key = kzalloc(pub_key_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_verify.pub_key, PUB_KEY_1024, pub_key_len);

        req->req_u.dsa_verify.m = kzalloc(m_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_verify.m, M_1024, m_len);

        req->req_u.dsa_verify.c = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
	memcpy(req->req_u.dsa_verify.c, ireq->req_u.dsa_sign.c, d_len);

	req->req_u.dsa_verify.d = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
	memcpy(req->req_u.dsa_verify.d, ireq->req_u.dsa_sign.d, d_len);

	req->req_u.dsa_verify.q_len = (q_len);
	req->req_u.dsa_verify.r_len = (r_len);
	req->req_u.dsa_verify.g_len = (g_len);
	req->req_u.dsa_verify.pub_key_len = (pub_key_len);
	req->req_u.dsa_verify.m_len = (m_len);
	req->req_u.dsa_verify.d_len = d_len;

	ret = test_dsa_op(req, dsa_sign_verify_verify_done);

	if (ret != 0) {
                kfree(req->req_u.dsa_verify.q);
                kfree(req->req_u.dsa_verify.r);
                kfree(req->req_u.dsa_verify.g);
                kfree(req->req_u.dsa_verify.pub_key);
                kfree(req->req_u.dsa_verify.m);
                kfree(req->req_u.dsa_verify.c);
                kfree(req->req_u.dsa_verify.d);
		kfree(req);
                atomic_dec(&total_enq_cnt);
        }

	return ret;
}

int dsa_sign_verify_sign_test(struct pkc_request *req)
{
	int ret = 0;

	req->type = DSA_SIGN;

        req->req_u.dsa_sign.q = kzalloc(q_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_sign.q, Q_1024, q_len);

        req->req_u.dsa_sign.r = kzalloc(r_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_sign.r, R_1024, r_len);

        req->req_u.dsa_sign.g = kzalloc(g_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_sign.g, G_1024, g_len);

        req->req_u.dsa_sign.priv_key = kzalloc(priv_key_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_sign.priv_key, PRIV_KEY_1024, priv_key_len);

        req->req_u.dsa_sign.m = kzalloc(m_len, GFP_KERNEL | GFP_DMA);
        memcpy(req->req_u.dsa_sign.m, M_1024, m_len);

	req->req_u.dsa_sign.c = kzalloc(d_len, GFP_KERNEL | GFP_DMA);
	req->req_u.dsa_sign.d = kzalloc(d_len, GFP_KERNEL | GFP_DMA);

	req->req_u.dsa_sign.q_len = (q_len);
	req->req_u.dsa_sign.r_len = (r_len);
	req->req_u.dsa_sign.g_len = (g_len);
	req->req_u.dsa_sign.priv_key_len = (priv_key_len);
	req->req_u.dsa_sign.m_len = (m_len);
	req->req_u.dsa_sign.d_len = d_len;

	ret = test_dsa_op(req, dsa_sign_verify_sign_done);

	if (ret != 0) {
                kfree(req->req_u.dsa_sign.q);
                kfree(req->req_u.dsa_sign.r);
                kfree(req->req_u.dsa_sign.g);
                kfree(req->req_u.dsa_sign.priv_key);
                kfree(req->req_u.dsa_sign.m);
		kfree(req->req_u.dsa_sign.c);
		kfree(req->req_u.dsa_sign.d);
		kfree(req);
	}

	return ret;
}

int dsa_sign_verify_test(void)
{
	struct pkc_request *req = kzalloc(sizeof(struct pkc_request), GFP_KERNEL);

	return dsa_sign_verify_sign_test(req);
}
