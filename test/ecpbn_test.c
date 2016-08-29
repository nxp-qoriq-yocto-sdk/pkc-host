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

#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "desc.h"

#include"test.h"
#include"ecpbn_test.h"

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);

atomic_t ecpbn_enq_count;
atomic_t ecpbn_deq_count;

struct pkc_request g_ecpbnverifyreq_283; 
struct pkc_request g_ecpbnsignreq_283;
struct pkc_request g_ecpbnverifyreq_409; 
struct pkc_request g_ecpbnsignreq_409;
struct pkc_request g_ecpbnverifyreq_571; 
struct pkc_request g_ecpbnsignreq_571;

/*
static struct completion keygen_control_completion_var;
*/

void ecpbn_done(struct pkc_request *req, int32_t sec_result)
{
#ifndef SIMPLE_TEST_ENABLE
#ifndef PERF_TEST
	uint32_t i = 0;
#endif
	print_debug("ECDSA REQ TYPE [%d]\n", req->type);
	print_debug("RESULT : %d\n ", sec_result);
	switch (req->type) {
	case ECDSA_SIGN:
#ifndef PERF_TEST
		print_debug(" C/D\n");
		print_debug("Length : %d\n", req->req_u.dsa_sign.d_len);

		print_debug(" C\n");
		for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
			print_debug("0x%0x,\t", req->req_u.dsa_sign.c[i]);

		print_debug(" D\n");
		for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
			print_debug("0x%0x,\t", req->req_u.dsa_sign.d[i]);

#endif
		kfree(req->req_u.dsa_sign.c);
		kfree(req->req_u.dsa_sign.d);
		kfree(req);
		break;
	case ECDSA_VERIFY:
		kfree(req);
		break;
	default:
		break;
	}
	dec_count();
    uint32_t i = 0;
    print_debug("ECDSA REQ TYPE [%d]\n", req->type);
    print_debug("RESULT : %d\n ", sec_result);
    switch (req->type) {
        case ECDSA_SIGN:
            print_debug("C/D\n");
            print_debug("Length : %d\n", req->req_u.dsa_sign.d_len);
            print_debug("C\n");
            for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
                print_debug("0x%x, ", req->req_u.dsa_sign.c[i]);

            print_debug("D\n");
            for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
                print_debug("0x%x, ", req->req_u.dsa_sign.d[i]);
            break;
	    case ECDSA_VERIFY:
            print_debug("Ecp Verify Done\n");
            break;
        default:
            print_debug("Wrong test\n");
            break;
    }
#endif
    common_dec_count();
}

void init_ecpbn_verify_test_283(void)
{
	g_ecpbnverifyreq_283.type = ECDSA_VERIFY;
	g_ecpbnverifyreq_283.curve_type = ECC_BINARY;

	g_ecpbnverifyreq_283.req_u.dsa_verify.q = kzalloc(sizeof(Q_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_283.req_u.dsa_verify.r = kzalloc(sizeof(R_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_283.req_u.dsa_verify.ab = kzalloc(sizeof(AB_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_283.req_u.dsa_verify.g = kzalloc(sizeof(G_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_283.req_u.dsa_verify.pub_key = kzalloc(sizeof(PUB_KEY_EC_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_283.req_u.dsa_verify.m = kzalloc(sizeof(M_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_283.req_u.dsa_verify.c = kzalloc(sizeof(C), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_283.req_u.dsa_verify.d = kzalloc(sizeof(D), GFP_KERNEL | GFP_DMA);

	g_ecpbnverifyreq_283.req_u.dsa_verify.q_len = sizeof(Q_283);
	g_ecpbnverifyreq_283.req_u.dsa_verify.r_len = sizeof(R_283);
	g_ecpbnverifyreq_283.req_u.dsa_verify.ab_len = sizeof(AB_283);
	g_ecpbnverifyreq_283.req_u.dsa_verify.g_len = sizeof(G_283);
	g_ecpbnverifyreq_283.req_u.dsa_verify.pub_key_len = sizeof(PUB_KEY_EC_283);
	g_ecpbnverifyreq_283.req_u.dsa_verify.m_len = sizeof(M_283);
	g_ecpbnverifyreq_283.req_u.dsa_verify.d_len = sizeof(D);

	memcpy(g_ecpbnverifyreq_283.req_u.dsa_verify.q, Q_283, sizeof(Q_283));
	memcpy(g_ecpbnverifyreq_283.req_u.dsa_verify.r, R_283, sizeof(R_283));
	memcpy(g_ecpbnverifyreq_283.req_u.dsa_verify.ab, AB_283, sizeof(AB_283));
	memcpy(g_ecpbnverifyreq_283.req_u.dsa_verify.g, G_283, sizeof(G_283));
	memcpy(g_ecpbnverifyreq_283.req_u.dsa_verify.pub_key, PUB_KEY_EC_283, sizeof(PUB_KEY_EC_283));
	memcpy(g_ecpbnverifyreq_283.req_u.dsa_verify.m, M_283, sizeof(M_283));
	memcpy(g_ecpbnverifyreq_283.req_u.dsa_verify.c, C, sizeof(C));
	memcpy(g_ecpbnverifyreq_283.req_u.dsa_verify.d, D, sizeof(D));
}

void init_ecpbn_sign_test_283(void)
{
	g_ecpbnsignreq_283.type = ECDSA_SIGN;
	g_ecpbnsignreq_283.curve_type = ECC_BINARY;

	g_ecpbnsignreq_283.req_u.dsa_sign.q = kzalloc(sizeof(Q_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_283.req_u.dsa_sign.r = kzalloc(sizeof(R_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_283.req_u.dsa_sign.ab = kzalloc(sizeof(AB_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_283.req_u.dsa_sign.g = kzalloc(sizeof(G_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_283.req_u.dsa_sign.priv_key = kzalloc(sizeof(PRIV_KEY_EC_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_283.req_u.dsa_sign.m = kzalloc(sizeof(M_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_283.req_u.dsa_sign.c = kzalloc(sizeof(R_283), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_283.req_u.dsa_sign.d = kzalloc(sizeof(R_283), GFP_KERNEL | GFP_DMA);

	g_ecpbnsignreq_283.req_u.dsa_sign.q_len = sizeof(Q_283);
	g_ecpbnsignreq_283.req_u.dsa_sign.r_len = sizeof(R_283);
	g_ecpbnsignreq_283.req_u.dsa_sign.ab_len = sizeof(AB_283);
	g_ecpbnsignreq_283.req_u.dsa_sign.g_len = sizeof(G_283);
	g_ecpbnsignreq_283.req_u.dsa_sign.priv_key_len = sizeof(PRIV_KEY_EC_283);
	g_ecpbnsignreq_283.req_u.dsa_sign.m_len = sizeof(M_283);
	g_ecpbnsignreq_283.req_u.dsa_sign.d_len = sizeof(R_283);

	memcpy(g_ecpbnsignreq_283.req_u.dsa_sign.q, Q_283, sizeof(Q_283));
	memcpy(g_ecpbnsignreq_283.req_u.dsa_sign.r, R_283, sizeof(R_283));
	memcpy(g_ecpbnsignreq_283.req_u.dsa_sign.ab, AB_283, sizeof(AB_283));
	memcpy(g_ecpbnsignreq_283.req_u.dsa_sign.g, G_283, sizeof(G_283));
	memcpy(g_ecpbnsignreq_283.req_u.dsa_sign.priv_key, PRIV_KEY_EC_283, sizeof(PRIV_KEY_EC_283));
	memcpy(g_ecpbnsignreq_283.req_u.dsa_sign.m, M_283, sizeof(M_283));
}

int ecpbn_verify_test_283(void)
{
	return test_dsa_op(&g_ecpbnverifyreq_283, ecpbn_done);
}

int ecpbn_sign_test_283(void)
{
	return test_dsa_op(&g_ecpbnsignreq_283, ecpbn_done);
}


void init_ecpbn_verify_test_409(void)
{
	g_ecpbnverifyreq_409.type = ECDSA_VERIFY;
	g_ecpbnverifyreq_409.curve_type = ECC_BINARY;

	g_ecpbnverifyreq_409.req_u.dsa_verify.q = kzalloc(sizeof(Q_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_409.req_u.dsa_verify.r = kzalloc(sizeof(R_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_409.req_u.dsa_verify.ab = kzalloc(sizeof(AB_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_409.req_u.dsa_verify.g = kzalloc(sizeof(G_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_409.req_u.dsa_verify.pub_key = kzalloc(sizeof(PUB_KEY_EC_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_409.req_u.dsa_verify.m = kzalloc(sizeof(M_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_409.req_u.dsa_verify.c = kzalloc(sizeof(C_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_409.req_u.dsa_verify.d = kzalloc(sizeof(D_409), GFP_KERNEL | GFP_DMA);

	g_ecpbnverifyreq_409.req_u.dsa_verify.q_len = sizeof(Q_409);
	g_ecpbnverifyreq_409.req_u.dsa_verify.r_len = sizeof(R_409);
	g_ecpbnverifyreq_409.req_u.dsa_verify.ab_len = sizeof(AB_409);
	g_ecpbnverifyreq_409.req_u.dsa_verify.g_len = sizeof(G_409);
	g_ecpbnverifyreq_409.req_u.dsa_verify.pub_key_len = sizeof(PUB_KEY_EC_409);
	g_ecpbnverifyreq_409.req_u.dsa_verify.m_len = sizeof(M_409);
	g_ecpbnverifyreq_409.req_u.dsa_verify.d_len = sizeof(D_409);

	memcpy(g_ecpbnverifyreq_409.req_u.dsa_verify.q, Q_409, sizeof(Q_409));
	memcpy(g_ecpbnverifyreq_409.req_u.dsa_verify.r, R_409, sizeof(R_409));
	memcpy(g_ecpbnverifyreq_409.req_u.dsa_verify.ab, AB_409, sizeof(AB_409));
	memcpy(g_ecpbnverifyreq_409.req_u.dsa_verify.g, G_409, sizeof(G_409));
	memcpy(g_ecpbnverifyreq_409.req_u.dsa_verify.pub_key, PUB_KEY_EC_409, sizeof(PUB_KEY_EC_409));
	memcpy(g_ecpbnverifyreq_409.req_u.dsa_verify.m, M_409, sizeof(M_409));
	memcpy(g_ecpbnverifyreq_409.req_u.dsa_verify.c, C_409, sizeof(C_409));
	memcpy(g_ecpbnverifyreq_409.req_u.dsa_verify.d, D_409, sizeof(D_409));
}

void init_ecpbn_sign_test_409(void)
{
	g_ecpbnsignreq_409.type = ECDSA_SIGN;
	g_ecpbnsignreq_409.curve_type = ECC_BINARY;

	g_ecpbnsignreq_409.req_u.dsa_sign.q = kzalloc(sizeof(Q_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_409.req_u.dsa_sign.r = kzalloc(sizeof(R_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_409.req_u.dsa_sign.ab = kzalloc(sizeof(AB_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_409.req_u.dsa_sign.g = kzalloc(sizeof(G_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_409.req_u.dsa_sign.priv_key = kzalloc(sizeof(PRIV_KEY_EC_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_409.req_u.dsa_sign.m = kzalloc(sizeof(M_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_409.req_u.dsa_sign.c = kzalloc(sizeof(R_409), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_409.req_u.dsa_sign.d = kzalloc(sizeof(R_409), GFP_KERNEL | GFP_DMA);

	g_ecpbnsignreq_409.req_u.dsa_sign.q_len = sizeof(Q_409);
	g_ecpbnsignreq_409.req_u.dsa_sign.r_len = sizeof(R_409);
	g_ecpbnsignreq_409.req_u.dsa_sign.ab_len = sizeof(AB_409);
	g_ecpbnsignreq_409.req_u.dsa_sign.g_len = sizeof(G_409);
	g_ecpbnsignreq_409.req_u.dsa_sign.priv_key_len = sizeof(PRIV_KEY_EC_409);
	g_ecpbnsignreq_409.req_u.dsa_sign.m_len = sizeof(M_409);
	g_ecpbnsignreq_409.req_u.dsa_sign.d_len = sizeof(R_409);

	memcpy(g_ecpbnsignreq_409.req_u.dsa_sign.q, Q_409, sizeof(Q_409));
	memcpy(g_ecpbnsignreq_409.req_u.dsa_sign.r, R_409, sizeof(R_409));
	memcpy(g_ecpbnsignreq_409.req_u.dsa_sign.ab, AB_409, sizeof(AB_409));
	memcpy(g_ecpbnsignreq_409.req_u.dsa_sign.g, G_409, sizeof(G_409));
	memcpy(g_ecpbnsignreq_409.req_u.dsa_sign.priv_key, PRIV_KEY_EC_409, sizeof(PRIV_KEY_EC_409));
	memcpy(g_ecpbnsignreq_409.req_u.dsa_sign.m, M_409, sizeof(M_409));
}

int ecpbn_verify_test_409(void)
{
	return test_dsa_op(&g_ecpbnverifyreq_409, ecpbn_done);
}

int ecpbn_sign_test_409(void)
{
	return test_dsa_op(&g_ecpbnsignreq_409, ecpbn_done);
}


void init_ecpbn_verify_test_571(void)
{
	g_ecpbnverifyreq_571.type = ECDSA_VERIFY;
	g_ecpbnverifyreq_571.curve_type = ECC_BINARY;

	g_ecpbnverifyreq_571.req_u.dsa_verify.q = kzalloc(sizeof(Q_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_571.req_u.dsa_verify.r = kzalloc(sizeof(R_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_571.req_u.dsa_verify.ab = kzalloc(sizeof(AB_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_571.req_u.dsa_verify.g = kzalloc(sizeof(G_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_571.req_u.dsa_verify.pub_key = kzalloc(sizeof(PUB_KEY_EC_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_571.req_u.dsa_verify.m = kzalloc(sizeof(M_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_571.req_u.dsa_verify.c = kzalloc(sizeof(C_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnverifyreq_571.req_u.dsa_verify.d = kzalloc(sizeof(D_571), GFP_KERNEL | GFP_DMA);

	g_ecpbnverifyreq_571.req_u.dsa_verify.q_len = sizeof(Q_571);
	g_ecpbnverifyreq_571.req_u.dsa_verify.r_len = sizeof(R_571);
	g_ecpbnverifyreq_571.req_u.dsa_verify.ab_len = sizeof(AB_571);
	g_ecpbnverifyreq_571.req_u.dsa_verify.g_len = sizeof(G_571);
	g_ecpbnverifyreq_571.req_u.dsa_verify.pub_key_len = sizeof(PUB_KEY_EC_571);
	g_ecpbnverifyreq_571.req_u.dsa_verify.m_len = sizeof(M_571);
	g_ecpbnverifyreq_571.req_u.dsa_verify.d_len = sizeof(D_571);

	memcpy(g_ecpbnverifyreq_571.req_u.dsa_verify.q, Q_571, sizeof(Q_571));
	memcpy(g_ecpbnverifyreq_571.req_u.dsa_verify.r, R_571, sizeof(R_571));
	memcpy(g_ecpbnverifyreq_571.req_u.dsa_verify.ab, AB_571, sizeof(AB_571));
	memcpy(g_ecpbnverifyreq_571.req_u.dsa_verify.g, G_571, sizeof(G_571));
	memcpy(g_ecpbnverifyreq_571.req_u.dsa_verify.pub_key, PUB_KEY_EC_571, sizeof(PUB_KEY_EC_571));
	memcpy(g_ecpbnverifyreq_571.req_u.dsa_verify.m, M_571, sizeof(M_571));
	memcpy(g_ecpbnverifyreq_571.req_u.dsa_verify.c, C_571, sizeof(C_571));
	memcpy(g_ecpbnverifyreq_571.req_u.dsa_verify.d, D_571, sizeof(D_571));
}

void init_ecpbn_sign_test_571(void)
{
	g_ecpbnsignreq_571.type = ECDSA_SIGN;
	g_ecpbnsignreq_571.curve_type = ECC_BINARY;

	g_ecpbnsignreq_571.req_u.dsa_sign.q = kzalloc(sizeof(Q_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_571.req_u.dsa_sign.r = kzalloc(sizeof(R_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_571.req_u.dsa_sign.ab = kzalloc(sizeof(AB_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_571.req_u.dsa_sign.g = kzalloc(sizeof(G_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_571.req_u.dsa_sign.priv_key = kzalloc(sizeof(PRIV_KEY_EC_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_571.req_u.dsa_sign.m = kzalloc(sizeof(M_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_571.req_u.dsa_sign.c = kzalloc(sizeof(R_571), GFP_KERNEL | GFP_DMA);
	g_ecpbnsignreq_571.req_u.dsa_sign.d = kzalloc(sizeof(R_571), GFP_KERNEL | GFP_DMA);

	g_ecpbnsignreq_571.req_u.dsa_sign.q_len = sizeof(Q_571);
	g_ecpbnsignreq_571.req_u.dsa_sign.r_len = sizeof(R_571);
	g_ecpbnsignreq_571.req_u.dsa_sign.ab_len = sizeof(AB_571);
	g_ecpbnsignreq_571.req_u.dsa_sign.g_len = sizeof(G_571);
	g_ecpbnsignreq_571.req_u.dsa_sign.priv_key_len = sizeof(PRIV_KEY_EC_571);
	g_ecpbnsignreq_571.req_u.dsa_sign.m_len = sizeof(M_571);
	g_ecpbnsignreq_571.req_u.dsa_sign.d_len = sizeof(R_571);

	memcpy(g_ecpbnsignreq_571.req_u.dsa_sign.q, Q_571, sizeof(Q_571));
	memcpy(g_ecpbnsignreq_571.req_u.dsa_sign.r, R_571, sizeof(R_571));
	memcpy(g_ecpbnsignreq_571.req_u.dsa_sign.ab, AB_571, sizeof(AB_571));
	memcpy(g_ecpbnsignreq_571.req_u.dsa_sign.g, G_571, sizeof(G_571));
	memcpy(g_ecpbnsignreq_571.req_u.dsa_sign.priv_key, PRIV_KEY_EC_571, sizeof(PRIV_KEY_EC_571));
	memcpy(g_ecpbnsignreq_571.req_u.dsa_sign.m, M_571, sizeof(M_571));
}

int ecpbn_verify_test_571(void)
{
	return test_dsa_op(&g_ecpbnverifyreq_571, ecpbn_done);
}

int ecpbn_sign_test_571(void)
{
	return test_dsa_op(&g_ecpbnsignreq_571, ecpbn_done);
}

void cleanup_ecpbn_test(void)
{
	if(g_ecpbnverifyreq_283.req_u.dsa_verify.q) {
		kfree(g_ecpbnverifyreq_283.req_u.dsa_verify.q);
	}
	if(g_ecpbnverifyreq_283.req_u.dsa_verify.r) {
		kfree(g_ecpbnverifyreq_283.req_u.dsa_verify.r);
	}
	if(g_ecpbnverifyreq_283.req_u.dsa_verify.ab) {
		kfree(g_ecpbnverifyreq_283.req_u.dsa_verify.ab);
	}
	if(g_ecpbnverifyreq_283.req_u.dsa_verify.g) {
		kfree(g_ecpbnverifyreq_283.req_u.dsa_verify.g);
	}
	if(g_ecpbnverifyreq_283.req_u.dsa_verify.pub_key) {
		kfree(g_ecpbnverifyreq_283.req_u.dsa_verify.pub_key);
	}
	if(g_ecpbnverifyreq_283.req_u.dsa_verify.m) {
		kfree(g_ecpbnverifyreq_283.req_u.dsa_verify.m);
	}
	if(g_ecpbnverifyreq_283.req_u.dsa_verify.c) {
		kfree(g_ecpbnverifyreq_283.req_u.dsa_verify.c);
	}
	if(g_ecpbnverifyreq_283.req_u.dsa_verify.d) {
		kfree(g_ecpbnverifyreq_283.req_u.dsa_verify.d);
	}


	if(g_ecpbnsignreq_283.req_u.dsa_sign.q) {
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.q);
	}
	if(g_ecpbnsignreq_283.req_u.dsa_sign.r) {
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.r);
	}
	if(g_ecpbnsignreq_283.req_u.dsa_sign.ab) {
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.ab);
	}
	if(g_ecpbnsignreq_283.req_u.dsa_sign.g) {
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.g);
	}
	if(g_ecpbnsignreq_283.req_u.dsa_sign.priv_key) {
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.priv_key);
	}
	if(g_ecpbnsignreq_283.req_u.dsa_sign.m) {
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.m);
	}
	if(g_ecpbnsignreq_283.req_u.dsa_sign.c) {
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.c);
	}
	if(g_ecpbnsignreq_283.req_u.dsa_sign.d) {
		kfree(g_ecpbnsignreq_283.req_u.dsa_sign.d);
	}


	if(g_ecpbnverifyreq_409.req_u.dsa_verify.q) {
		kfree(g_ecpbnverifyreq_409.req_u.dsa_verify.q);
	}
	if(g_ecpbnverifyreq_409.req_u.dsa_verify.r) {
		kfree(g_ecpbnverifyreq_409.req_u.dsa_verify.r);
	}
	if(g_ecpbnverifyreq_409.req_u.dsa_verify.ab) {
		kfree(g_ecpbnverifyreq_409.req_u.dsa_verify.ab);
	}
	if(g_ecpbnverifyreq_409.req_u.dsa_verify.g) {
		kfree(g_ecpbnverifyreq_409.req_u.dsa_verify.g);
	}
	if(g_ecpbnverifyreq_409.req_u.dsa_verify.pub_key) {
		kfree(g_ecpbnverifyreq_409.req_u.dsa_verify.pub_key);
	}
	if(g_ecpbnverifyreq_409.req_u.dsa_verify.m) {
		kfree(g_ecpbnverifyreq_409.req_u.dsa_verify.m);
	}
	if(g_ecpbnverifyreq_409.req_u.dsa_verify.c) {
		kfree(g_ecpbnverifyreq_409.req_u.dsa_verify.c);
	}
	if(g_ecpbnverifyreq_409.req_u.dsa_verify.d) {
		kfree(g_ecpbnverifyreq_409.req_u.dsa_verify.d);
	}


	if(g_ecpbnsignreq_409.req_u.dsa_sign.q) {
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.q);
	}
	if(g_ecpbnsignreq_409.req_u.dsa_sign.r) {
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.r);
	}
	if(g_ecpbnsignreq_409.req_u.dsa_sign.ab) {
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.ab);
	}
	if(g_ecpbnsignreq_409.req_u.dsa_sign.g) {
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.g);
	}
	if(g_ecpbnsignreq_409.req_u.dsa_sign.priv_key) {
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.priv_key);
	}
	if(g_ecpbnsignreq_409.req_u.dsa_sign.m) {
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.m);
	}
	if(g_ecpbnsignreq_409.req_u.dsa_sign.c) {
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.c);
	}
	if(g_ecpbnsignreq_409.req_u.dsa_sign.d) {
		kfree(g_ecpbnsignreq_409.req_u.dsa_sign.d);
	}


	if(g_ecpbnverifyreq_571.req_u.dsa_verify.q) {
		kfree(g_ecpbnverifyreq_571.req_u.dsa_verify.q);
	}
	if(g_ecpbnverifyreq_571.req_u.dsa_verify.r) {
		kfree(g_ecpbnverifyreq_571.req_u.dsa_verify.r);
	}
	if(g_ecpbnverifyreq_571.req_u.dsa_verify.ab) {
		kfree(g_ecpbnverifyreq_571.req_u.dsa_verify.ab);
	}
	if(g_ecpbnverifyreq_571.req_u.dsa_verify.g) {
		kfree(g_ecpbnverifyreq_571.req_u.dsa_verify.g);
	}
	if(g_ecpbnverifyreq_571.req_u.dsa_verify.pub_key) {
		kfree(g_ecpbnverifyreq_571.req_u.dsa_verify.pub_key);
	}
	if(g_ecpbnverifyreq_571.req_u.dsa_verify.m) {
		kfree(g_ecpbnverifyreq_571.req_u.dsa_verify.m);
	}
	if(g_ecpbnverifyreq_571.req_u.dsa_verify.c) {
		kfree(g_ecpbnverifyreq_571.req_u.dsa_verify.c);
	}
	if(g_ecpbnverifyreq_571.req_u.dsa_verify.d) {
		kfree(g_ecpbnverifyreq_571.req_u.dsa_verify.d);
	}

	if(g_ecpbnsignreq_571.req_u.dsa_sign.q) {
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.q);
	}
	if(g_ecpbnsignreq_571.req_u.dsa_sign.r) {
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.r);
	}
	if(g_ecpbnsignreq_571.req_u.dsa_sign.ab) {
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.ab);
	}
	if(g_ecpbnsignreq_571.req_u.dsa_sign.g) {
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.g);
	}
	if(g_ecpbnsignreq_571.req_u.dsa_sign.priv_key) {
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.priv_key);
	}
	if(g_ecpbnsignreq_571.req_u.dsa_sign.m) {
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.m);
	}
	if(g_ecpbnsignreq_571.req_u.dsa_sign.c) {
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.c);
	}
	if(g_ecpbnsignreq_571.req_u.dsa_sign.d) {
		kfree(g_ecpbnsignreq_571.req_u.dsa_sign.d);
	}
}
