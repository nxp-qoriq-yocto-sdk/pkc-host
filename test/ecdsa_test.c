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
#include "pkc_desc.h"
#include "desc.h"
#include "memmgr.h"

#include"test.h"

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);

atomic_t ecdsa_enq_count;
atomic_t ecdsa_deq_count;

struct pkc_request g_ecdsaverifyreq;
struct pkc_request g_ecdsasignreq;

static uint8_t Q[] = {
	0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
	0XFF, 0XFF, 0XFF, 0XFE, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF
};
static uint8_t R[] = {
	0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
	0X99, 0XDE, 0XF8, 0X36, 0X14, 0X6B, 0XC9, 0XB1, 0XB4, 0XD2, 0X28, 0X31
};
static uint8_t AB[] = {
	0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
	0XFF, 0XFF, 0XFF, 0XFE, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFC,
	0X64, 0X21, 0X05, 0X19, 0XE5, 0X9C, 0X80, 0XE7, 0X0F, 0XA7, 0XE9, 0XAB,
	0X72, 0X24, 0X30, 0X49, 0XFE, 0XB8, 0XDE, 0XEC, 0XC1, 0X46, 0XB9, 0XB1
};
static uint8_t G[] = {
	0X18, 0X8D, 0XA8, 0X0E, 0XB0, 0X30, 0X90, 0XF6, 0X7C, 0XBF, 0X20, 0XEB,
	0X43, 0XA1, 0X88, 0X00, 0XF4, 0XFF, 0X0A, 0XFD, 0X82, 0XFF, 0X10, 0X12,
	0X07, 0X19, 0X2B, 0X95, 0XFF, 0XC8, 0XDA, 0X78, 0X63, 0X10, 0X11, 0XED,
	0X6B, 0X24, 0XCD, 0XD5, 0X73, 0XF9, 0X77, 0XA1, 0X1E, 0X79, 0X48, 0X11
};
static uint8_t PRIV_KEY[] = {
	0X13, 0XBD, 0XA6, 0XFE, 0X20, 0XE2, 0X8F, 0X2C, 0X7F, 0X17, 0X7D, 0X27,
	0XBC, 0X1D, 0XDF, 0X69, 0X73, 0X3C, 0XD3, 0XFC, 0X51, 0X70, 0X4F, 0X34
};
static uint8_t PUB_KEY[] = {
	0XCF, 0X69, 0XC4, 0XA4, 0XE7, 0X13, 0XD3, 0XC1, 0X1D, 0XEC, 0X21, 0XC8,
	0XA7, 0XBC, 0XD6, 0X16, 0X6D, 0XA9, 0X4D, 0XE4, 0XF1, 0XB1, 0X23, 0XA5,
	0X34, 0XBC, 0XEE, 0X9E, 0X75, 0XE5, 0X80, 0X99, 0X89, 0XA7, 0X3B, 0X82,
	0X48, 0XE1, 0XBE, 0XDF, 0XF5, 0X5F, 0X95, 0X5A, 0X09, 0X43, 0X8B, 0X3D
};
static uint8_t M[] = {
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
	0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C,
	0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80
};

static uint8_t C[] = {
	0x3b, 0x6e, 0xcc, 0x31, 0x0c, 0x95, 0xb9, 0x12, 0x53, 0x16, 0x01, 0x36,
	0xee, 0x02, 0xad, 0x8d, 0x8d, 0x21, 0x96, 0x4b, 0x69, 0x25, 0x29, 0xa1
};

static uint8_t D[] = {
	0x9b, 0x55, 0xab, 0x03, 0x04, 0x4d, 0xfe, 0x1c, 0x82, 0x46, 0x92, 0x22,
	0x3b, 0xcd, 0x4b, 0xbf, 0x3a, 0xb8, 0xfd, 0xb0, 0x1b, 0xc7, 0x7c, 0xf5
};

static struct completion keygen_control_completion_var;
#ifndef SIMPLE_TEST_ENABLE
static void dec_count(void)
{
#ifndef PERF_TEST
	int32_t d_cnt = 0;
	d_cnt = atomic_inc_return(&ecdsa_deq_count);

	print_debug("Deq cnt... :%d\n", d_cnt);
#endif
	atomic_inc(&total_deq_cnt);
}
#endif

void ecdsa_keygen_done(struct pkc_request *req, int32_t sec_result)
{
	print_debug("req: %p, sec_result: %0x \n", req, sec_result);
	complete(&keygen_control_completion_var);
}

void ecdsa_done(struct pkc_request *req, int32_t sec_result)
{
#ifndef SIMPLE_TEST_ENABLE
#ifndef PERF_TEST
	uint32_t i = 0;
#endif
	print_debug("ECDSA REQ TYPE [%d]\n", req->type);
	print_debug("RESULT: %d\n ", sec_result);
	switch (req->type) {
	case ECDSA_SIGN:
#ifndef PERF_TEST
		print_debug("C/D\n");
		print_debug("Length: %d\n", req->req_u.dsa_sign.d_len);

		print_debug("C\n");
		for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
			print_debug("%x,\t", req->req_u.dsa_sign.c[i]);

		print_debug("D\n");
		for (i = 0; i < req->req_u.dsa_sign.d_len; i++)
			print_debug("%x,\t", req->req_u.dsa_sign.d[i]);

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
#endif
	common_dec_count();
}

void init_ecdsa_verify_test(void)
{
	g_ecdsaverifyreq.type = ECDSA_VERIFY;

	g_ecdsaverifyreq.req_u.dsa_verify.q = Q;
	g_ecdsaverifyreq.req_u.dsa_verify.q_len = sizeof(Q);

	g_ecdsaverifyreq.req_u.dsa_verify.r = R;
	g_ecdsaverifyreq.req_u.dsa_verify.r_len = sizeof(R);

	g_ecdsaverifyreq.req_u.dsa_verify.ab = AB;
	g_ecdsaverifyreq.req_u.dsa_verify.ab_len = sizeof(AB);

	g_ecdsaverifyreq.req_u.dsa_verify.g = G;
	g_ecdsaverifyreq.req_u.dsa_verify.g_len = sizeof(G);

	g_ecdsaverifyreq.req_u.dsa_verify.pub_key = PUB_KEY;
	g_ecdsaverifyreq.req_u.dsa_verify.pub_key_len = sizeof(PUB_KEY);

	g_ecdsaverifyreq.req_u.dsa_verify.m = M;
	g_ecdsaverifyreq.req_u.dsa_verify.m_len = sizeof(M);

	g_ecdsaverifyreq.req_u.dsa_verify.c = C;

	g_ecdsaverifyreq.req_u.dsa_verify.d = D;
	g_ecdsaverifyreq.req_u.dsa_verify.d_len = sizeof(D);
}

void init_ecdsa_sign_test(void)
{
	g_ecdsasignreq.type = ECDSA_SIGN;

	g_ecdsasignreq.req_u.dsa_sign.q = Q;
	g_ecdsasignreq.req_u.dsa_sign.q_len = sizeof(Q);

	g_ecdsasignreq.req_u.dsa_sign.r = R;
	g_ecdsasignreq.req_u.dsa_sign.r_len = sizeof(R);

	g_ecdsasignreq.req_u.dsa_sign.ab = AB;
	g_ecdsasignreq.req_u.dsa_sign.ab_len = sizeof(AB);

	g_ecdsasignreq.req_u.dsa_sign.g = G;
	g_ecdsasignreq.req_u.dsa_sign.g_len = sizeof(G);

	g_ecdsasignreq.req_u.dsa_sign.priv_key = PRIV_KEY;
	g_ecdsasignreq.req_u.dsa_sign.priv_key_len = sizeof(PRIV_KEY);

	g_ecdsasignreq.req_u.dsa_sign.m = M;
	g_ecdsasignreq.req_u.dsa_sign.m_len = sizeof(M);

	g_ecdsasignreq.req_u.dsa_sign.c = kzalloc(sizeof(D), GFP_KERNEL | GFP_DMA);

	g_ecdsasignreq.req_u.dsa_sign.d = kzalloc(sizeof(D), GFP_KERNEL | GFP_DMA);
	g_ecdsasignreq.req_u.dsa_sign.d_len = sizeof(D);
}

void cleanup_ecdsa_test(void)
{
	if(g_ecdsasignreq.req_u.dsa_sign.c) {
		kfree(g_ecdsasignreq.req_u.dsa_sign.c);
	}
	if(g_ecdsasignreq.req_u.dsa_sign.d) {
		kfree(g_ecdsasignreq.req_u.dsa_sign.d);
	}
}

int ecdsa_verify_test(void)
{
	if (-1 == test_dsa_op(&g_ecdsaverifyreq, ecdsa_done)) {
		return -1;
	}

	return 0;
}

int ecdsa_sign_test(void)
{
	if (-1 == test_dsa_op(&g_ecdsasignreq, ecdsa_done)) {
		return -1;
	}

	return 0;
}

int ecdsa_keygen_verify_test(struct pkc_request *genreq,
			     struct pkc_request *signreq,
			     struct pkc_request *req)
{
	int ret = 0;

	req->type = ECDSA_VERIFY;

	req->req_u.dsa_verify.q = Q;
	req->req_u.dsa_verify.q_len = sizeof(Q);

	req->req_u.dsa_verify.r = R;
	req->req_u.dsa_verify.r_len = sizeof(R);

	req->req_u.dsa_verify.ab = AB;
	req->req_u.dsa_verify.ab_len = sizeof(AB);

	req->req_u.dsa_verify.g = G;
	req->req_u.dsa_verify.g_len = sizeof(G);

	req->req_u.dsa_verify.pub_key = kzalloc(sizeof(PUB_KEY), GFP_KERNEL);
	memcpy(req->req_u.dsa_verify.pub_key, genreq->req_u.dsa_keygen.pubkey,
	       sizeof(PUB_KEY));
	req->req_u.dsa_verify.pub_key_len = sizeof(PUB_KEY);

	req->req_u.dsa_verify.m = M;
	req->req_u.dsa_verify.m_len = sizeof(M);

	req->req_u.dsa_verify.c = kzalloc(sizeof(D), GFP_KERNEL);
	memcpy(req->req_u.dsa_verify.c, signreq->req_u.dsa_sign.c, sizeof(D));

	req->req_u.dsa_verify.d = kzalloc(sizeof(D), GFP_KERNEL);
	memcpy(req->req_u.dsa_verify.d, signreq->req_u.dsa_sign.d, sizeof(D));
	req->req_u.dsa_verify.d_len = sizeof(D);

	ret = test_dsa_op(req, ecdsa_keygen_done);

	return ret;
}

int ecdsa_keygen_sign_test(struct pkc_request *genreq, struct pkc_request *req)
{
	int ret = 0;

	req->type = ECDSA_SIGN;

	req->req_u.dsa_sign.q = Q;
	req->req_u.dsa_sign.q_len = sizeof(Q);

	req->req_u.dsa_sign.r = R;
	req->req_u.dsa_sign.r_len = sizeof(R);

	req->req_u.dsa_sign.ab = AB;
	req->req_u.dsa_sign.ab_len = sizeof(AB);

	req->req_u.dsa_sign.g = G;
	req->req_u.dsa_sign.g_len = sizeof(G);

	req->req_u.dsa_sign.priv_key = kzalloc(sizeof(PRIV_KEY), GFP_KERNEL);
	memcpy(req->req_u.dsa_sign.priv_key, genreq->req_u.dsa_keygen.prvkey,
	       sizeof(PRIV_KEY));
	req->req_u.dsa_sign.priv_key_len = sizeof(PRIV_KEY);

	req->req_u.dsa_sign.m = M;
	req->req_u.dsa_sign.m_len = sizeof(M);

	req->req_u.dsa_sign.c = kzalloc(sizeof(D), GFP_KERNEL | GFP_DMA);

	req->req_u.dsa_sign.d = kzalloc(sizeof(D), GFP_KERNEL | GFP_DMA);
	req->req_u.dsa_sign.d_len = sizeof(D);

	ret = test_dsa_op(req, ecdsa_keygen_done);

	return ret;
}

int ecdsa_keygen_test(void)
{
	int ret = -ENOMEM;
	struct pkc_request *genreq, *signreq, *verifyreq;
	void *tmp;

	genreq = kzalloc(sizeof(*genreq), GFP_KERNEL);
	if (!genreq)
		return ret;

	signreq = kzalloc(sizeof(*signreq), GFP_KERNEL);
	if (!signreq)
		goto no_signreq;

	verifyreq = kzalloc(sizeof(*verifyreq), GFP_KERNEL);
	if (!verifyreq)
		goto no_verifyreq;

	tmp = kzalloc(sizeof(PUB_KEY), GFP_KERNEL | GFP_DMA);
	if (!tmp)
		goto no_pubkey;
	genreq->req_u.dsa_keygen.pubkey = tmp;

	tmp = kzalloc(sizeof(PRIV_KEY), GFP_KERNEL | GFP_DMA);
	if (!tmp)
		goto no_prvkey;
	genreq->req_u.dsa_keygen.prvkey = tmp;

	init_completion(&keygen_control_completion_var);

	genreq->type = ECDSA_KEYGEN;
	genreq->req_u.dsa_keygen.pubkey_len = sizeof(PUB_KEY);
	genreq->req_u.dsa_keygen.prvkey_len = sizeof(PRIV_KEY);
	genreq->req_u.dsa_keygen.q = Q;
	genreq->req_u.dsa_keygen.q_len = sizeof(Q);
	genreq->req_u.dsa_keygen.r = R;
	genreq->req_u.dsa_keygen.r_len = sizeof(R);
	genreq->req_u.dsa_keygen.g = G;
	genreq->req_u.dsa_keygen.g_len = sizeof(G);
	genreq->req_u.dsa_keygen.ab = AB;
	genreq->req_u.dsa_keygen.ab_len = sizeof(AB);

	ret = test_dsa_op(genreq, ecdsa_keygen_done);
	if (-1 == ret)
		goto error;

	wait_for_completion(&keygen_control_completion_var);

	ret = ecdsa_keygen_sign_test(genreq, signreq);
	if (-1 == ret)
		goto error;

	wait_for_completion(&keygen_control_completion_var);

	ret = ecdsa_keygen_verify_test(genreq, signreq, verifyreq);
	if (-1 == ret)
		goto error;

	wait_for_completion(&keygen_control_completion_var);

	common_dec_count();

error:
	kfree(signreq->req_u.dsa_sign.c);
	kfree(signreq->req_u.dsa_sign.d);
	kfree(signreq->req_u.dsa_sign.priv_key);

	kfree(verifyreq->req_u.dsa_verify.c);
	kfree(verifyreq->req_u.dsa_verify.d);
	kfree(verifyreq->req_u.dsa_verify.pub_key);

	kfree(genreq->req_u.dsa_keygen.prvkey);
no_prvkey:
	kfree(genreq->req_u.dsa_keygen.pubkey);
no_pubkey:
	kfree(verifyreq);
no_verifyreq:
	kfree(signreq);
no_signreq:
	kfree(genreq);
	return ret;
}

