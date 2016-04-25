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
#include "test.h"
#include "ecdh_keygen_test.h"

struct pkc_request p256;
struct pkc_request p384;
struct pkc_request p521;
struct pkc_request b283;
struct pkc_request b409;
struct pkc_request b571;

void ecdh_keygen_done(struct pkc_request *req, int32_t sec_result)
{
#if 0 
    int i = 0;
    printk(KERN_ERR "Result... :%d \n", sec_result);
	printk(KERN_ERR "pubkey_len : %d\n",req->req_u.dh_keygenreq.pubkey_len);
	printk(KERN_ERR "prvkey_len : %d\n",req->req_u.dh_keygenreq.prvkey_len);

    for(i=0; i<req->req_u.dh_keygenreq.pubkey_len; i++)
        printk(KERN_ERR "%0x",req->req_u.dh_keygenreq.pubkey[i]);
    printk(KERN_ERR "\n\n");        
    for(i=0; i<req->req_u.dh_keygenreq.prvkey_len; i++)
        printk(KERN_ERR "%0x",req->req_u.dh_keygenreq.prvkey[i]);
                
    printk(KERN_ERR "\n\n");        
#endif

	common_dec_count();
}

void init_ecdh_keygen_test_p256(void)
{
	struct dh_keygen_req_s *req = &p256.req_u.dh_keygenreq;
	p256.type = ECDH_KEYGEN;

	req->q = kzalloc(sizeof(Q_256), GFP_KERNEL|GFP_DMA);
	req->r = kzalloc(sizeof(R_256), GFP_KERNEL|GFP_DMA);
	req->g = kzalloc(sizeof(G_256), GFP_KERNEL|GFP_DMA);
	req->ab = kzalloc(sizeof(AB_256), GFP_KERNEL|GFP_DMA);
	req->prvkey = kzalloc(sizeof(R_256), GFP_KERNEL|GFP_DMA);
	req->pubkey = kzalloc(sizeof(G_256), GFP_KERNEL|GFP_DMA);

	req->q_len = sizeof(Q_256);
	req->r_len = sizeof(R_256);
	req->g_len = sizeof(G_256);
	req->ab_len = sizeof(AB_256);
	req->prvkey_len = sizeof(R_256);
	req->pubkey_len = sizeof(G_256);

        memcpy(req->q, Q_256, sizeof(Q_256));
        memcpy(req->r, R_256, sizeof(R_256));
        memcpy(req->g, G_256, sizeof(G_256));
        memcpy(req->ab, AB_256, sizeof(AB_256));
}

void init_ecdh_keygen_test_p384(void)
{
	struct dh_keygen_req_s *req = &p384.req_u.dh_keygenreq;
	p384.type = ECDH_KEYGEN;

	req->q = kzalloc(sizeof(Q_384), GFP_KERNEL|GFP_DMA);
	req->r = kzalloc(sizeof(R_384), GFP_KERNEL|GFP_DMA);
	req->g = kzalloc(sizeof(G_384), GFP_KERNEL|GFP_DMA);
	req->ab = kzalloc(sizeof(AB_384), GFP_KERNEL|GFP_DMA);
	req->prvkey = kzalloc(sizeof(R_384), GFP_KERNEL|GFP_DMA);
	req->pubkey = kzalloc(sizeof(G_384), GFP_KERNEL|GFP_DMA);

	req->q_len = sizeof(Q_384);
	req->r_len = sizeof(R_384);
	req->g_len = sizeof(G_384);
	req->ab_len = sizeof(AB_384);
	req->prvkey_len = sizeof(R_384);
	req->pubkey_len = sizeof(G_384);

        memcpy(req->q, Q_384, sizeof(Q_384));
        memcpy(req->r, R_384, sizeof(R_384));
        memcpy(req->g, G_384, sizeof(G_384));
        memcpy(req->ab, AB_384, sizeof(AB_384));
}

void init_ecdh_keygen_test_p521(void)
{
	struct dh_keygen_req_s *req = &p521.req_u.dh_keygenreq;
	p521.type = ECDH_KEYGEN;

	req->q = kzalloc(sizeof(Q_521), GFP_KERNEL|GFP_DMA);
	req->r = kzalloc(sizeof(R_521), GFP_KERNEL|GFP_DMA);
	req->g = kzalloc(sizeof(G_521), GFP_KERNEL|GFP_DMA);
	req->ab = kzalloc(sizeof(AB_521), GFP_KERNEL|GFP_DMA);
	req->prvkey = kzalloc(sizeof(R_521), GFP_KERNEL|GFP_DMA);
	req->pubkey = kzalloc(sizeof(G_521), GFP_KERNEL|GFP_DMA);

	req->q_len = sizeof(Q_521);
	req->r_len = sizeof(R_521);
	req->g_len = sizeof(G_521);
	req->ab_len = sizeof(AB_521);
	req->prvkey_len = sizeof(R_521);
	req->pubkey_len = sizeof(G_521);

        memcpy(req->q, Q_521, sizeof(Q_521));
        memcpy(req->r, R_521, sizeof(R_521));
        memcpy(req->g, G_521, sizeof(G_521));
        memcpy(req->ab, AB_521, sizeof(AB_521));
}

void init_ecdh_keygen_test_b283(void)
{
	struct dh_keygen_req_s *req = &b283.req_u.dh_keygenreq;
	b283.type = ECDH_KEYGEN;
	b283.curve_type = ECC_BINARY;

	req->q = kzalloc(sizeof(Q_283), GFP_KERNEL|GFP_DMA);
	req->r = kzalloc(sizeof(R_283), GFP_KERNEL|GFP_DMA);
	req->g = kzalloc(sizeof(G_283), GFP_KERNEL|GFP_DMA);
	req->ab = kzalloc(sizeof(AB_283), GFP_KERNEL|GFP_DMA);
	req->prvkey = kzalloc(sizeof(R_283), GFP_KERNEL|GFP_DMA);
	req->pubkey = kzalloc(sizeof(G_283), GFP_KERNEL|GFP_DMA);

	req->q_len = sizeof(Q_283);
	req->r_len = sizeof(R_283);
	req->g_len = sizeof(G_283);
	req->ab_len = sizeof(AB_283);
	req->prvkey_len = sizeof(R_283);
	req->pubkey_len = sizeof(G_283);

        memcpy(req->q, Q_283, sizeof(Q_283));
        memcpy(req->r, R_283, sizeof(R_283));
        memcpy(req->g, G_283, sizeof(G_283));
        memcpy(req->ab, AB_283, sizeof(AB_283));
}

void init_ecdh_keygen_test_b409(void)
{
	struct dh_keygen_req_s *req = &b409.req_u.dh_keygenreq;
	b409.type = ECDH_KEYGEN;
	b409.curve_type = ECC_BINARY;

	req->q = kzalloc(sizeof(Q_409), GFP_KERNEL|GFP_DMA);
	req->r = kzalloc(sizeof(R_409), GFP_KERNEL|GFP_DMA);
	req->g = kzalloc(sizeof(G_409), GFP_KERNEL|GFP_DMA);
	req->ab = kzalloc(sizeof(AB_409), GFP_KERNEL|GFP_DMA);
	req->prvkey = kzalloc(sizeof(R_409), GFP_KERNEL|GFP_DMA);
	req->pubkey = kzalloc(sizeof(G_409), GFP_KERNEL|GFP_DMA);

	req->q_len = sizeof(Q_409);
	req->r_len = sizeof(R_409);
	req->g_len = sizeof(G_409);
	req->ab_len = sizeof(AB_409);
	req->prvkey_len = sizeof(R_409);
	req->pubkey_len = sizeof(G_409);

	memcpy(req->q, Q_409, sizeof(Q_409));
	memcpy(req->r, R_409, sizeof(R_409));
	memcpy(req->g, G_409, sizeof(G_409));
	memcpy(req->ab, AB_409, sizeof(AB_409));
}

void init_ecdh_keygen_test_b571(void)
{
	struct dh_keygen_req_s *req = &b571.req_u.dh_keygenreq;
	b571.type = ECDH_KEYGEN;
	b571.curve_type = ECC_BINARY;

	req->q = kzalloc(sizeof(Q_571), GFP_KERNEL|GFP_DMA);
	req->r = kzalloc(sizeof(R_571), GFP_KERNEL|GFP_DMA);
	req->g = kzalloc(sizeof(G_571), GFP_KERNEL|GFP_DMA);
	req->ab = kzalloc(sizeof(AB_571), GFP_KERNEL|GFP_DMA);
	req->prvkey = kzalloc(sizeof(R_571), GFP_KERNEL|GFP_DMA);
	req->pubkey = kzalloc(sizeof(G_571), GFP_KERNEL|GFP_DMA);

	req->q_len = sizeof(Q_571);
	req->r_len = sizeof(R_571);
	req->g_len = sizeof(G_571);
	req->ab_len = sizeof(AB_571);
	req->prvkey_len = sizeof(R_571);
	req->pubkey_len = sizeof(G_571);

	memcpy(req->q, Q_571, sizeof(Q_571));
	memcpy(req->r, R_571, sizeof(R_571));
	memcpy(req->g, G_571, sizeof(G_571));
	memcpy(req->ab, AB_571, sizeof(AB_571));
}

void cleanup_ecdh_keygen_test(void)
{
	if(p256.req_u.dh_keygenreq.q) {
		kfree(p256.req_u.dh_keygenreq.q);
	}
	if(p256.req_u.dh_keygenreq.r) {
		kfree(p256.req_u.dh_keygenreq.r);
	}
	if(p256.req_u.dh_keygenreq.g) {
		kfree(p256.req_u.dh_keygenreq.g);
	}
	if(p256.req_u.dh_keygenreq.ab) {
		kfree(p256.req_u.dh_keygenreq.ab);
	}
	if(p256.req_u.dh_keygenreq.pubkey) {
		kfree(p256.req_u.dh_keygenreq.pubkey);
	}
	if(p256.req_u.dh_keygenreq.prvkey) {
		kfree(p256.req_u.dh_keygenreq.prvkey);
	}


	if(p384.req_u.dh_keygenreq.q) {
		kfree(p384.req_u.dh_keygenreq.q);
	}
	if(p384.req_u.dh_keygenreq.r) {
		kfree(p384.req_u.dh_keygenreq.r);
	}
	if(p384.req_u.dh_keygenreq.g) {
		kfree(p384.req_u.dh_keygenreq.g);
	}
	if(p384.req_u.dh_keygenreq.ab) {
		kfree(p384.req_u.dh_keygenreq.ab);
	}
	if(p384.req_u.dh_keygenreq.pubkey) {
		kfree(p384.req_u.dh_keygenreq.pubkey);
	}
	if(p384.req_u.dh_keygenreq.prvkey) {
		kfree(p384.req_u.dh_keygenreq.prvkey);
	}


	if(p521.req_u.dh_keygenreq.q) {
		kfree(p521.req_u.dh_keygenreq.q);
	}
	if(p521.req_u.dh_keygenreq.r) {
		kfree(p521.req_u.dh_keygenreq.r);
	}
	if(p521.req_u.dh_keygenreq.g) {
		kfree(p521.req_u.dh_keygenreq.g);
	}
	if(p521.req_u.dh_keygenreq.ab) {
		kfree(p521.req_u.dh_keygenreq.ab);
	}
	if(p521.req_u.dh_keygenreq.pubkey) {
		kfree(p521.req_u.dh_keygenreq.pubkey);
	}
	if(p521.req_u.dh_keygenreq.prvkey) {
		kfree(p521.req_u.dh_keygenreq.prvkey);
	}

	if(b283.req_u.dh_keygenreq.q) {
		kfree(b283.req_u.dh_keygenreq.q);
	}
	if(b283.req_u.dh_keygenreq.r) {
		kfree(b283.req_u.dh_keygenreq.r);
	}
	if(b283.req_u.dh_keygenreq.g) {
		kfree(b283.req_u.dh_keygenreq.g);
	}
	if(b283.req_u.dh_keygenreq.ab) {
		kfree(b283.req_u.dh_keygenreq.ab);
	}
	if(b283.req_u.dh_keygenreq.pubkey) {
		kfree(b283.req_u.dh_keygenreq.pubkey);
	}
	if(b283.req_u.dh_keygenreq.prvkey) {
		kfree(b283.req_u.dh_keygenreq.prvkey);
	}


	if(b409.req_u.dh_keygenreq.q) {
		kfree(b409.req_u.dh_keygenreq.q);
	}
	if(b409.req_u.dh_keygenreq.r) {
		kfree(b409.req_u.dh_keygenreq.r);
	}
	if(b409.req_u.dh_keygenreq.g) {
		kfree(b409.req_u.dh_keygenreq.g);
	}
	if(b409.req_u.dh_keygenreq.ab) {
		kfree(b409.req_u.dh_keygenreq.ab);
	}
	if(b409.req_u.dh_keygenreq.pubkey) {
		kfree(b409.req_u.dh_keygenreq.pubkey);
	}
	if(b409.req_u.dh_keygenreq.prvkey) {
		kfree(b409.req_u.dh_keygenreq.prvkey);
	}


	if(b571.req_u.dh_keygenreq.q) {
		kfree(b571.req_u.dh_keygenreq.q);
	}
	if(b571.req_u.dh_keygenreq.r) {
		kfree(b571.req_u.dh_keygenreq.r);
	}
	if(b571.req_u.dh_keygenreq.g) {
		kfree(b571.req_u.dh_keygenreq.g);
	}
	if(b571.req_u.dh_keygenreq.ab) {
		kfree(b571.req_u.dh_keygenreq.ab);
	}
	if(b571.req_u.dh_keygenreq.pubkey) {
		kfree(b571.req_u.dh_keygenreq.pubkey);
	}
	if(b571.req_u.dh_keygenreq.prvkey) {
		kfree(b571.req_u.dh_keygenreq.prvkey);
	}
}

int ecdh_keygen_test_b409(void)
{
	return test_dh_op(&b409, ecdh_keygen_done);
}

int ecdh_keygen_test_b283(void)
{
	return test_dh_op(&b283, ecdh_keygen_done);
}

int ecdh_keygen_test_b571(void)
{
	return test_dh_op(&b571, ecdh_keygen_done);
}

int ecdh_keygen_test_p521(void)
{
	return test_dh_op(&p521, ecdh_keygen_done);
}

int ecdh_keygen_test_p384(void)
{
	return test_dh_op(&p384, ecdh_keygen_done);
}

int ecdh_keygen_test_p256(void)
{
	return test_dh_op(&p256, ecdh_keygen_done);
}

