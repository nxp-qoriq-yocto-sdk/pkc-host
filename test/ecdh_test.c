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
#include "types.h"
#include "algs.h"
#include "desc.h"

#include "test.h"

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);
/*
static DECLARE_COMPLETION(jobs_done);
static int count;
*/
atomic_t ecdh_enq_count;
atomic_t ecdh_deq_count;
struct pkc_request g_ecdhreq;

static uint8_t Q[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF
};

static uint8_t AB[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFC,
	0x1C, 0x97, 0xBE, 0xFC, 0x54, 0xBD, 0x7A, 0x8B, 0x65, 0xAC, 0xF8, 0x9F,
	0x81, 0xD4, 0xD4, 0xAD, 0xC5, 0x65, 0xFA, 0x45
};

static uint8_t W1[] = {
	0x62, 0x06, 0xa3, 0xdd, 0x25, 0x81, 0x29, 0xe6, 0xbd, 0xbb, 0x51, 0xa7,
	0xad, 0x7d,
	0x58, 0xfb, 0x3e, 0xa8, 0x4b, 0x4a, 0xbc, 0x2a, 0xca, 0xf2, 0xc4, 0xd6,
	0x00, 0x1d, 0xc1,
	0x47, 0x5e, 0x75, 0xef, 0x2a, 0x50, 0x89, 0x18, 0x3d, 0x48, 0x71
};
static uint8_t S2[] = {
	0x4d, 0x47, 0x6e, 0x7d, 0xea, 0x49, 0x6e, 0x3c, 0x9a, 0x2e, 0x04, 0xec,
	0xc2, 0x92, 0x6d,
	0x61, 0xdc, 0x12, 0x1b, 0xe3
};

#ifndef SIMPLE_TEST_ENABLE
void dec_count(void)
{
#ifndef PERF_TEST
	int32_t d_cnt = 0;
	d_cnt = atomic_inc_return(&ecdh_deq_count);

	print_debug("Deq cnt... :%d\n", d_cnt);
#endif
	atomic_inc(&total_deq_cnt);
}
#endif

void ecdh_done(struct pkc_request *req, int32_t sec_result)
{
#ifndef SIMPLE_TEST_ENABLE
#ifndef PERF_TEST
	uint32_t i = 0;
#endif
	print_debug("************* ECDH  DONE ************\n");

#ifndef PERF_TEST
	print_debug(" Z\n");
	print_debug("Length : %d\n", req->req_u.dh_req.z_len);

	for (i = 0; i < req->req_u.dh_req.z_len; i++)
		print_debug("0x%0x,", req->req_u.dh_req.z[i]);

#endif

	kfree(req->req_u.dh_req.z);
	kfree(req);
	dec_count();
#endif
	common_dec_count();
}

void init_ecdh_test(void)
{
	g_ecdhreq.type = ECDH_COMPUTE_KEY;

	g_ecdhreq.req_u.dh_req.q = kzalloc(sizeof(Q), GFP_KERNEL | GFP_DMA);
	g_ecdhreq.req_u.dh_req.pub_key = kzalloc(sizeof(W1), GFP_KERNEL | GFP_DMA);
	g_ecdhreq.req_u.dh_req.s = kzalloc(sizeof(S2), GFP_KERNEL | GFP_DMA);
	g_ecdhreq.req_u.dh_req.ab = kzalloc(sizeof(AB), GFP_KERNEL | GFP_DMA);
	g_ecdhreq.req_u.dh_req.z = kzalloc(sizeof(Q), GFP_KERNEL | GFP_DMA);

	g_ecdhreq.req_u.dh_req.q_len = sizeof(Q);
	g_ecdhreq.req_u.dh_req.pub_key_len = sizeof(W1);
	g_ecdhreq.req_u.dh_req.s_len = sizeof(S2);
	g_ecdhreq.req_u.dh_req.ab_len = sizeof(AB);
	g_ecdhreq.req_u.dh_req.z_len = sizeof(Q);

	memcpy(g_ecdhreq.req_u.dh_req.q, Q, sizeof(Q));
	memcpy(g_ecdhreq.req_u.dh_req.pub_key, W1, sizeof(W1));
	memcpy(g_ecdhreq.req_u.dh_req.s, S2, sizeof(S2));
	memcpy(g_ecdhreq.req_u.dh_req.ab, AB, sizeof(AB));
}

void cleanup_ecdh_test(void)
{
	if(g_ecdhreq.req_u.dh_req.z) {
		kfree(g_ecdhreq.req_u.dh_req.z);
	}
	if(g_ecdhreq.req_u.dh_req.ab) {
		kfree(g_ecdhreq.req_u.dh_req.ab);
	}
	if(g_ecdhreq.req_u.dh_req.s) {
		kfree(g_ecdhreq.req_u.dh_req.s);
	}
	if(g_ecdhreq.req_u.dh_req.pub_key) {
		kfree(g_ecdhreq.req_u.dh_req.pub_key);
	}
	if(g_ecdhreq.req_u.dh_req.q) {
		kfree(g_ecdhreq.req_u.dh_req.q);
	}
}

int ecdh_test(void)
{
	return test_dh_op(&g_ecdhreq, ecdh_done);
}
