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
#include "memmgr.h"
#include "test.h"
#include "rsa_test.h"

typedef void (*cb) (struct pkc_request *req, int32_t sec_result);
/*static DECLARE_COMPLETION(jobs_done);*/
atomic_t rsa_enq_count;
atomic_t rsa_deq_count;
/**** WORKING TEST INPUTS ****/
/* PUB OP BUFFERS */

struct pkc_request g_1kpubopreq;
struct pkc_request g_2kpubopreq;
struct pkc_request g_4kpubopreq;
struct pkc_request g_1kprv3opreq;
struct pkc_request g_2kprv3opreq;
struct pkc_request g_4kprv3opreq;

dma_addr_t pub_1k_n, pub_1k_e, pub_1k_f, pub_2k_n, pub_2k_e, pub_2k_f, pub_4k_n, pub_4k_e, pub_4k_f, pri_1k_p, pri_1k_q, pri_1k_dp, pri_1k_dq, pri_1k_c, pri_1k_g, pri_2k_p, pri_2k_q, pri_2k_dp, pri_2k_dq, pri_2k_c, pri_2k_g, pri_4k_p, pri_4k_q, pri_4k_dp, pri_4k_dq, pri_4k_c, pri_4k_g;

void init_1k_rsa_pub_op_req(void)
{
#ifndef USE_SEC_DIRECT_READ
	g_1kpubopreq.type = RSA_PUB;

	g_1kpubopreq.req_u.rsa_pub_req.n = PUB_N_1024;
	g_1kpubopreq.req_u.rsa_pub_req.n_len = (pub_n_len);

	g_1kpubopreq.req_u.rsa_pub_req.e = PUB_E_1024;
	g_1kpubopreq.req_u.rsa_pub_req.e_len = (pub_e_len);

	g_1kpubopreq.req_u.rsa_pub_req.f = PUB_F_1024;
	g_1kpubopreq.req_u.rsa_pub_req.f_len = (pub_f_len);

	g_1kpubopreq.req_u.rsa_pub_req.g =
	    kzalloc(pub_n_len, GFP_KERNEL | GFP_DMA);
	g_1kpubopreq.req_u.rsa_pub_req.g_len = pub_n_len;
#else
	g_1kpubopreq.type = RSA_PUB;

	g_1kpubopreq.req_u.rsa_pub_req.n = kzalloc(pub_n_len, GFP_KERNEL | GFP_DMA);
	g_1kpubopreq.req_u.rsa_pub_req.n_len = (pub_n_len);
	pub_1k_n = pci_map_single(g_fsl_pci_dev->dev, g_1kpubopreq.req_u.rsa_pub_req.n, pub_n_len, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_1kpubopreq.req_u.rsa_pub_req.n ,PUB_N_1024, pub_n_len);

	g_1kpubopreq.req_u.rsa_pub_req.e = kzalloc(ALIGN_LEN_TO_DMA(pub_e_len), GFP_KERNEL | GFP_DMA);
	g_1kpubopreq.req_u.rsa_pub_req.e_len = (pub_e_len);
	pub_1k_e = pci_map_single(g_fsl_pci_dev->dev, g_1kpubopreq.req_u.rsa_pub_req.e,
			ALIGN_LEN_TO_DMA(pub_e_len), PCI_DMA_BIDIRECTIONAL);
	memcpy(g_1kpubopreq.req_u.rsa_pub_req.e ,PUB_E_1024, pub_e_len);

	g_1kpubopreq.req_u.rsa_pub_req.f = kzalloc(pub_f_len, GFP_KERNEL | GFP_DMA);
	g_1kpubopreq.req_u.rsa_pub_req.f_len = (pub_f_len);
	pub_1k_f = pci_map_single(g_fsl_pci_dev->dev, g_1kpubopreq.req_u.rsa_pub_req.f, pub_f_len, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_1kpubopreq.req_u.rsa_pub_req.f ,PUB_F_1024, pub_f_len);

	g_1kpubopreq.req_u.rsa_pub_req.g =
	    kzalloc(pub_n_len, GFP_KERNEL | GFP_DMA);
	g_1kpubopreq.req_u.rsa_pub_req.g_len = pub_n_len;
#endif
}

void init_2k_rsa_pub_op_req(void)
{
#ifndef USE_SEC_DIRECT_READ
	g_2kpubopreq.type = RSA_PUB;

	g_2kpubopreq.req_u.rsa_pub_req.n = N_2048;
	g_2kpubopreq.req_u.rsa_pub_req.n_len = (n_2048);

	g_2kpubopreq.req_u.rsa_pub_req.e = E_2048;
	g_2kpubopreq.req_u.rsa_pub_req.e_len = (e_2048);

	g_2kpubopreq.req_u.rsa_pub_req.f = F_2048;
	g_2kpubopreq.req_u.rsa_pub_req.f_len = (f_2048);

	g_2kpubopreq.req_u.rsa_pub_req.g =
	    kzalloc(n_2048, GFP_KERNEL | GFP_DMA);
	g_2kpubopreq.req_u.rsa_pub_req.g_len = n_2048;
#else
	g_2kpubopreq.type = RSA_PUB;

	g_2kpubopreq.req_u.rsa_pub_req.n = kzalloc(n_2048, GFP_KERNEL | GFP_DMA);
	g_2kpubopreq.req_u.rsa_pub_req.n_len = (n_2048);
	pub_2k_n = pci_map_single(g_fsl_pci_dev->dev, g_2kpubopreq.req_u.rsa_pub_req.n, n_2048, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_2kpubopreq.req_u.rsa_pub_req.n ,N_2048, n_2048);

	g_2kpubopreq.req_u.rsa_pub_req.e = kzalloc(ALIGN_LEN_TO_DMA(e_2048), GFP_KERNEL | GFP_DMA);
	g_2kpubopreq.req_u.rsa_pub_req.e_len = (e_2048);
	pub_2k_e = pci_map_single(g_fsl_pci_dev->dev, g_2kpubopreq.req_u.rsa_pub_req.e, ALIGN_LEN_TO_DMA(e_2048), PCI_DMA_BIDIRECTIONAL);
	memcpy(g_2kpubopreq.req_u.rsa_pub_req.e ,E_2048, e_2048);

	g_2kpubopreq.req_u.rsa_pub_req.f = kzalloc(f_2048, GFP_KERNEL | GFP_DMA);
	g_2kpubopreq.req_u.rsa_pub_req.f_len = (f_2048);
	pub_2k_f = pci_map_single(g_fsl_pci_dev->dev, g_2kpubopreq.req_u.rsa_pub_req.f, f_2048, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_2kpubopreq.req_u.rsa_pub_req.f ,F_2048, f_2048);

	g_2kpubopreq.req_u.rsa_pub_req.g =
	    kzalloc(n_2048, GFP_KERNEL | GFP_DMA);
	g_2kpubopreq.req_u.rsa_pub_req.g_len = n_2048;
#endif
}

void init_4k_rsa_pub_op_req(void)
{
#ifndef USE_SEC_DIRECT_READ
	g_4kpubopreq.type = RSA_PUB;

	g_4kpubopreq.req_u.rsa_pub_req.n = N_4096;
	g_4kpubopreq.req_u.rsa_pub_req.n_len = (n_4096);

	g_4kpubopreq.req_u.rsa_pub_req.e = E_4096;
	g_4kpubopreq.req_u.rsa_pub_req.e_len = (e_4096);

	g_4kpubopreq.req_u.rsa_pub_req.f = F_4096;
	g_4kpubopreq.req_u.rsa_pub_req.f_len = (f_4096);

	g_4kpubopreq.req_u.rsa_pub_req.g =
	    kzalloc(n_4096, GFP_KERNEL | GFP_DMA);
	g_4kpubopreq.req_u.rsa_pub_req.g_len = n_4096;
#else
	g_4kpubopreq.type = RSA_PUB;

	g_4kpubopreq.req_u.rsa_pub_req.n = kzalloc(n_4096, GFP_KERNEL | GFP_DMA);
	g_4kpubopreq.req_u.rsa_pub_req.n_len = (n_4096);
	pub_4k_n = pci_map_single(g_fsl_pci_dev->dev, g_4kpubopreq.req_u.rsa_pub_req.n, n_4096, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_4kpubopreq.req_u.rsa_pub_req.n ,N_4096, n_4096);

	g_4kpubopreq.req_u.rsa_pub_req.e = kzalloc(ALIGN_LEN_TO_DMA(e_4096), GFP_KERNEL | GFP_DMA);
	g_4kpubopreq.req_u.rsa_pub_req.e_len = (e_4096);
	pub_4k_e = pci_map_single(g_fsl_pci_dev->dev, g_4kpubopreq.req_u.rsa_pub_req.e, ALIGN_LEN_TO_DMA(e_4096), PCI_DMA_BIDIRECTIONAL);
	memcpy(g_4kpubopreq.req_u.rsa_pub_req.e ,E_4096, e_4096);

	g_4kpubopreq.req_u.rsa_pub_req.f = kzalloc(f_4096, GFP_KERNEL | GFP_DMA);
	g_4kpubopreq.req_u.rsa_pub_req.f_len = (f_4096);
	pub_4k_f = pci_map_single(g_fsl_pci_dev->dev, g_4kpubopreq.req_u.rsa_pub_req.f, f_4096, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_4kpubopreq.req_u.rsa_pub_req.f ,F_4096, f_4096);

	g_4kpubopreq.req_u.rsa_pub_req.g =
	    kzalloc(n_4096, GFP_KERNEL | GFP_DMA);
	g_4kpubopreq.req_u.rsa_pub_req.g_len = n_4096;
#endif
}

void init_1k_rsa_prv3_op_req(void)
{
#ifndef USE_SEC_DIRECT_READ
	g_1kprv3opreq.type = RSA_PRIV_FORM3;

	g_1kprv3opreq.req_u.rsa_priv_f3.p = (uint8_t *) PRV3_P_1024;
	g_1kprv3opreq.req_u.rsa_priv_f3.p_len = prv3_p_len;

	g_1kprv3opreq.req_u.rsa_priv_f3.q = (uint8_t *) PRV3_Q_1024;
	g_1kprv3opreq.req_u.rsa_priv_f3.q_len = prv3_q_len;

	g_1kprv3opreq.req_u.rsa_priv_f3.dp = (uint8_t *) PRV3_DP_1024;
	g_1kprv3opreq.req_u.rsa_priv_f3.dp_len = prv3_dp_len;

	g_1kprv3opreq.req_u.rsa_priv_f3.dq = (uint8_t *) PRV3_DQ_1024;
	g_1kprv3opreq.req_u.rsa_priv_f3.dq_len = prv3_dq_len;

	g_1kprv3opreq.req_u.rsa_priv_f3.c = (uint8_t *) PRV3_C_1024;
	g_1kprv3opreq.req_u.rsa_priv_f3.c_len = prv3_c_len;

	g_1kprv3opreq.req_u.rsa_priv_f3.g = (uint8_t *) PRV3_G_1024;
	g_1kprv3opreq.req_u.rsa_priv_f3.g_len = prv3_g_len;

	g_1kprv3opreq.req_u.rsa_priv_f3.f =
	    kzalloc(prv3_n_len, GFP_KERNEL | GFP_DMA);
	g_1kprv3opreq.req_u.rsa_priv_f3.f_len = prv3_n_len;
#else
	g_1kprv3opreq.type = RSA_PRIV_FORM3;

	g_1kprv3opreq.req_u.rsa_priv_f3.p = kzalloc(prv3_p_len, GFP_KERNEL | GFP_DMA);
	g_1kprv3opreq.req_u.rsa_priv_f3.p_len = prv3_p_len;
	pri_1k_p = pci_map_single(g_fsl_pci_dev->dev, g_1kprv3opreq.req_u.rsa_priv_f3.p, prv3_p_len, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_1kprv3opreq.req_u.rsa_priv_f3.p, PRV3_P_1024, prv3_p_len);

	g_1kprv3opreq.req_u.rsa_priv_f3.q = kzalloc(prv3_q_len, GFP_KERNEL | GFP_DMA);
	g_1kprv3opreq.req_u.rsa_priv_f3.q_len = prv3_q_len;
	pri_1k_q = pci_map_single(g_fsl_pci_dev->dev, g_1kprv3opreq.req_u.rsa_priv_f3.q, prv3_q_len, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_1kprv3opreq.req_u.rsa_priv_f3.q, PRV3_Q_1024, prv3_q_len);

	g_1kprv3opreq.req_u.rsa_priv_f3.dp = kzalloc(prv3_dp_len, GFP_KERNEL | GFP_DMA);
	g_1kprv3opreq.req_u.rsa_priv_f3.dp_len = prv3_dp_len;
	pri_1k_dp = pci_map_single(g_fsl_pci_dev->dev, g_1kprv3opreq.req_u.rsa_priv_f3.dp, prv3_dp_len, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_1kprv3opreq.req_u.rsa_priv_f3.dp, PRV3_DP_1024, prv3_dp_len);

	g_1kprv3opreq.req_u.rsa_priv_f3.dq = kzalloc(prv3_dq_len, GFP_KERNEL | GFP_DMA);
	g_1kprv3opreq.req_u.rsa_priv_f3.dq_len = prv3_dq_len;
	pri_1k_dq = pci_map_single(g_fsl_pci_dev->dev, g_1kprv3opreq.req_u.rsa_priv_f3.dq, prv3_dq_len, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_1kprv3opreq.req_u.rsa_priv_f3.dq, PRV3_DQ_1024, prv3_dq_len);

	g_1kprv3opreq.req_u.rsa_priv_f3.c = kzalloc(prv3_c_len, GFP_KERNEL | GFP_DMA);
	g_1kprv3opreq.req_u.rsa_priv_f3.c_len = prv3_c_len;
	pri_1k_c = pci_map_single(g_fsl_pci_dev->dev, g_1kprv3opreq.req_u.rsa_priv_f3.c, prv3_c_len, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_1kprv3opreq.req_u.rsa_priv_f3.c, PRV3_C_1024, prv3_c_len);

	g_1kprv3opreq.req_u.rsa_priv_f3.g = kzalloc(prv3_g_len, GFP_KERNEL | GFP_DMA);
	g_1kprv3opreq.req_u.rsa_priv_f3.g_len = prv3_g_len;
	pri_1k_g = pci_map_single(g_fsl_pci_dev->dev, g_1kprv3opreq.req_u.rsa_priv_f3.g, prv3_g_len, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_1kprv3opreq.req_u.rsa_priv_f3.g, PRV3_G_1024, prv3_g_len);

	g_1kprv3opreq.req_u.rsa_priv_f3.f =
	    kzalloc(prv3_n_len, GFP_KERNEL | GFP_DMA);
	g_1kprv3opreq.req_u.rsa_priv_f3.f_len = prv3_n_len;
#endif
}

void init_2k_rsa_prv3_op_req(void)
{
#ifndef USE_SEC_DIRECT_READ
	g_2kprv3opreq.type = RSA_PRIV_FORM3;

	g_2kprv3opreq.req_u.rsa_priv_f3.p = (uint8_t *) P_2048;
	g_2kprv3opreq.req_u.rsa_priv_f3.p_len = p_2048;

	g_2kprv3opreq.req_u.rsa_priv_f3.q = (uint8_t *) Q_2048;
	g_2kprv3opreq.req_u.rsa_priv_f3.q_len = q_2048;

	g_2kprv3opreq.req_u.rsa_priv_f3.dp = (uint8_t *) DP1_2048;
	g_2kprv3opreq.req_u.rsa_priv_f3.dp_len = dp1_2048;

	g_2kprv3opreq.req_u.rsa_priv_f3.dq = (uint8_t *) DQ1_2048;
	g_2kprv3opreq.req_u.rsa_priv_f3.dq_len = dq1_2048;

	g_2kprv3opreq.req_u.rsa_priv_f3.c = (uint8_t *) C_2048;
	g_2kprv3opreq.req_u.rsa_priv_f3.c_len = c_2048;

	g_2kprv3opreq.req_u.rsa_priv_f3.g = (uint8_t *) N_2048;
	g_2kprv3opreq.req_u.rsa_priv_f3.g_len = n_2048;

	g_2kprv3opreq.req_u.rsa_priv_f3.f =
	    kzalloc(n_2048, GFP_KERNEL | GFP_DMA);
	g_2kprv3opreq.req_u.rsa_priv_f3.f_len = n_2048;
#else
	g_2kprv3opreq.type = RSA_PRIV_FORM3;

	g_2kprv3opreq.req_u.rsa_priv_f3.p = kzalloc(p_2048, GFP_KERNEL | GFP_DMA);
	g_2kprv3opreq.req_u.rsa_priv_f3.p_len = p_2048;
	pri_2k_p = pci_map_single(g_fsl_pci_dev->dev, g_2kprv3opreq.req_u.rsa_priv_f3.p, p_2048, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_2kprv3opreq.req_u.rsa_priv_f3.p, P_2048, p_2048);

	g_2kprv3opreq.req_u.rsa_priv_f3.q = kzalloc(q_2048, GFP_KERNEL | GFP_DMA);
	g_2kprv3opreq.req_u.rsa_priv_f3.q_len = q_2048;
	pri_2k_q = pci_map_single(g_fsl_pci_dev->dev, g_2kprv3opreq.req_u.rsa_priv_f3.q, q_2048, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_2kprv3opreq.req_u.rsa_priv_f3.q, Q_2048, q_2048);

	g_2kprv3opreq.req_u.rsa_priv_f3.dp = kzalloc(dp1_2048, GFP_KERNEL | GFP_DMA);
	g_2kprv3opreq.req_u.rsa_priv_f3.dp_len = dp1_2048;
	pri_2k_dp = pci_map_single(g_fsl_pci_dev->dev, g_2kprv3opreq.req_u.rsa_priv_f3.dp, dp1_2048, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_2kprv3opreq.req_u.rsa_priv_f3.dp, DP1_2048, dp1_2048);

	g_2kprv3opreq.req_u.rsa_priv_f3.dq = kzalloc(dq1_2048, GFP_KERNEL | GFP_DMA);
	g_2kprv3opreq.req_u.rsa_priv_f3.dq_len = dq1_2048;
	pri_2k_dq = pci_map_single(g_fsl_pci_dev->dev, g_2kprv3opreq.req_u.rsa_priv_f3.dq, dq1_2048, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_2kprv3opreq.req_u.rsa_priv_f3.dq, DQ1_2048, dq1_2048);

	g_2kprv3opreq.req_u.rsa_priv_f3.c = kzalloc(c_2048, GFP_KERNEL | GFP_DMA);
	g_2kprv3opreq.req_u.rsa_priv_f3.c_len = c_2048;
	pri_2k_c = pci_map_single(g_fsl_pci_dev->dev, g_2kprv3opreq.req_u.rsa_priv_f3.c, c_2048, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_2kprv3opreq.req_u.rsa_priv_f3.c, C_2048, c_2048);

	g_2kprv3opreq.req_u.rsa_priv_f3.g = kzalloc(n_2048, GFP_KERNEL | GFP_DMA);
	g_2kprv3opreq.req_u.rsa_priv_f3.g_len = n_2048;
	pri_2k_g = pci_map_single(g_fsl_pci_dev->dev, g_2kprv3opreq.req_u.rsa_priv_f3.g, n_2048, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_2kprv3opreq.req_u.rsa_priv_f3.g, N_2048, n_2048);

	g_2kprv3opreq.req_u.rsa_priv_f3.f =
	    kzalloc(n_2048, GFP_KERNEL | GFP_DMA);
	g_2kprv3opreq.req_u.rsa_priv_f3.f_len = n_2048;
#endif
}

void init_4k_rsa_prv3_op_req(void)
{
#ifndef USE_SEC_DIRECT_READ
	g_4kprv3opreq.type = RSA_PRIV_FORM3;

	g_4kprv3opreq.req_u.rsa_priv_f3.p = (uint8_t *) P_4096;
	g_4kprv3opreq.req_u.rsa_priv_f3.p_len = p_4096;

	g_4kprv3opreq.req_u.rsa_priv_f3.q = (uint8_t *) Q_4096;
	g_4kprv3opreq.req_u.rsa_priv_f3.q_len = q_4096;

	g_4kprv3opreq.req_u.rsa_priv_f3.dp = (uint8_t *) DP1_4096;
	g_4kprv3opreq.req_u.rsa_priv_f3.dp_len = dp1_4096;

	g_4kprv3opreq.req_u.rsa_priv_f3.dq = (uint8_t *) DQ1_4096;
	g_4kprv3opreq.req_u.rsa_priv_f3.dq_len = dq1_4096;

	g_4kprv3opreq.req_u.rsa_priv_f3.c = (uint8_t *) C_4096;
	g_4kprv3opreq.req_u.rsa_priv_f3.c_len = c_4096;

	g_4kprv3opreq.req_u.rsa_priv_f3.g = (uint8_t *) N_4096;
	g_4kprv3opreq.req_u.rsa_priv_f3.g_len = n_4096;

	g_4kprv3opreq.req_u.rsa_priv_f3.f =
	    kzalloc(n_4096, GFP_KERNEL | GFP_DMA);
	g_4kprv3opreq.req_u.rsa_priv_f3.f_len = n_4096;
#else
	g_4kprv3opreq.type = RSA_PRIV_FORM3;

	g_4kprv3opreq.req_u.rsa_priv_f3.p = kzalloc(p_4096, GFP_KERNEL | GFP_DMA);
	g_4kprv3opreq.req_u.rsa_priv_f3.p_len = p_4096;
	pri_4k_p = pci_map_single(g_fsl_pci_dev->dev, g_4kprv3opreq.req_u.rsa_priv_f3.p, p_4096, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_4kprv3opreq.req_u.rsa_priv_f3.p, P_4096, p_4096);

	g_4kprv3opreq.req_u.rsa_priv_f3.q = kzalloc(q_4096, GFP_KERNEL | GFP_DMA);
	g_4kprv3opreq.req_u.rsa_priv_f3.q_len = q_4096;
	pri_4k_q = pci_map_single(g_fsl_pci_dev->dev, g_4kprv3opreq.req_u.rsa_priv_f3.q, q_4096, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_4kprv3opreq.req_u.rsa_priv_f3.q, Q_4096, q_4096);

	g_4kprv3opreq.req_u.rsa_priv_f3.dp = kzalloc(dp1_4096, GFP_KERNEL | GFP_DMA);
	g_4kprv3opreq.req_u.rsa_priv_f3.dp_len = dp1_4096;
	pri_4k_dp = pci_map_single(g_fsl_pci_dev->dev, g_4kprv3opreq.req_u.rsa_priv_f3.dp, dp1_4096, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_4kprv3opreq.req_u.rsa_priv_f3.dp, DP1_4096, dp1_4096);

	g_4kprv3opreq.req_u.rsa_priv_f3.dq = kzalloc(dq1_4096, GFP_KERNEL | GFP_DMA);
	g_4kprv3opreq.req_u.rsa_priv_f3.dq_len = dq1_4096;
	pri_4k_dq = pci_map_single(g_fsl_pci_dev->dev, g_4kprv3opreq.req_u.rsa_priv_f3.dq, dq1_4096, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_4kprv3opreq.req_u.rsa_priv_f3.dq, DQ1_4096, dq1_4096);

	g_4kprv3opreq.req_u.rsa_priv_f3.c = kzalloc(c_4096, GFP_KERNEL | GFP_DMA);
	g_4kprv3opreq.req_u.rsa_priv_f3.c_len = c_4096;
	pri_4k_c = pci_map_single(g_fsl_pci_dev->dev, g_4kprv3opreq.req_u.rsa_priv_f3.c, c_4096, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_4kprv3opreq.req_u.rsa_priv_f3.c, C_4096, c_4096);

	g_4kprv3opreq.req_u.rsa_priv_f3.g = kzalloc(n_4096, GFP_KERNEL | GFP_DMA);
	g_4kprv3opreq.req_u.rsa_priv_f3.g_len = n_4096;
	pri_4k_g = pci_map_single(g_fsl_pci_dev->dev, g_4kprv3opreq.req_u.rsa_priv_f3.g, n_4096, PCI_DMA_BIDIRECTIONAL);
	memcpy(g_4kprv3opreq.req_u.rsa_priv_f3.g, N_4096, n_4096);

	g_4kprv3opreq.req_u.rsa_priv_f3.f =
	    kzalloc(n_4096, GFP_KERNEL | GFP_DMA);
	g_4kprv3opreq.req_u.rsa_priv_f3.f_len = n_4096;
#endif
}

void cleanup_rsa_test(void)
{
	if(g_1kpubopreq.req_u.rsa_pub_req.g)
		kfree(g_1kpubopreq.req_u.rsa_pub_req.g);
	if(g_2kpubopreq.req_u.rsa_pub_req.g)
		kfree(g_2kpubopreq.req_u.rsa_pub_req.g);
	if(g_4kpubopreq.req_u.rsa_pub_req.g)
		kfree(g_4kpubopreq.req_u.rsa_pub_req.g);
	if(g_1kprv3opreq.req_u.rsa_priv_f3.f)
		kfree(g_1kprv3opreq.req_u.rsa_priv_f3.f);
	if(g_2kprv3opreq.req_u.rsa_priv_f3.f)
		kfree(g_2kprv3opreq.req_u.rsa_priv_f3.f);
	if(g_4kprv3opreq.req_u.rsa_priv_f3.f)
		kfree(g_4kprv3opreq.req_u.rsa_priv_f3.f);

#ifdef USE_SEC_DIRECT_READ
	pci_unmap_single(g_fsl_pci_dev->dev, pub_1k_n, pub_n_len, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pub_1k_e, ALIGN_LEN_TO_DMA(pub_e_len), PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pub_1k_f, pub_f_len, PCI_DMA_BIDIRECTIONAL);
	kfree(g_1kpubopreq.req_u.rsa_pub_req.n);
	kfree(g_1kpubopreq.req_u.rsa_pub_req.e);
	kfree(g_1kpubopreq.req_u.rsa_pub_req.f);

	pci_unmap_single(g_fsl_pci_dev->dev, pub_2k_n, n_2048, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pub_2k_e, ALIGN_LEN_TO_DMA(e_2048), PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pub_2k_f, f_2048, PCI_DMA_BIDIRECTIONAL);
	kfree(g_2kpubopreq.req_u.rsa_pub_req.n);
	kfree(g_2kpubopreq.req_u.rsa_pub_req.e);
	kfree(g_2kpubopreq.req_u.rsa_pub_req.f);

	pci_unmap_single(g_fsl_pci_dev->dev, pub_4k_n, n_4096, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pub_4k_e, ALIGN_LEN_TO_DMA(e_4096), PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pub_4k_f, f_4096, PCI_DMA_BIDIRECTIONAL);
	kfree(g_4kpubopreq.req_u.rsa_pub_req.n);
	kfree(g_4kpubopreq.req_u.rsa_pub_req.e);
	kfree(g_4kpubopreq.req_u.rsa_pub_req.f);

	pci_unmap_single(g_fsl_pci_dev->dev, pri_1k_p, prv3_p_len, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_1k_q, prv3_q_len, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_1k_dp, prv3_dp_len, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_1k_dq, prv3_dq_len, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_1k_c, prv3_c_len, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_1k_g, prv3_n_len, PCI_DMA_BIDIRECTIONAL);
	kfree(g_1kprv3opreq.req_u.rsa_priv_f3.p);
	kfree(g_1kprv3opreq.req_u.rsa_priv_f3.q);
	kfree(g_1kprv3opreq.req_u.rsa_priv_f3.dp);
	kfree(g_1kprv3opreq.req_u.rsa_priv_f3.dq);
	kfree(g_1kprv3opreq.req_u.rsa_priv_f3.c);
	kfree(g_1kprv3opreq.req_u.rsa_priv_f3.g);

	pci_unmap_single(g_fsl_pci_dev->dev, pri_2k_p, p_2048, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_2k_q, q_2048, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_2k_dp, dp1_2048, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_2k_dq, dq1_2048, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_2k_c, c_2048, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_2k_g, n_2048, PCI_DMA_BIDIRECTIONAL);
	kfree(g_2kprv3opreq.req_u.rsa_priv_f3.p);
	kfree(g_2kprv3opreq.req_u.rsa_priv_f3.q);
	kfree(g_2kprv3opreq.req_u.rsa_priv_f3.dp);
	kfree(g_2kprv3opreq.req_u.rsa_priv_f3.dq);
	kfree(g_2kprv3opreq.req_u.rsa_priv_f3.c);
	kfree(g_2kprv3opreq.req_u.rsa_priv_f3.g);

	pci_unmap_single(g_fsl_pci_dev->dev, pri_4k_p, p_4096, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_4k_q, q_4096, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_4k_dp, dp1_4096, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_4k_dq, dq1_4096, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_4k_c, c_4096, PCI_DMA_BIDIRECTIONAL);
	pci_unmap_single(g_fsl_pci_dev->dev, pri_4k_g, n_4096, PCI_DMA_BIDIRECTIONAL);
	kfree(g_4kprv3opreq.req_u.rsa_priv_f3.p);
	kfree(g_4kprv3opreq.req_u.rsa_priv_f3.q);
	kfree(g_4kprv3opreq.req_u.rsa_priv_f3.dp);
	kfree(g_4kprv3opreq.req_u.rsa_priv_f3.dq);
	kfree(g_4kprv3opreq.req_u.rsa_priv_f3.c);
	kfree(g_4kprv3opreq.req_u.rsa_priv_f3.g);
#endif
}

#ifndef SIMPLE_TEST_ENABLE
static void dec_count(void)
{
#ifndef PERF_TEST
	int32_t d_cnt = 0;
	d_cnt = atomic_inc_return(&rsa_deq_count);

	printk("Deq cnt... :%d\n", d_cnt);
#endif
	atomic_inc(&total_deq_cnt);
}
#endif

void rsa_op_done(struct pkc_request *req, int32_t sec_result)
{
#ifndef SIMPLE_TEST_ENABLE
#ifndef PERF_TEST
	uint32_t i = 0;
#endif

	print_debug("RSA REQ TYPE [%d]\n", req->type);
	if (!sec_result) {
		switch (req->type) {
		case RSA_PRIV_FORM3:
#ifndef PERF_TEST
			for (i = 0; i < req->req_u.rsa_priv_f3.f_len; i++) {
				if (req->req_u.rsa_priv_f3.f[i] !=
				    (uint8_t) PRV3_F_1024[i]) {
					print_error
					    ("Wrong byte [%0x] orig [%0x] index [%d]\n",
					     req->req_u.rsa_priv_f3.f[i],
					     (uint8_t) PRV3_F_1024[i], i);
				}

			}
#endif
			kfree(req->req_u.rsa_priv_f3.f);

			break;
		case RSA_PRIV_FORM2:
#ifndef PERF_TEST
			for (i = 0; i < req->req_u.rsa_priv_f2.f_len; i++) {
				if (req->req_u.rsa_priv_f2.f[i] !=
				    (uint8_t) PRV2_F_1024[i]) {
					print_error
					    ("Wrong byte [%0x] orig [%0x] index [%d]\n",
					     req->req_u.rsa_priv_f2.f[i],
					     (uint8_t) PRV2_F_1024[i], i);
				}
			}
#endif
			kfree(req->req_u.rsa_priv_f2.f);
			break;
		case RSA_PUB:
#ifndef PERF_TEST
			for (i = 0; i < req->req_u.rsa_pub_req.g_len; i++) {
				if (req->req_u.rsa_pub_req.g[i] !=
				    (uint8_t) PUB_G_1024[i]) {
					print_error
					    ("Wrong byte [%0x] orig [%0x] index [%d]\n",
					     req->req_u.rsa_pub_req.g[i],
					     (uint8_t) PUB_G_1024[i], i);
				}
			}
#endif
			kfree(req->req_u.rsa_pub_req.g);
			break;
		default:
			print_error("\ninvalid option\n");
		}
	} else
		print_error
		    ("SEC couldn't process the operation : Error Code : %d\n",
		     sec_result);

	kfree(req);
	dec_count();
#endif
	common_dec_count();
}

int test_rsa_pub_op_1k(void)
{
	if (-1 == test_rsa_op(&g_1kpubopreq, rsa_op_done))
		return -1;

	return 0;
}

int test_rsa_pub_op_2k(void)
{
	if (-1 == test_rsa_op(&g_2kpubopreq, rsa_op_done))
		return -1;

	return 0;
}

int test_rsa_pub_op_4k(void)
{
	if (-1 == test_rsa_op(&g_4kpubopreq, rsa_op_done))
		return -1;

	return 0;
}

int rsa_priv2_op_test(void)
{
	int ret = 0;
	struct pkc_request *req =
	    kzalloc(sizeof(struct pkc_request), GFP_KERNEL);

	req->type = RSA_PRIV_FORM2;

	req->req_u.rsa_priv_f2.p = PRV2_P_1024;
	req->req_u.rsa_priv_f2.p_len = prv2_p_len;

	req->req_u.rsa_priv_f2.q = PRV2_Q_1024;
	req->req_u.rsa_priv_f2.q_len = prv2_q_len;

	req->req_u.rsa_priv_f2.d = PRV2_D_1024;
	req->req_u.rsa_priv_f2.d_len = prv2_d_len;

	req->req_u.rsa_priv_f2.g = PRV2_G_1024;
	req->req_u.rsa_priv_f2.g_len = prv2_g_len;

	req->req_u.rsa_priv_f2.f = kzalloc(prv2_n_len, GFP_KERNEL | GFP_DMA);
	req->req_u.rsa_priv_f2.f_len = prv2_n_len;

	req->req_u.rsa_priv_f2.n_len = prv2_n_len;

	ret = test_rsa_op(req, rsa_op_done);

	if (-1 == ret) {
		kfree(req->req_u.rsa_priv_f2.f);
		kfree(req);
	}
#ifndef PERF_TEST
	else {
		printk("Enq test_rsa_prv2_op : %d\n",
		       atomic_inc_return(&rsa_enq_count));
	}
#endif

	return ret;
}

int test_rsa_priv_op_1k(void)
{
	if (-1 == test_rsa_op(&g_1kprv3opreq, rsa_op_done))
		return -1;

	return 0;
}

int test_rsa_priv_op_2k(void)
{
	if (-1 == test_rsa_op(&g_2kprv3opreq, rsa_op_done))
		return -1;

	return 0;
}

int test_rsa_priv_op_4k(void)
{
	if (-1 == test_rsa_op(&g_4kprv3opreq, rsa_op_done))
		return -1;

	return 0;
}
