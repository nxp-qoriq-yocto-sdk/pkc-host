#ifndef FSL_PKC_CRYPTO_CTX_H
#define FSL_PKC_CRYPTO_CTX_H

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

#include "algs.h"

#define NUM_OF_CTXS     1024

typedef struct ctx_pool {
	crypto_op_ctx_t mem[NUM_OF_CTXS];
	crypto_op_ctx_t *head;
	spinlock_t ctx_lock;
} ctx_pool_t;

static inline void *get_crypto_ctx(ctx_pool_t *pool)
{
	crypto_op_ctx_t *ctx;

	spin_lock_bh(&pool->ctx_lock);
	ctx = pool->head;
	if (ctx != NULL) {
		pool->head = ctx->next;
	}
	spin_unlock_bh(&pool->ctx_lock);

	return ctx;
}

static inline void free_crypto_ctx(void *id, crypto_op_ctx_t *ctx)
{
	ctx_pool_t *pool = id;

	spin_lock_bh(&pool->ctx_lock);
	memset(ctx, 0, sizeof(crypto_op_ctx_t));
	ctx->next = pool->head;
	pool->head = ctx;
	spin_unlock_bh(&pool->ctx_lock);
}

#else
#error Header file is already included
#endif
