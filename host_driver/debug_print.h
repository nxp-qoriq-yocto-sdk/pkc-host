/* Copyright 2016 Freescale Semiconductor, Inc.
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

#ifndef FSL_PKC_DEBUG_PRINT_H
#define FSL_PKC_DEBUG_PRINT_H

#ifdef PRINT_DEBUG
#define print_debug(msg, ...) \
pr_err("FSL-CRYPTO-DRV [%s:%d] DEBUG:\t" msg, __func__, __LINE__, ##__VA_ARGS__)
#else
#define print_debug(msg, ...)
#endif

#ifdef PRINT_INFO
#define print_info(msg, ...) \
pr_info("FSL-CRYPTO-DRV [%s:%d] INFO:\t" msg, __func__, __LINE__, ##__VA_ARGS__)
#else
#define print_info(msg, ...)
#endif

#ifdef DEV_PRINT_DBG
#define dev_print_dbg(fdev, msg, ...) {	\
dev_err(&(fdev->dev->dev), "[%s:%d] Devcnt:%d, DevId:0x%x, VendorId:0x%x, Bus:%d\n", \
	__func__, __LINE__, fdev->dev_no, fdev->id->device, fdev->id->vendor, \
	fdev->dev->bus->number); \
dev_err(&(fdev->dev->dev), msg, ##__VA_ARGS__);\
}
#else
#define dev_print_dbg(fdev, msg, ...)
#endif

#define print_error(msg, ...) \
pr_err("FSL-CRYPTO-DRV [%s:%d] ERROR:\t" msg, __func__, __LINE__, ##__VA_ARGS__)

#endif