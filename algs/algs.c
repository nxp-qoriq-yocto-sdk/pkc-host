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

#include "common.h"
#include "fsl_c2x0_crypto_layer.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "error.h"

#define MAX_ERROR_STRING 302

fsl_crypto_dev_t *get_device_rr(void)
{
	uint32_t no_of_devices = 0, new_device = 0;
	int device_status = 0, count = 0, cpu = 0;
	per_dev_struct_t *dev_stat = NULL;
	fsl_crypto_dev_t *c_dev = NULL;

    no_of_devices = get_no_of_devices();
    if (0 >= no_of_devices) {
        print_error("No Device configured\n");
        return NULL;
    }

	while (!device_status && count < no_of_devices) {
		new_device =
			((atomic_inc_return(&selected_devices) -
				1) % no_of_devices) + 1;
		c_dev = get_crypto_dev(new_device);
		if (!c_dev) {
			print_error
				("Could not retrieve the device structure.\n");
			return NULL;
		}

		cpu = get_cpu();
		dev_stat = per_cpu_ptr(c_dev->dev_status, cpu);
		put_cpu();

		device_status = atomic_read(&(dev_stat->device_status));
		count++;
	}

	if (!device_status) {
		print_error("No Device is ALIVE\n");
		return NULL;		
	}

	return c_dev;
}

#ifdef DEBUG_DESC
void dump_desc(void *buff, uint32_t desc_size, const uint8_t *func)
{
	uint32_t i;
	/* buff comes usually as a (uint8_t *) and to avoid explicit casts on
	 * all calls we do the cast here */
	uint32_t *desc_buff = buff;

	for (i = 0; i < desc_size; i++) {
		pr_err("DESC: %s: Word %d:\t%08x\n", func, i, ioread32be(&desc_buff[i]));
	}
}
#endif

/* FIXME: this function should not be necessary at all.
 *	In fact it is incorrect since it ignores endianness for 64 bit pointers
 *	used in descriptors and even messes up IMM-ediate byte arrays!
 *	The descriptors should probably be written directly to device memory
 *	in device endianness (big) to avoid memcopy. Either way, we should look
 *	for ways to remove, improve or fix it.
 */
void change_desc_endianness(uint32_t *dev_mem,
			    uint32_t *host_mem, int32_t words)
{
	while (words) {
		iowrite32be(*host_mem, dev_mem);
		dev_mem++;
		host_mem++;
		words--;
	}
}
