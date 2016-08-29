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

#ifndef FSL_PKC_COMMON_H
#define FSL_PKC_COMMON_H

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/device.h>	/* class_creatre */
#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/highmem.h>
#include <asm/pgalloc.h>
#include <linux/sched.h>
#include <linux/list.h>		/* Kernel Linked List */
#include <linux/percpu.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
/*#include <asm/io.h>*/
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/smp.h>
#include <linux/dmaengine.h>

#include <linux/completion.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/cpumask.h>

/* Identifier for the ring pairs */
typedef enum ring_id {
	CRYPTO_COMMAND_RING_ID,
	CRYPTO_APP_RING_ID,
	/*This ID is not used in driver but the same
	 * enum will be used by firmware*/
	CRYPTO_SEC_RING_ID
} ring_id_t;

/*******************************************************************************
Description :	Contains the configuration read from the file.
Fields      :	dev_no    : Number of the device to which this config applies.
		ring_id   : Identifies the ring Command/App
		flags     : Useful only for App to identify its properties
			0-4 : Priority level 32- priority levels
			5-7 : SEC engine affinity
			8   : Ordered/Un-ordered
		list      : To maintain list of config structures per device
*******************************************************************************/
struct crypto_dev_config {
	uint32_t dev_no;
/*  int8_t      *name;  We may not need this field  */
#define FIRMWARE_FILE_DEFAULT_PATH  "/etc/crypto/pkc-firmware.bin"
#define FIRMWARE_FILE_PATH_LEN  100
	uint8_t fw_file_path[FIRMWARE_FILE_PATH_LEN];

	uint8_t *firmware;

	uint8_t num_of_rings;

/* Safe MAX number of ring pairs -
 * Only required for some static data structures. */
#define FSL_CRYPTO_MAX_RING_PAIRS   6

	struct ring_info {
		ring_id_t ring_id;
		uint32_t depth;
		uint8_t flags;
		uint32_t msi_addr_l;
		uint32_t msi_addr_h;
		uint16_t msi_data;
	} ring[FSL_CRYPTO_MAX_RING_PAIRS];

	struct list_head list;
};

/* Different types of memory between driver and ep */
typedef enum crypto_dev_mem_type {
	MEM_TYPE_CONFIG,
	MEM_TYPE_SRAM,
	MEM_TYPE_DRIVER,
	MEM_TYPE_MSI,
	MEM_TYPE_MAX
} crypto_dev_mem_type_t;

#endif
