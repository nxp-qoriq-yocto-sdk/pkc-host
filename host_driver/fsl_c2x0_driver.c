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

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/cpumask.h>

#include "debug_print.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "test.h"

/*********************************************************
 *                  MACRO DEFINITIONS                    *
 *********************************************************/
#define FSL_CRA_PRIORITY 4000

extern int rsa_op(struct pkc_request *req);
extern int dsa_op(struct pkc_request *req);
extern int dh_op(struct pkc_request *req);

/*********************************************************
 *        GLOBAL VARIABLES                               *
 *********************************************************/
int napi_poll_count = -1;

/* default configuration for all devices */
struct c29x_cfg defcfg = {
	.firmware ="/etc/crypto/pkc-firmware.bin",
	.num_of_rps = FSL_CRYPTO_MAX_RING_PAIRS,
	.ring_depth = 1024,
};

/* FIXME: assigning dev_no to new devices in probe is broken. Since this
 * variable is used to match devices with their configuration, we can end up
 * with incorrect configurations being assigned to multiple devices if we keep
 * removing and adding devices in arbitrary order (e.g using /sys/bus/pci)
 */
static uint32_t dev_no;
static struct workqueue_struct *workq;

module_param(napi_poll_count, int, S_IRUGO);
MODULE_PARM_DESC(napi_poll_count, "Poll count for NAPI thread");

static struct pci_device_id fsl_crypto_pci_dev_ids[] = {
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C290_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C280_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C270_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C291_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C281_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_C271_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD1_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD2_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD3_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD4_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD5_PCI_DEVICE_ID)},
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_TBD6_PCI_DEVICE_ID)},
	{0,},
};

struct c29x_dev *g_fsl_pci_dev;

/* Head of the PCI devices linked list */
LIST_HEAD(pci_dev_list);

/* Head of all the sysfs entries */
struct sysfs_dir *fsl_sysfs_entries;
void *wt_loop_cnt_sysfs_file;

/* Pointer to the base of per cpu memory */
struct bh_handler __percpu *bh_workers;

struct list_head alg_list;
static struct alg_template driver_algs[] = {
	{
	 .name = "pkc(rsa)",
	 .driver_name = "pkc-rsa-fsl",
	 .blocksize = 0,
	 .type = CRYPTO_ALG_TYPE_PKC_RSA,
	 .pkc = {
		   .pkc_op = rsa_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },

	{
	 .name = "pkc(dsa)",
	 .driver_name = "pkc-dsa-fsl",
	 .blocksize = 0,
	 .type = CRYPTO_ALG_TYPE_PKC_DSA,
	 .pkc = {
		   .pkc_op = dsa_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },
	{
	 .name = "pkc(dh)",
	 .driver_name = "pkc-dh-fsl",
	 .type = CRYPTO_ALG_TYPE_PKC_DH,
	 .pkc = {
		   .pkc_op = dh_op,
		   .min_keysize = 512,
		   .max_keysize = 4096,
		   },
	 },
};

int fill_crypto_dev_sess_ctx(struct crypto_dev_sess *ctx, uint32_t op_type)
{
	uint32_t num_of_rps = 0;

	if (dev_no == 0) {
		print_error("No Device configured\n");
		return -1;
	}

	ctx->c_dev = get_crypto_dev(1);
	if (!ctx->c_dev) {
		print_error("Could not retrieve the device structure.\n");
		return -1;
	}

	num_of_rps = ctx->c_dev->config.num_of_rps;
	/* Select the ring in which this job has to be posted. */
	ctx->r_id = atomic_inc_return(&ctx->c_dev->crypto_dev_sess_cnt)
			% num_of_rps;

	print_debug("C dev num of rings [%d] r_id [%d]\n",
		    ctx->c_dev->config.num_of_rps, ctx->r_id);

	return 0;
}

static int pkc_cra_init(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	struct fsl_crypto_alg *fsl_alg =
	    container_of(alg, struct fsl_crypto_alg, crypto_alg);

	struct crypto_dev_sess *ctx = crypto_tfm_ctx(tfm);
	if (-1 == fill_crypto_dev_sess_ctx(ctx, fsl_alg->op_type))
		return -1;

	return 0;
}

static void pkc_cra_exit(struct crypto_tfm *tfm)
{
	/* Nothing to be done */
}

static struct fsl_crypto_alg *fsl_alg_alloc(struct alg_template *template)
{
	struct crypto_alg *alg = NULL;
	struct fsl_crypto_alg *f_alg =
	    kzalloc(sizeof(struct fsl_crypto_alg), GFP_KERNEL);
	if (!f_alg) {
		print_error("failed to allocate fsl_crypto_alg\n");
		return NULL;
	}

	alg = &f_alg->crypto_alg;

	snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s", template->name);
	snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s", template->driver_name);

	alg->cra_module = THIS_MODULE;
	alg->cra_priority = FSL_CRA_PRIORITY;
	alg->cra_blocksize = template->blocksize;
	alg->cra_alignmask = 0;
	alg->cra_ctxsize = sizeof(struct crypto_dev_sess);
	alg->cra_flags = CRYPTO_ALG_ASYNC | template->type;

	switch (template->type) {
	case CRYPTO_ALG_TYPE_PKC_RSA:
	case CRYPTO_ALG_TYPE_PKC_DSA:
	case CRYPTO_ALG_TYPE_PKC_DH:
		alg->cra_init = pkc_cra_init;
		alg->cra_exit = pkc_cra_exit;
		alg->cra_type = &crypto_pkc_type;
		alg->cra_u.pkc = template->pkc;
		f_alg->op_type = ASYMMETRIC;
		break;
	}

	return f_alg;
}

void fsl_algapi_exit(void)
{
	struct fsl_crypto_alg *f_alg, *temp;
	struct crypto_alg *alg = NULL;

	if (!alg_list.next)
		return;

	list_for_each_entry_safe(f_alg, temp, &alg_list, entry) {
		alg = &f_alg->crypto_alg;
		crypto_unregister_alg(alg);
		list_del(&f_alg->entry);
		kfree(f_alg);
	}
}

int32_t fsl_algapi_init(void)
{
	int loop, err;
	char *driver_alg_name;
	struct fsl_crypto_alg *f_alg;

	INIT_LIST_HEAD(&alg_list);

	for (loop = 0; loop < ARRAY_SIZE(driver_algs); loop++) {
		f_alg = fsl_alg_alloc(&driver_algs[loop]);
		if (!f_alg) {
			err = -ENOMEM;
			print_error("%s alg allocation failed\n",
				    driver_algs[loop].driver_name);
			goto out_err;
		}
		print_debug("%s alg allocation successful\n",
				driver_algs[loop].driver_name);

		err = crypto_register_alg(&f_alg->crypto_alg);
		driver_alg_name = f_alg->crypto_alg.cra_driver_name;

		if (err) {
			print_error("%s alg registration failed\n",
				    driver_alg_name);
			kfree(f_alg);
			goto out_err;
		}

		print_debug("%s alg registration successful\n", driver_alg_name);
		list_add_tail(&f_alg->entry, &alg_list);
	}

	return 0;

out_err:
	fsl_algapi_exit();
	return err;
}


struct c29x_dev *get_crypto_dev(uint32_t no)
{
	struct c29x_dev *dev_n_cursor = NULL;
	struct c29x_dev *dev_cursor = NULL;

	list_for_each_entry_safe(dev_cursor, dev_n_cursor, &pci_dev_list, list) {
		print_debug("Input number [%d] Dev cursor dev no [%d]\n", no,
			    dev_cursor->dev_no);

		if (no == dev_cursor->dev_no) {

			print_debug("Found the device\n");
			return dev_cursor;
		}
	}
	return NULL;
}

/*******************************************************************************
 * Function     : fsl_crypto_isr
 *
 * Arguments    : irq : Vector number
 *                dev : Instance of the device which raised this interrupt
 *
 * Return Value : irqreturn_t
 *
 * Description  : ISR implementation
 *
 ******************************************************************************/
static irqreturn_t fsl_crypto_isr(int irq, void *data)
{
	struct isr_ctx *isr_ctx = data;
	struct bh_handler *bh_worker;

	if (unlikely(isr_ctx == NULL)) {
		print_error("[ISR] Null Params.....\n");
		return IRQ_NONE;
	}

	bh_worker = per_cpu_ptr(bh_workers, isr_ctx->core_no);
	queue_work_on(isr_ctx->core_no, workq, &(bh_worker->work));

	return IRQ_HANDLED;
}

/* release up to bar_max entries allocated in *bar array */
void fsl_free_bar_map(struct pci_bar_info *bar, int bar_max)
{
	int i;

	for (i = 0; i < bar_max; i++) {
		iounmap(bar->host_v_addr);
		release_mem_region(bar->host_p_addr, bar->len);
		bar++;
	}
}

int request_and_map_pci_resource(struct pci_bar_info *bar)
{
	int err = -ENOMEM;

	/* Request resource region */
	if (!request_mem_region(bar->host_p_addr, bar->len, "FSL-CRYPTO")) {
		print_error("BAR: Request mem region failed\n");
		return err;
	}

	/* Map the MEM to the kernel address space */
	bar->host_v_addr = ioremap(bar->host_p_addr, (unsigned long)bar->len);
	if (!bar->host_v_addr) {
		print_error("BAR: Mapping to kernel address failed\n");
		goto out_free;
	}

	return 0;

out_free:
	release_mem_region(bar->host_p_addr, bar->len);
	return err;

}

int fsl_get_bar_map(struct c29x_dev *c_dev)
{
	int i;
	struct pci_dev *dev = c_dev->dev;
	struct pci_bar_info *bars = c_dev->bars;
	struct device *my_dev = &c_dev->dev->dev;

	/* Get the BAR resources and remap them into the driver memory */
	for (i = 0; i < MEM_TYPE_MAX; i++) {
		/* Read the hardware address and length*/
		bars[i].len = pci_resource_len(dev, i);
		bars[i].host_p_addr = pci_resource_start(dev, i);
		if (!bars[i].host_p_addr) {
			dev_err(my_dev, "BAR %d: failed to get physical address\n", i);
			goto error; /* no clean-up required */
		}
		print_debug("BAR %d: physical address %pa\n", i, &bars[i].host_p_addr);

		if (request_and_map_pci_resource(&bars[i]) != 0)
			goto error;
		print_debug("BAR %d: virtual address %p, length %pa\n", i,
				bars[i].host_v_addr, &bars[i].len);
	}
	return 0;

error:
	/* request_and_map_pci_resource cleans after itself;
	 * clean-up resources allocated in previous iterations */
	fsl_free_bar_map(bars, i);

	return -ENOMEM;
}

void fsl_release_irqs(struct c29x_dev *c_dev, uint32_t maxvec)
{
	uint32_t i;
	isr_ctx_t *isr_ctx;

	for (i = 0; i < maxvec; i++) {
		isr_ctx = &(c_dev->isr_ctx[i]);
		irq_set_affinity_hint(isr_ctx->irq, NULL);
		free_irq(isr_ctx->irq, isr_ctx);
	}
}

int32_t get_irq_vectors(struct c29x_dev *c_dev)
{
	int32_t nvec;
	int8_t maxvec = c_dev->config.num_of_rps;
	struct device *my_dev = &c_dev->dev->dev;

	print_debug("MSI available vectors: %d\n", pci_msi_vec_count(c_dev->dev));
	print_debug("MSI requested vectors: %d\n", maxvec);

	nvec = pci_enable_msi_range(c_dev->dev, 1, maxvec);
	if (nvec < 0) {
		dev_err(my_dev, "MSI enable failed !!\n");
		return -ENODEV;
	}
	c_dev->intr_vectors_cnt = nvec;
	print_debug("MSI enabled vectors  : %d\n", nvec);

	/* We assume one ring - one interrupt - one core.
	 * If we don't have enough interrupts for our rings, then we can't know
	 * which ring has jobs returned from SEC: we can only do a linear
	 * scan of the rings to see which one should be enqueued to bottom half
	 *
	 * This might not be as bad as it sounds for the IRS code but is not
	 * exactly the intended use-case either.
	 */
	if (nvec < c_dev->config.num_of_rps) {
		c_dev->config.num_of_rps = nvec;
	}
	return 0;
}

int fsl_request_irqs(struct c29x_dev *c_dev)
{
	uint32_t i;
	uint32_t num_of_vectors;
	isr_ctx_t *isr_ctx;
	int err;
	struct device *my_dev = &c_dev->dev->dev;

	num_of_vectors = c_dev->intr_vectors_cnt;
	for (i = 0; i < num_of_vectors; i++) {
		isr_ctx = &(c_dev->isr_ctx[i]);
		isr_ctx->core_no = i;
		isr_ctx->irq = c_dev->dev->irq + i;
		cpumask_set_cpu(i, &isr_ctx->affinity_mask);

		err = request_irq(isr_ctx->irq, fsl_crypto_isr, 0,
				c_dev->dev_name, isr_ctx);
		/* IRQ affinity setting should work with kernels after
		 * v3.19-rc5-1-ge2e64a9 */
		irq_set_affinity_hint(isr_ctx->irq, &isr_ctx->affinity_mask);

		if (err) {
			dev_err(my_dev, "Request IRQ failed for vector: %d\n", i);
			goto free_irqs;
		}

		pci_read_config_dword(c_dev->dev, PCI_MSI_ADDR_LOW,
				&(isr_ctx->msi_addr_low));
		pci_read_config_dword(c_dev->dev, PCI_MSI_ADDR_HIGH,
				&(isr_ctx->msi_addr_high));
		pci_read_config_word(c_dev->dev, PCI_MSI_ADDR_DATA,
				&(isr_ctx->msi_data));
		isr_ctx->msi_data += i;

		print_debug("MSI addr low  [%0X]\n", isr_ctx->msi_addr_low);
		print_debug("MSI addr high [%0X]\n", isr_ctx->msi_addr_high);
		print_debug("MSI data      [%0X]\n", isr_ctx->msi_data);
	}
	return 0;

free_irqs:
	fsl_release_irqs(c_dev, i);
	return err;
}

int32_t create_c29x_workqueue(void)
{
	uint32_t i = 0;
	struct bh_handler *bh_worker;

	bh_workers = alloc_percpu(struct bh_handler);

	if (unlikely(bh_workers == NULL)) {
		print_error("Mem allocation failed\n");
		return -1;
	}

	workq = create_workqueue("pkc_wq");
	for_each_online_cpu(i) {
		bh_worker = per_cpu_ptr(bh_workers, i);
		INIT_WORK(&(bh_worker->work), process_work);
	}
	return 0;
}

/*******************************************************************************
 * Function     : cleanup_pci_device
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Does the PCI related cleanup of a device
 *
 ******************************************************************************/
static void cleanup_pci_device(struct c29x_dev *c_dev)
{
	uint32_t i;

	if (NULL == c_dev)
		return;

	sysfs_cleanup(c_dev);

	/* Free the BAR related resources */
	for (i = 0; i < MEM_TYPE_MAX; i++) {
		if (NULL != c_dev->bars[i].host_v_addr) {
			print_debug("IOunmap\n");
			/* io unmap */
			iounmap(c_dev->bars[i].host_v_addr);
		}

		if (0 != c_dev->bars[i].host_p_addr) {
			print_debug("Releasing region\n");
			/* Free the resource */
			/* Free the mem region */
			pci_release_region(c_dev->dev, i);
		}
	}

	if (c_dev->intr_vectors_cnt == 0) {
		print_debug("Zero interrupt count");
		goto disable_dev;
	}

	fsl_release_irqs(c_dev, c_dev->intr_vectors_cnt);
	pci_disable_msi(c_dev->dev);

disable_dev:
	pci_disable_device(c_dev->dev);
}

/*******************************************************************************
 * Function     : cleanup_percore_list
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Destroys the per core information
 *
 ******************************************************************************/
static void cleanup_percore_list(void)
{
	uint32_t i = 0;
	struct bh_handler *bh_worker;

	if (bh_workers == NULL)
		return;

	for_each_online_cpu(i)
	{
		bh_worker = per_cpu_ptr(bh_workers, i);
		if (bh_worker == NULL) 
			return;
	}

	flush_workqueue(workq);
	destroy_workqueue(workq);

	free_percpu(bh_workers);
}

/*******************************************************************************
 * Function     : fsl_crypto_pci_remove
 *
 * Arguments    : dev : PCI device structure instance.
 * Return Value : void
 * Description  : Handles the PCI removal of the device.
 *
 ******************************************************************************/
static void fsl_crypto_pci_remove(struct pci_dev *dev)
{
	struct c29x_dev *c_dev = dev_get_drvdata(&(dev->dev));

	if (unlikely(NULL == c_dev)) {
		dev_err(&dev->dev, "No such device\n");
		return;
	}

	stop_device(c_dev);
	/* To do crypto layer related cleanup corresponding to this device */
	cleanup_crypto_device(c_dev);
	/* Cleanup the PCI related resources */
	cleanup_pci_device(c_dev);
	/* Delete the device from list */
	list_del(&(c_dev->list));

	kfree(c_dev);
	dev_no--;
}

/*******************************************************************************
 * Function     : fsl_crypto_pci_probe
 *
 * Arguments    : dev : PCI device structure instance.
 * 		  id  : Id of the PCI device.
 *
 * Return Value : int32_t
 *
 * Description  : Handles the PCI probe of the device.
 *
 ******************************************************************************/
static int32_t fsl_crypto_pci_probe(struct pci_dev *dev,
				    const struct pci_device_id *id)
{
	int32_t err = -ENODEV;
	int8_t pci_info[60];
	int8_t sys_pci_info[100];
	struct c29x_dev *c_dev = NULL;

	print_debug("========== PROBE FUNCTION ==========\n");

	if (!dev) {
		print_error("PCI device with VendorId:%0x DeviceId:%0x is not found\n",
				id->vendor, id->device);
		return err;
	}

	/* Allocate memory for the new PCI device data structure */
	c_dev = kzalloc(sizeof(struct c29x_dev), GFP_KERNEL);
	if (!c_dev) {
		print_error("Memory allocation failed\n");
		return -ENOMEM;
	}
	c_dev->config = defcfg;
	/* sanity checks to avoid arrays overflow */
	if (c_dev->config.num_of_rps > FSL_CRYPTO_MAX_RING_PAIRS) {
		c_dev->config.num_of_rps = FSL_CRYPTO_MAX_RING_PAIRS;
	}
	if (c_dev->config.num_of_rps > num_online_cpus()) {
		c_dev->config.num_of_rps = num_online_cpus();
	}

	/* Set this device instance as private data inside the pci dev struct */
	dev_set_drvdata(&(dev->dev), c_dev);

	c_dev->dev = dev;
	c_dev->id = id;

	/* Starts from 1 */
	c_dev->dev_no = ++dev_no;

	snprintf(c_dev->dev_name, FSL_PCI_DEV_NAME_MAX_LEN, "%s%d",
		 FSL_PCI_DEV_NAME, dev_no);

	print_debug("Found C29x Device");

	/* Set the DMA mask for the device. This helps the PCI subsystem
	 * for proper dma mappings */
#ifdef SEC_ENGINE_DMA_36BIT
	pci_set_dma_mask(dev, DMA_36BIT_MASK);
#else
	pci_set_dma_mask(dev, DMA_32BIT_MASK);
#endif

	if (!pci_find_capability(dev, PCI_CAP_ID_EXP)) {
		dev_err(&dev->dev, "Does not have PCIe cap\n");
		goto free_dev;
	}

	if (!pci_find_capability(dev, PCI_CAP_ID_MSI)) {
		dev_err(&dev->dev, "Does not support MSI\n");
		goto free_dev;
	}

	/* Wake up the device if it is in suspended state */
	err = pci_enable_device(dev);
	if (err) {
		dev_err(&dev->dev, "Enable Device failed\n");
		goto free_dev;
	}

	/* Set bus master */
	pci_set_master(dev);

	err = fsl_get_bar_map(c_dev);
	if (err)
		goto clear_master;

	err = get_irq_vectors(c_dev);
	if (err)
		goto free_bar_map;

	err = fsl_request_irqs(c_dev);
	if (err)
		goto disable_msi;

	/* Now create all the SYSFS entries required for this device */
	err = init_sysfs(c_dev);
	if (err) {
		print_error("Sysfs init failed !!\n");
		goto free_req_irq;
	}

	err = fsl_crypto_layer_add_device(c_dev);
	if (err != 0) {
		dev_err(&dev->dev, "Adding device as crypto dev failed\n");
		goto deinit_sysfs;
	}

	/* Updating the information to sysfs entries */
	print_debug("Updating sys info\n");
	snprintf(pci_info, 60, "VendorId:%0x DeviceId:%0x BusNo:%0x\nCAP:PCIe\n",
		 id->device, id->vendor, c_dev->dev->bus->number);
	strcpy(sys_pci_info, pci_info);
	strcat(sys_pci_info, "MSI CAP\n");

	set_sysfs_value(c_dev, PCI_INFO_SYS_FILE,
			(uint8_t *) sys_pci_info, strlen(sys_pci_info));

	/* TODO: remove global variable that references the device. It assumes
	 * a single board is installed in the system. Currently it is used with
	 * the tests but we may want to support more than a single board on the
	 * same system and referencing only one driver through this variable
	 * will not work for multiple boards */
	g_fsl_pci_dev = c_dev;

	/* Add this node to the pci device's linked list */
	list_add(&(c_dev->list), &pci_dev_list);

	return 0;

deinit_sysfs:
	sysfs_cleanup(c_dev);
free_req_irq:
	fsl_release_irqs(c_dev, c_dev->intr_vectors_cnt);
disable_msi:
	pci_disable_msi(c_dev->dev);
free_bar_map:
	fsl_free_bar_map(c_dev->bars, MEM_TYPE_MAX);
clear_master:
	pci_clear_master(dev);
free_dev:
	dev_err(&dev->dev, "Probe of device [%d] failed\n", c_dev->dev_no);
	kfree(c_dev);
	dev_no--; /* don't count this device as usable */

	return err;
}

static struct pci_driver fsl_cypto_driver = {
	.name = "FSL-Crypto-Driver",
	.id_table = fsl_crypto_pci_dev_ids,
	.probe = fsl_crypto_pci_probe,
	.remove = fsl_crypto_pci_remove,
};

/*******************************************************************************
 * Function     : fsl_drv_init
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Module initialization function. Init all the resources.
 *
 ******************************************************************************/
static int32_t __init fsl_crypto_drv_init(void)
{
	int32_t ret = 0;

	if ( -1 == napi_poll_count ) {
		napi_poll_count = 1;
		print_info("NAPI poll count is not specified, using default value: %d\n",
				napi_poll_count);
	} else {
		print_info("NAPI poll count is specified, configured value: %d\n",
				napi_poll_count);
	}

	ret = init_common_sysfs();
	if(ret) {
		print_error("Sysfs creation failed\n");
		goto free_config;
	}

	/* Create the per core data structures */
	ret = create_c29x_workqueue();
	if (ret) {
		print_error("Per cpu alloc failed\n");
		goto free_sysfs;
	}

	/* Register the PCIe driver for the device,
	 * The register function will return success if the
	 * device is not present, hence an additional check
	 * to see whether device list is initialized
	 * or not.
	 */
	ret = pci_register_driver(&fsl_cypto_driver);
	if (ret < 0) {
		print_error("ERROR: pci_register_driver \n");
		goto free_percore;
	}

	/* If there is no device detected -- goto error */
	if (!dev_no) {
		ret = -ENODEV;
		print_error("NO DEVICE FOUND...\n");
		goto unreg_drv;
	}

	ret = fsl_algapi_init();
	if (ret) {
		print_error("ERROR: fsl_algapi_init\n");
		goto unreg_drv;
	}

	/* FIXME: proper clean-up for tests */
	init_all_test();

	return 0;

unreg_drv:
	pci_unregister_driver(&fsl_cypto_driver);
free_percore:
	cleanup_percore_list();
free_sysfs:
	clean_common_sysfs();
free_config:

	return ret;
}

/*******************************************************************************
 * Function     : fsl_drv_exit
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Cleanup function. Destroys all the resources.
 *
 ******************************************************************************/
static void __exit fsl_crypto_drv_exit(void)
{
	clean_all_test();

	fsl_algapi_exit();

	/* Clean up all the devices and the resources */
	pci_unregister_driver(&fsl_cypto_driver);

	clean_common_sysfs();

	/* Cleanup the per core linked list */
	cleanup_percore_list();

	return;
}

/* Registering Init/Exit function of driver with kernel */
module_init(fsl_crypto_drv_init);
module_exit(fsl_crypto_drv_exit);

MODULE_AUTHOR("FSL");
MODULE_DESCRIPTION("FSL c29x Device driver ");
MODULE_LICENSE("Dual BSD/GPL");
