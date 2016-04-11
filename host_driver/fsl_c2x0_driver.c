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
#include "device.h"
#include "fsl_c2x0_driver.h"
#include "fsl_c2x0_crypto_layer.h"
#include "sysfs.h"
#include "command.h"
#include "ioctl.h"
#ifdef VIRTIO_C2X0
#include "crypto_ctx.h"
#include "fsl_c2x0_virtio.h"
#endif
#include "algs.h"
#include "algs_reg.h"
#include "test.h"
#include "dma.h"

static void create_default_config(struct crypto_dev_config *, uint8_t, uint8_t);
/*********************************************************
 *                  MACRO DEFINITIONS                    *
 *********************************************************/
#define DEV_PRINT_DEBUG(...) dev_print_dbg(fsl_pci_dev, ##__VA_ARGS__)

/*********************************************************
 *         INTERNAL FUNCTION PROTOTYPES                  *
 *********************************************************/
static long fsl_cryptodev_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg);

/*********************************************************
 *        GLOBAL VARIABLES                               *
 *********************************************************/
static char *dev_config_file = "/etc/crypto/crypto.cfg";
int napi_poll_count = -1;
/*TODO: Make wt_cpu_mask a real CPU bitmask */
int32_t wt_cpu_mask = -1;

#ifdef VIRTIO_C2X0
struct list_head virtio_c2x0_cmd_list;
struct list_head virtio_c2x0_hash_sess_list;
struct list_head virtio_c2x0_symm_sess_list;
spinlock_t cmd_list_lock;
spinlock_t hash_sess_list_lock;
spinlock_t symm_sess_list_lock;

uint64_t virtio_enq_cnt;
uint64_t virtio_deq_cnt;
#endif

/* FIXME: assigning dev_no to new devices in probe is broken. Since this
 * variable is used to match devices with their configuration, we can end up
 * with incorrect configurations being assigned to multiple devices if we keep
 * removing and adding devices in arbitrary order (e.g using /sys/bus/pci)
 */
static uint32_t dev_no;
int32_t dma_channel_count = 1;
int32_t dma_channel_cpu_mask[NR_CPUS];
int32_t cpu_mask_count;

static struct workqueue_struct *workq;

/* Module Load time parameter */
/* This parameter specifies the file system path of the configuration file .*/
module_param(dev_config_file, charp, S_IRUGO);
MODULE_PARM_DESC(dev_config_file, "Configuration file for the device");

module_param(napi_poll_count, int, S_IRUGO);
MODULE_PARM_DESC(napi_poll_count, "Poll count for NAPI thread");

module_param(wt_cpu_mask, int, S_IRUGO);
MODULE_PARM_DESC(wt_cpu_mask, "CPU mask for napi worker threads");

module_param(dma_channel_count, int, S_IRUGO);
MODULE_PARM_DESC(dma_channel_count, "No of dma chnls to use");

module_param_array(dma_channel_cpu_mask, int, &cpu_mask_count, 0000);
MODULE_PARM_DESC(dma_channel_cpu_mask, "CPU mask for dma chnl alloc");

static struct pci_device_id fsl_crypto_pci_dev_ids[] = {
#ifdef P4080_EP 
	{PCI_DEVICE(FSL_CRYPTO_PCI_VENDOR_ID, FSL_CRYPTO_PCI_DEVICE_ID)},
#elif C293_EP
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
#endif
	{0,},
};

struct c29x_dev *g_fsl_pci_dev;

/*********************************************************
 *        FILE OPERATION STRUCTURE                       *
 *********************************************************/
static const struct file_operations fsl_cryptodev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = fsl_cryptodev_ioctl,
};

static struct miscdevice fsl_cryptodev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "fsl_cryptodev",
	.fops = &fsl_cryptodev_fops,
	.mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
};

/* Head of the PCI devices linked list */
LIST_HEAD(pci_dev_list);

/* Head of the list of configuration data structure instances */
LIST_HEAD(crypto_dev_config_list);

/* Head of the list of per core cpu data structures */
LIST_HEAD(per_core_list_head);

/* Head of all the sysfs entries */
struct sysfs_dir *fsl_sysfs_entries;
void *wt_loop_cnt_sysfs_file;

/* Pointer to the base of per cpu memory */
struct bh_handler __percpu *per_core;

void sysfs_napi_loop_count_set(char *fname, char *count, int len)
{
	uint32_t no = *((uint32_t *) (count));
	printk(KERN_ERR "Count to set... :%d\n", no);
	napi_poll_count = no;
}

/*******************************************************************************
 * Function     : fsl_cryptodev_register
 *
 * Arguments    : None
 *
 * Return Value : int32_t
 *
 * Description  : Registers the fsl_crypto device
 *
 ******************************************************************************/
static int32_t __init fsl_cryptodev_register(void)
{
	int32_t rc;

	rc = misc_register(&fsl_cryptodev);
	if (rc != 0) {
		print_error("registration of /dev/fsl_crypto failed\n");
	}
	return rc;
}

/*******************************************************************************
 * Function     : fsl_cryptodev_deregister
 *
 * Arguments    : None
 *
 * Return Value : None
 *
 * Description  : Unregisters the fsl_crypto device
 *
 ******************************************************************************/
static void fsl_cryptodev_deregister(void)
{
	misc_deregister(&fsl_cryptodev);
}

uint32_t get_no_of_devices(void)
{
	return dev_no;
}

/*******************************************************************************
 * Function     : get_crypto_dev
 *
 * Arguments    : no : Device number
 *
 * Return Value : fsl_crypto_dev_t - Crypto dev instance
 *
 * Description  : Searches the device corresponding to the input argument number
 *                and returns the corresponding crypto dev instance.
 *
 ******************************************************************************/
fsl_crypto_dev_t *get_crypto_dev(uint32_t no)
{
	struct c29x_dev *dev_n_cursor = NULL;
	struct c29x_dev *dev_cursor = NULL;

	list_for_each_entry_safe(dev_cursor, dev_n_cursor, &pci_dev_list, list) {
		print_debug("Input number [%d] Dev cursor dev no [%d]\n", no,
			    dev_cursor->dev_no);

		if (no == dev_cursor->dev_no) {

			print_debug("Found the device\n");
			return dev_cursor->crypto_dev;
		}
	}
	return NULL;
}

/*******************************************************************************
 * Function     : fsl_cryptodev_ioctl
 *
 * Arguments    :
 *
 * Return Value :
 *
 * Description  : ioctl command handler
 *
 ******************************************************************************/
static long fsl_cryptodev_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	print_debug("fsl_cryptodev_ioctl\n");
	print_debug("COMMAND: %u\n", cmd);
	print_debug("CMDOPERATION: %llx\n", (uint64_t)CMDOPERATION);
	switch (cmd) {
	case CMDOPERATION:
		{
#ifdef HIGH_PERF
			return EACCES;
#else
			fsl_crypto_dev_t *c_dev = NULL;
			user_command_args_t usr_cmd_desc = { };

			if (copy_from_user
			    ((void *)&usr_cmd_desc, (void *)arg,
			     sizeof(usr_cmd_desc))) {
				print_error("Copy from user failed....\n");
				return -1;
			}

			c_dev = get_crypto_dev(usr_cmd_desc.dev_id);
			if (NULL == c_dev) {
				print_debug("Invalid device number: %d\n", usr_cmd_desc.dev_id);
				return -1;
			}
			return process_cmd_req(c_dev, &usr_cmd_desc);
#endif
		}
	case CHECKCMD:
		{
#ifdef HIGH_PERF
			return EACCES;
#else
			fsl_crypto_dev_t *c_dev = NULL;
			user_command_args_t usr_cmd_desc = { };
			if (copy_from_user
					((void *)&usr_cmd_desc, (void *)arg,
					sizeof(usr_cmd_desc))) {
				print_error("Copy from user failed....\n");
				return -1;
			}
			c_dev = get_crypto_dev(usr_cmd_desc.dev_id);
			if (NULL == c_dev) {
				print_debug("Invalid device number: %d\n", usr_cmd_desc.dev_id);
				return -1;
			}
			return validate_cmd_args(c_dev, &usr_cmd_desc); 
#endif
		}
#ifdef VIRTIO_C2X0
	case VIRTIOOPERATION:
		{
			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			int ret = 0;

			virtio_job = (struct virtio_c2x0_job_ctx *)
			    kzalloc(sizeof(struct virtio_c2x0_job_ctx),
				    GFP_KERNEL);
			if (!virtio_job) {
				print_error("Alloc failed for virtio_job: %p\n",
						virtio_job);
				return -1;
			}

			qemu_cmd = &(virtio_job->qemu_cmd);

			print_debug("Allocation succeed %p, coping data from user space\n",
					qemu_cmd);
			ret = copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				return -1;
			}

			ret = process_virtio_app_req(virtio_job);
			if (ret < 0) {
				print_error("Virtio Job,op[%d],cmd_index[%d], guest_id[%d] failed with ret %d\n",
				     qemu_cmd->op, qemu_cmd->cmd_index,
				     qemu_cmd->guest_id, ret);
				if (virtio_job->ctx)
					free_crypto_ctx(virtio_job->ctx->
							ctx_pool,
							virtio_job->ctx);
				kfree(virtio_job);
				return ret;
			}
			if (NONBLOCKING == qemu_cmd->block_type) {
				/*  Adding job to pending job list  */
				print_debug("Adding index %u to pending list\n",
						qemu_cmd->cmd_index);
				spin_lock(&cmd_list_lock);
				list_add_tail(&virtio_job->list_entry,
					      &virtio_c2x0_cmd_list);
				spin_unlock(&cmd_list_lock);
			} else if (BLOCKING == qemu_cmd->block_type) {
				/*
				 * Blocking Command finished
				 * Free up virtio job
				 */
				if (virtio_job->ctx)
					free_crypto_ctx(virtio_job->ctx->
							ctx_pool,
							virtio_job->ctx);
				kfree(virtio_job);
			}

			print_debug("VIRTIOIOERATION returninig with ret %d\n", ret);

			return ret;
		}
		break;
	case VIRTIOOPSTATUS:
		{
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			struct virtio_c2x0_job_ctx *next_job = NULL;
			int ret = -1;

			spin_lock(&cmd_list_lock);
			list_for_each_entry_safe(virtio_job, next_job,
						 &virtio_c2x0_cmd_list,
						 list_entry) {

				if (virtio_job->ctx->card_status != -1) {
					switch (virtio_job->qemu_cmd.op) {
					case RSA:{
							switch (virtio_job->
								qemu_cmd.u.pkc.
								pkc_req.type) {
							case RSA_PUB:
								print_debug("RSA_PUB completion\n");
								ret =
								    copy_to_user
								    ((void
								      __user *)
									virtio_job->
								    qemu_cmd.u.
								    pkc.
								    pkc_req.
								    req_u.
								    rsa_pub_req.
								    g,
								    (void *)
								    virtio_job->
								    ctx->req.
								    pkc->req_u.
								    rsa_pub_req.
								    g,
								    virtio_job->
								    ctx->req.
								    pkc->req_u.
								    rsa_pub_req.
								    g_len);
								print_debug("return value for RSA PUB of ouput copy_to_user = %d\n", ret);
								break;
							case RSA_PRIV_FORM1:
							case RSA_PRIV_FORM2:
							case RSA_PRIV_FORM3:
								{
									int i = 0;

									print_debug("RSA_FORM3 completion: Output f_len = %d\n",
											virtio_job->ctx->req.pkc->req_u.rsa_priv_f3.f_len);

									for (i =
									     0;
									     i <
									     virtio_job->
									     ctx->
									     req.
									     pkc->
									     req_u.
									     rsa_priv_f3.
									     f_len;
									     i++) {
										print_debug
										    ("0x%x ",
										     virtio_job->
										     ctx->
										     req.
										     pkc->
										     req_u.
										     rsa_priv_f3.
										     f
										     [i]);
									}

									ret =
									    copy_to_user
									    ((void __user *)
										virtio_job->
										qemu_cmd.u.pkc.pkc_req.
										req_u.rsa_priv_f3.f,
										(void *)virtio_job->ctx->
										req.pkc->req_u.rsa_priv_f3.f,
										virtio_job->ctx->req.pkc->
										req_u.rsa_priv_f3.f_len);

									print_debug("return value for RSA FORM 3 of ouput copy_to_user = %d\n", ret);
									break;
								}
							default:
								break;
							}
							break;
						}
					case DSA:{
							switch (virtio_job->
								qemu_cmd.u.pkc.
								pkc_req.type) {
							case DSA_SIGN:
								{
									ret =
									    copy_to_user
									    ((void __user *)
										virtio_job->qemu_cmd.u.pkc.
										pkc_req.req_u.dsa_sign.c,
										(void *)virtio_job->ctx->req.
										pkc->req_u.dsa_sign.c,
										virtio_job->ctx->req.pkc->
										req_u.dsa_sign.d_len);

									print_debug("return value DSA SIGN 'c' of ouput copy_to_user = %d\n", ret);
									ret =
									    copy_to_user
									    ((void __user *)
										virtio_job->qemu_cmd.u.pkc.
										pkc_req.req_u.dsa_sign.d,
										(void *)virtio_job->ctx->req.
										pkc->req_u.dsa_sign.d,
										virtio_job->ctx->req.pkc->
										req_u.dsa_sign.d_len);
									print_debug
								    ("return value DSA\
									 SIGN 'd' of ouput copy_to_user = %d\n",
									 ret);
								}
								break;
							default:
								break;
							}
							break;
						}
					default:
						{
							print_error("OP NOT handled\n");
							break;
						}
					}
					print_debug("Status from Device : 0x%08x\n", virtio_job->ctx->card_status);
					ret = copy_to_user((void __user *)
							 virtio_job->qemu_cmd.
							 host_status,
							 (void *)&virtio_job->
							 ctx->card_status,
							 sizeof(virtio_job->
								ctx->
								card_status));
					print_debug("return value of status copy_to_user = %d\n", ret);
					/* count++; */
					ret = 0;
					print_debug("Job finished : ret =  %d\n", ret);
					print_debug("VIRTIOOPSTATUS returninig succesfuly\n");

					/* Clean up */
					kfree(virtio_job->ctx);
					list_del(&virtio_job->list_entry);
					kfree(virtio_job);
		    /********************/
				}
			}
			spin_unlock(&cmd_list_lock);
			return ret;
		}
		break;
	case VIRTIOSINGLECMDSTATUS:
		{
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			struct virtio_c2x0_job_ctx *next_job = NULL;
			struct virtio_c2x0_cmd_status *resp = NULL;
			int ret = 0;

			resp = (struct virtio_c2x0_cmd_status *)
			    kzalloc(sizeof(struct virtio_c2x0_cmd_status),
				    GFP_KERNEL);
			if (!resp) {
				print_error("Alloc failed for resp: %p\n", resp);
				return -1;
			}

			ret =
			    copy_from_user(resp,
					   (struct virtio_c2x0_cmd_status *)arg,
					   sizeof(struct
						  virtio_c2x0_cmd_status));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(resp);
				return -1;
			}

			spin_lock(&cmd_list_lock);
			list_for_each_entry_safe(virtio_job, next_job,
						 &virtio_c2x0_cmd_list,
						 list_entry) {
				if ((virtio_job->qemu_cmd.cmd_index ==
				     resp->cmd_index)
				    && (virtio_job->qemu_cmd.guest_id ==
					resp->guest_id)) {

					if (NULL == virtio_job->ctx) {
						print_error("NULL ctx in virtio_job for %d OP, cmd_index %d, %d guest_id",
						     virtio_job->qemu_cmd.op,
						     virtio_job->qemu_cmd.cmd_index,
						     virtio_job->qemu_cmd.guest_id);
						/* No completion to check; Free up the buffers and return success */
						list_del(&virtio_job->
							 list_entry);
						kfree(virtio_job);
						spin_unlock(&cmd_list_lock);
						kfree(resp);
						return 0;
					}
					if (-1 == virtio_job->ctx->card_status) {
						/*
						 * If command is still under process, return immediately
						 */
						spin_unlock(&cmd_list_lock);
						kfree(resp);
						return -1;
					}

					print_debug("Status from Device: 0x%08x\n",
							virtio_job->ctx->card_status);
					resp->status =
					    virtio_job->ctx->card_status;

					ret =
					    copy_to_user((void __user *)arg,
							 (void *)resp,
							 sizeof(struct
								virtio_c2x0_cmd_status));
					if (ret != 0) {
						print_error("Status copytouser=%d for Cmd index[%d],qemuid[%d]\n",
						     ret, resp->cmd_index,
						     resp->guest_id);
						spin_unlock(&cmd_list_lock);
						kfree(resp);
						return -1;
					}

                    /*
                     * Send response of the virtio job
                     * by copying ouputs to VM buffers
                     */
					process_virtio_job_response(virtio_job);

					/* Clean up */
					free_crypto_ctx(virtio_job->ctx->
							ctx_pool,
							virtio_job->ctx);

					list_del(&virtio_job->list_entry);
					kfree(virtio_job);
		    /********************/
					spin_unlock(&cmd_list_lock);
					kfree(resp);
					return ret;
				}
			}

			spin_unlock(&cmd_list_lock);

			print_error("Cmd with index[%d],qemuid[%d] NOT found in list\n",
					resp->cmd_index, resp->guest_id);
			/* No completion to check; Free up the buffers and return success */
			kfree(resp);
			return 0;
		}
		break;
#ifdef HASH_OFFLOAD
	case VIRTIO_HASHCRAINIT:
		{
			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			int ret = 0;

			print_debug("VIRTIO_HASHCRAINIT:\n");
			virtio_job = (struct virtio_c2x0_job_ctx *)
			    kzalloc(sizeof(struct virtio_c2x0_job_ctx),
				    GFP_KERNEL);
			if (!virtio_job) {
				print_error("Alloc failed for virtio_job: %p\n", virtio_job);
				return -1;
			}

			qemu_cmd = &(virtio_job->qemu_cmd);

			print_debug("Allocation succeed %p, coping data from user space %p\n",
					qemu_cmd, (struct virtio_c2x0_qemu_cmd *)arg);
			ret =
			    copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(virtio_job);
				return -1;
			}

			ret = virtio_c2x0_hash_cra_init(virtio_job);
			print_debug("VIRTIO_HASHCRAINIT returning with %d return vallue for id [%lx]\n",
					ret, qemu_cmd->u.hash.init.sess_id);

			kfree(virtio_job);

			if (ret < 0)
				return -1;

			break;
		}

	case VIRTIO_HASHCRAEXIT:
		{
			/* unsigned long sess_id = (unsigned long) arg; */
			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;
			int ret = 0;
			/* struct virtio_c2x0_crypto_sess_ctx *hash_sess = NULL,
				*next_sess = NULL; */

			print_debug("VIRTIO_HASHCRAEXIT:\n");
			qemu_cmd = (struct virtio_c2x0_qemu_cmd *)
			    kzalloc(sizeof(struct virtio_c2x0_qemu_cmd),
				    GFP_KERNEL);
			if (!qemu_cmd) {
				print_error("Alloc failed for qemu_cmd: %p\n",
					    qemu_cmd);
				return -1;
			}
			ret =
			    copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(qemu_cmd);
				return -1;
			}

			ret = virtio_c2x0_hash_cra_exit(qemu_cmd);
			print_debug("VIRTIO_HASHCRAEXIT returning with %d return vallue for id[%lx]\n",
					ret, qemu_cmd->u.hash.exit.sess_id);
#if 0
			/*
			 * Verify if sess_id is still present in list
			 * even after deletion of an entry
			 */
			list_for_each_entry_safe(hash_sess, next_sess,
						 &virtio_c2x0_hash_sess_list,
						 list_entry) {
				if (hash_sess->sess_id ==
				    qemu_cmd->u.hash.exit.sess_id
				    && hash_sess->guest_id ==
				    qemu_cmd->guest_id) {
					print_error("hash sess_id[%x],guest[%d] still in list\n",
					     qemu_cmd->u.hash.exit.sess_id,
					     qemu_cmd->guest_id);
				}
			}
#endif

			kfree(qemu_cmd);

			if (ret < 0)
				return -1;

			break;
		}
#endif
#ifdef SYMMETRIC_OFFLOAD
	case VIRTIO_SYMMCRAINIT:
		{
			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;
			struct virtio_c2x0_job_ctx *virtio_job = NULL;
			int ret = 0;

			print_debug("VIRTIO_SYMMCRAINIT:\n");
			virtio_job = (struct virtio_c2x0_job_ctx *)
			    kzalloc(sizeof(struct virtio_c2x0_job_ctx),
				    GFP_KERNEL);
			if (!virtio_job) {
				print_error("Alloc failed for virtio_job: %p\n", virtio_job);
				return -1;
			}

			qemu_cmd = &(virtio_job->qemu_cmd);

			print_debug("Allocation succeed %p, coping data from user space %p\n",
					qemu_cmd, (struct virtio_c2x0_qemu_cmd *)arg);
			ret = copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(virtio_job);
				return -1;
			}

			ret = virtio_c2x0_symm_cra_init(virtio_job);
			print_debug("VIRTIO_SYMMCRAINIT returninig with %d return vallue for id [%lx]\n",
					ret, qemu_cmd->u.symm.init.sess_id);

			kfree(virtio_job);

			if (ret < 0)
				return -1;

			break;
		}
	case VIRTIO_SYMMCRAEXIT:
		{
			int ret = 0;
			struct virtio_c2x0_qemu_cmd *qemu_cmd = NULL;

			print_debug("VIRTIO_SYMMCRAEXIT:\n");
			qemu_cmd = (struct virtio_c2x0_qemu_cmd *)
			    kzalloc(sizeof(struct virtio_c2x0_qemu_cmd),
				    GFP_KERNEL);
			if (!qemu_cmd) {
				print_error("Alloc failed for qemu_cmd: %p\n",
					    qemu_cmd);
				return -1;
			}
			ret =
			    copy_from_user(qemu_cmd,
					   (struct virtio_c2x0_qemu_cmd *)arg,
					   sizeof(struct virtio_c2x0_qemu_cmd));
			if (ret != 0) {
				print_error("Copy from user failed\n");
				kfree(qemu_cmd);
				return -1;
			}

			ret = virtio_c2x0_symm_cra_exit(qemu_cmd);
			print_debug("VIRTIO_SYMMCRAEXIT returninig with %d return vallue for id [%lx]\n",
					ret, qemu_cmd->u.symm.exit.sess_id);
			kfree(qemu_cmd);
			if (ret < 0)
				return -1;
			break;
		}
#endif

#endif /* VIRTIO_C2X0 : Virtio ioctl operations */

		print_error("DEFAULT IOCTL CALLED\n");
		break;
	}
	return 0;
}

/*******************************************************************************
 * Function     : response_ring_handler
 *
 * Arguments    : work - Kernel work posted to this handler
 *
 * Return Value : none
 *
 * Description  : Bottom half implementation to handle the responses.
 *
 ******************************************************************************/
static void response_ring_handler(struct work_struct *work)
{
	struct bh_handler *bh = container_of(work, struct bh_handler, work);
	fsl_crypto_dev_t *c_dev;

	if (unlikely(NULL == bh)) {
		print_error("No bottom half handler found for the work\n");
		return;
	}

	c_dev = bh->c_dev;	/* get_crypto_dev(1); */
	print_debug("GOT INTERRUPT FROM DEV : %d\n", c_dev->config->dev_no);
#ifdef MULTIPLE_RESP_RINGS
	print_debug("Worker thread invoked on cpu [%d]\n", bh->core_no);
	process_rings(c_dev, &(bh->ring_list_head));
#else
	demux_fw_responses(c_dev);
#endif
	return;
}

/*******************************************************************************
 * Function     : get_dev_config
 *
 * Arguments    : dev : PCI device instance
 *
 * Return Value : config - Config struct corresponding to the device
 *
 * Description  : Returns the configuration corresponding to the device
 *
 ******************************************************************************/

struct crypto_dev_config *get_config(uint32_t dev_no)
{
	struct crypto_dev_config *config = NULL;

	/* Loop for each config to get to the correct config.
	 */
	list_for_each_entry(config, &crypto_dev_config_list, list) {
		print_debug("Config Dev no:%d Arg Dev no: %d\n",
			    config->dev_no, dev_no);

		if (config->dev_no == dev_no)
			return config;

	}

	return NULL;
}

/*******************************************************************************
 * Function     : get_dev_config
 *
 * Arguments    : dev : PCI device instance
 *
 * Return Value : config - Config struct corresponding to the device
 *
 * Description  : Returns the configuration corresponding to the device
 *
 ******************************************************************************/

struct crypto_dev_config *get_dev_config(struct c29x_dev *fsl_pci_dev)
{
	struct crypto_dev_config *config = NULL;

	/* Loop for each config to get to the correct config.
	 */
	list_for_each_entry(config, &crypto_dev_config_list, list) {
		print_debug("Config Dev no:%d Arg Dev no: %d\n",
			    config->dev_no, fsl_pci_dev->dev_no);

		if (config->dev_no == fsl_pci_dev->dev_no)
			return config;

	}

	return NULL;
}

#if 0
static uint64_t readtb(void)
{
	uint32_t tbl = 0, tbh = 0;
	uint64_t tb = 0;

	asm volatile ("mfspr %0, 526" : "=r" (tbl));
	asm volatile ("mfspr %0, 527" : "=r" (tbh));

	tb = ((uint64_t) tbh << 32) | tbl;

	return tb;
}
#endif

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
	isr_ctx_t *isr_ctx = (isr_ctx_t *) data;
	struct bh_handler *instance = NULL;
	fsl_h_rsrc_ring_pair_t *rp = NULL;

	if (unlikely(!isr_ctx)) {
		print_error("[ISR] Null Params.....\n");
		return IRQ_NONE;
	}

	list_for_each_entry((rp), &(isr_ctx->ring_list_head), isr_ctx_list_node) {
		print_debug("Ring is assoc with this intr on core [%d]\n",
			    rp->core_no);
		print_debug("SHEDULING THE WORK ON CORE : %d\n", rp->core_no);
		/* From the core number get the per core info instance */
		instance = per_cpu_ptr(per_core, rp->core_no);
		instance->c_dev = isr_ctx->dev->crypto_dev;

		queue_work_on(rp->core_no, workq, &(instance->work));
	}

	return IRQ_HANDLED;
}

/* release up to bar_max entries allocated in *bar array */
void fsl_free_bar_map(struct pci_bar_info *bar, int bar_max)
{
	int i;

	/* This function makes sense only for CONFIG and SRAM bars */
	bar_max = max(bar_max, MEM_TYPE_DRIVER);

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

	/* We will not be using DMA from RC or DMA from EP.
	 * Hence this memory need not be mapped to DMA. */
	bar->host_dma_addr = 0;
	return 0;

out_free:
	release_mem_region(bar->host_p_addr, bar->len);
	return err;

}

int fsl_get_bar_map(struct c29x_dev *fsl_pci_dev)
{
	int i;
	struct pci_dev *dev = fsl_pci_dev->dev;
	struct pci_bar_info *bars = fsl_pci_dev->bars;
	struct device *my_dev = &fsl_pci_dev->dev->dev;

	/* Get the BAR resources and remap them into the driver memory */
	for (i = 0; i < MEM_TYPE_DRIVER; i++) {
		/* Read the hardware address and length*/
		bars[i].len = pci_resource_len(dev, i);
		bars[i].host_p_addr = pci_resource_start(dev, i);
		if (!bars[i].host_p_addr) {
			dev_err(my_dev, "BAR %d: failed to get physical address\n", i);
			goto error; /* no clean-up required */
		}
		DEV_PRINT_DEBUG("BAR %d: physical address %pa\n", i, &bars[i].host_p_addr);

		if (request_and_map_pci_resource(&bars[i]) != 0)
			goto error;
		DEV_PRINT_DEBUG("BAR %d: virtual address %p, length %pa\n", i,
				bars[i].host_v_addr, &bars[i].len);
	}
	return 0;

error:
	/* request_and_map_pci_resource cleans after itself;
	 * clean-up resources allocated in previous iterations */
	fsl_free_bar_map(bars, i);

	return -ENOMEM;
}

#ifdef MULTIPLE_MSI_SUPPORT
int get_msi_iv_cnt(struct c29x_dev *fsl_pci_dev, uint8_t num_of_vectors)
{
	int err, tmp;
	uint16_t msi_ctrl_word;
	uint32_t mmc_count, mme_count;
	struct device *my_dev = &fsl_pci_dev->dev->dev;

	/* Check whether the device supports multiple MSI interrupts */
	pci_read_config_word(fsl_pci_dev->dev, PCI_MSI_CTRL_REGISTER,
				&msi_ctrl_word);

	/* Check the MMC field to see how many MSIs are supported */
	mmc_count = (msi_ctrl_word & MSI_CTRL_WORD_MMC_MASK) >>
			MSI_CTRL_WORD_MMC_SHIFT;
	mmc_count = 0x01 << mmc_count;

	/* Check the MME field to see how many are actually enabled
	 * by PCI subsystem */
	mme_count = (msi_ctrl_word & MSI_CTRL_WORD_MME_MASK) >>
			MSI_CTRL_WORD_MME_SHIFT;
	mme_count = 0x01 << mme_count;

	DEV_PRINT_DEBUG("MMC count [%d] MME count [%d]\n", mmc_count, mme_count);

	do {
		tmp = num_of_vectors;
		err = pci_enable_msi_block(fsl_pci_dev->dev, num_of_vectors);
		num_of_vectors = err;
	} while (err > 0);

	if (err) {
		dev_err(my_dev, "MSI enable failed!!\n");
		return -ENODEV;
	}

	DEV_PRINT_DEBUG("Number of MSI vectors actually enabled %d\n", tmp);
	fsl_pci_dev->intr_info.intr_vectors_cnt = tmp;

	return 0;
}
#else
int get_msi_iv(struct c29x_dev *fsl_pci_dev)
{
	struct device *my_dev = &fsl_pci_dev->dev->dev;

	if (pci_enable_msi(fsl_pci_dev->dev) != 0) {
		dev_err(my_dev, "MSI enable failed !!\n");
		return -ENODEV;
	}

	fsl_pci_dev->intr_info.intr_vectors_cnt = 1;
	return 0;
}
#endif

/* Get the MSI address and MSI data from the configuration space */
void get_msi_config_data(struct c29x_dev *fsl_pci_dev, isr_ctx_t *isr_context)
{
	struct pci_bar_info *bar = &fsl_pci_dev->bars[MEM_TYPE_MSI];

	pci_read_config_dword(fsl_pci_dev->dev, PCI_MSI_ADDR_LOW,
			&(isr_context->msi_addr_low));
	pci_read_config_dword(fsl_pci_dev->dev, PCI_MSI_ADDR_HIGH,
			&(isr_context->msi_addr_high));
	pci_read_config_word(fsl_pci_dev->dev, PCI_MSI_ADDR_DATA,
			&(isr_context->msi_data));

	DEV_PRINT_DEBUG("MSI addr low [%0X] MSI addr high [%0X] MSI data [%0X]\n",
			isr_context->msi_addr_low, isr_context->msi_addr_high,
			isr_context->msi_data);

	bar->host_p_addr = isr_context->msi_addr_low;
	if (sizeof(phys_addr_t) == sizeof(u64)) {
		bar->host_p_addr |= ((u64) isr_context->msi_addr_high) << 32;
	}

	bar->host_v_addr = (void *) phys_to_virt((unsigned long)bar->host_p_addr);
}

void fsl_release_irqs(struct c29x_dev *fsl_pci_dev)
{
	isr_ctx_t *isr_context, *isr_n_context;

	list_for_each_entry_safe(isr_context, isr_n_context,
			&(fsl_pci_dev->intr_info.isr_ctx_list_head), list) {
		dev_print_dbg(fsl_pci_dev, "Freeing Irq\n");
		free_irq(isr_context->irq, isr_context);
		list_del(&(isr_context->list));
		list_del(&(isr_context->ring_list_head));
		kfree(isr_context);
	}
}

int get_irq_vectors(struct c29x_dev *fsl_pci_dev, uint8_t num_of_rings)
{
	int err;

#ifdef MULTIPLE_MSI_SUPPORT
	err = get_msi_iv_cnt(fsl_pci_dev, num_of_rings);
#else
	err = get_msi_iv(fsl_pci_dev);
#endif

	if (err != 0) {
		pci_disable_msi(fsl_pci_dev->dev);
	}

	return err;
}

int fsl_request_irqs(struct c29x_dev *fsl_pci_dev)
{
	uint16_t i, num_of_vectors;
	uint32_t irq;
	isr_ctx_t *isr_context;
	struct list_head *ctx_list;
	int err;
	struct device *my_dev = &fsl_pci_dev->dev->dev;

	ctx_list = &(fsl_pci_dev->intr_info.isr_ctx_list_head);
	INIT_LIST_HEAD(ctx_list);

	/* this was set-up earlier by get_irq_vectors */
	num_of_vectors = fsl_pci_dev->intr_info.intr_vectors_cnt;
	for (i = 0; i < num_of_vectors; i++) {
		isr_context = kzalloc(sizeof(*isr_context), GFP_KERNEL);
		if (!isr_context) {
			dev_err(my_dev, "Mem alloc failed\n");
			err = -ENOMEM;
			goto free_irqs;
		}

		INIT_LIST_HEAD(&(isr_context->ring_list_head));
		isr_context->dev = fsl_pci_dev;

		irq = fsl_pci_dev->dev->irq + i;

		/* Register the ISR with kernel for each vector */
		err = request_irq(irq, (irq_handler_t) fsl_crypto_isr, 0,
				fsl_pci_dev->dev_name, isr_context);
		if (err) {
			dev_err(my_dev, "Request IRQ failed for vector: %d\n", i);
			kfree(isr_context);
			goto free_irqs;
		}
		isr_context->irq = irq;

		get_msi_config_data(fsl_pci_dev, isr_context);

		/* Add this to the list of ISR contexts */
		list_add(&(isr_context->list), ctx_list);
	}
	return 0;

free_irqs:
	fsl_release_irqs(fsl_pci_dev);
	return err;
}

/*******************************************************************************
 * Function     : create_per_core_info
 *
 * Arguments    : None
 *
 * Return Value : None
 *
 * Description  : Creates per core data structures
 *
 ******************************************************************************/
int32_t create_per_core_info(void)
{
	uint32_t i = 0;
	struct bh_handler *instance;

	per_core = alloc_percpu(struct bh_handler);

	if (unlikely(per_core == NULL)) {
		print_error("Mem allocation failed\n");
		return -1;
	}

	workq = create_workqueue("pkc_wq");
	for_each_online_cpu(i) {
		if (!(wt_cpu_mask & (1 << i)))
			continue;
		instance = per_cpu_ptr(per_core, i);
		INIT_WORK(&(instance->work), response_ring_handler);
		instance->core_no = i;

		INIT_LIST_HEAD(&(instance->ring_list_head));
	}
	return 0;
}

/*******************************************************************************
 * Function     : str_to_int
 *
 * Arguments    : p - String
 *
 * Return Value : None
 *
 * Description  : Converts the string to an integer
 *
 ******************************************************************************/
static uint32_t str_to_int(int8_t *p)
{
	int value = 0;

	while (*p != '\0') {
		value = (value * 10) + (*p - '0');
		p++;
	}
	return value;
}

/*******************************************************************************
 * Function     : get_line
 *
 * Arguments    : file - Configuration file
 *				  pos  - Current read position inside the file
 *				  line - Output buffer to read the line
 *
 * Return Value : int32_t
 *
 * Description  : To get the line from the passed configuration file.
 *
 ******************************************************************************/
static int32_t get_line(struct file *file, loff_t *pos, uint8_t *line,
			int32_t line_size)
{
	char ch = 0;
	uint8_t count = 0;

	line[0] = '\0';
	while (ch != '\n') {
		if (vfs_read(file, &ch, 1, pos) <= 0) {
			return -1;
		}
		if (ch != '\n') {
			line[count++] = ch;
			if (count == line_size)
				return 0;
		}
	}

	line[count] = '\0';
	return 0;
}

/*******************************************************************************
 * Function     : get_label
 *
 * Arguments    : line - Line read from configuration file
 *
 * Return Value : int8_t*
 *
 * Description  : Parses the line to get label
 *
 ******************************************************************************/
int8_t *get_label(int8_t *line)
{
	int8_t *p = line;

	while (*line != '\n' && *line != '\0') {
		if (*line == '<') {
			return line;
		} else if (*line == ':') {
			*line = '\0';
			return p;
		} else {
			line++;
		}
	}

	while (*p == ' ')
		p++;

	return p;
}

/*******************************************************************************
 * Function     :	create_default_config
 *
 * Arguments    :	config - current device config structure
 *			from_ring - from which ring to take default values
 *			max_ring  - maximum number of rings to be created
 *
 * Return Value :	void
 *
 * Description  :	Creates the default device configuration
 *						default values
 *			DEPTH - 16	AFFINITY - 0
 *			PRIORITY - 1	ORDER - 0
 *
 ******************************************************************************/
static void create_default_config(struct crypto_dev_config *config,
				  uint8_t from_ring, uint8_t max_ring)
{
	if (max_ring > FSL_CRYPTO_MAX_RING_PAIRS) {
		max_ring = FSL_CRYPTO_MAX_RING_PAIRS;
	}
	print_debug("Total no of Rings : %d\n", max_ring);
	for (; from_ring < max_ring; ++from_ring) {
		config->ring[from_ring].ring_id = from_ring;
		if (0 == from_ring) {
			config->ring[from_ring].depth = 16;
		} else {
			config->ring[from_ring].depth = 1024;
		}
		/* default values for affinity, priority and order */
		f_set_a(&config->ring[from_ring].flags, 0);
		f_set_p(&config->ring[from_ring].flags, 1);
		f_set_o(&config->ring[from_ring].flags, 0);

		print_debug("Ring [%d] default Depth : %d\n", from_ring,
			    config->ring[from_ring].depth);
		print_debug("Ring [%d] default Affinity : 0\n", from_ring);
		print_debug("Ring [%d] default Priority : 1\n", from_ring);
		print_debug("Ring [%d] default Order : 0\n", from_ring);

	}
	config->num_of_rings = max_ring;
}

/*******************************************************************************
 * Function     : process_label
 *
 * Arguments    : label - Token to identify the value
 *		  value - Actual value
 *
 * Return Value : int32_t
 *
 * Description  : Understands and initialize the config data structure based on
 *		  the passed label and value
 *
 ******************************************************************************/
uint32_t dev_count;
int32_t process_label(int8_t *label, int8_t *value)
{
	int32_t conv_value = 0;
	static struct crypto_dev_config *config;
	static uint32_t rings_spec;
	static uint8_t ring_count;
	static uint32_t ring_start;
	static uint32_t dev_start;

	if (!strcmp(label, "<device>")) {
		/* New device node - allocate memory for new config structure */
		config = kzalloc(sizeof(struct crypto_dev_config), GFP_KERNEL);

		if (unlikely(NULL == config)) {
			print_error("Mem allocation failed\n");
			return -1;
		}

		/* Add this to the existing list */
		list_add(&(config->list), &(crypto_dev_config_list));
		config->dev_no = ++dev_count;

		dev_start = true;
	} else if (!strcmp(label, "firmware")) {
		strncpy(config->fw_file_path, value,
				FIRMWARE_FILE_PATH_LEN - 1);
		config->fw_file_path[FIRMWARE_FILE_PATH_LEN - 1] = '\0';
	} else if (!strcmp(label, "rings")) {
		conv_value = str_to_int(value);
		if (FSL_CRYPTO_MAX_RING_PAIRS < conv_value || 0 > conv_value) {
			conv_value = FSL_CRYPTO_MAX_RING_PAIRS;
		}
		config->num_of_rings = conv_value;
		rings_spec = true;
		/* Default values for all the rings */
		/*create_default_config(config,0,config->num_of_rings); */
	} else if (!strcmp(label, "<ring>") && (dev_start == true)) {
		/* New ring information is starting here */
		ring_start = true;
		if (false == rings_spec) {
			/* Default values for all the rings */
			create_default_config(config, 0, 2);
			return 0;
		}
		if (ring_count >= FSL_CRYPTO_MAX_RING_PAIRS)
			return -1;
		config->ring[ring_count].ring_id = ring_count;
	} else if (!strcmp(label, "depth") && (ring_start == true)) {
		config->ring[ring_count].depth = str_to_int(value);
	} else if (!strcmp(label, "affinity") && (ring_start == true)) {
		conv_value = str_to_int(value);
		f_set_a(&config->ring[ring_count].flags, (uint8_t)conv_value);
	} else if (!strcmp(label, "priority") && (ring_start == true)) {
		conv_value = str_to_int(value);
		if (16 < conv_value) {
			conv_value = 16;
		}
		if (0 >= conv_value) {
			conv_value = 1;
		}
		f_set_p(&config->ring[ring_count].flags, (uint8_t)conv_value);
	} else if (!strcmp(label, "order") && (ring_start == true)) {
		conv_value = str_to_int(value);
		if ( conv_value > 1 || conv_value < 0) {
			conv_value = 0;
		}
		f_set_o(&config->ring[ring_count].flags, (uint8_t)conv_value);
	} else if (!strcmp(label, "<end>")) {
		if (ring_start == true) {
			ring_start = false;
			if (config->ring[ring_count].depth < 16) {
				if (ring_count == 0) {
					config->ring[ring_count].depth = 16;
				} else {
					config->ring[ring_count].depth = 128;
				}
			}
			ring_count++;
		} else if (dev_start == true) {
			/* FIX: IF GIVEN CONFIGURATION FAILS THEN MAKE DEFAULT
			 * CONFIGURATION ENABLED */
			if (1 >= config->num_of_rings) {
				create_default_config(config, 0, 2);
			} else if (ring_count < config->num_of_rings) {
				create_default_config(config, ring_count,
						      config->num_of_rings);
			} else if (ring_count > config->num_of_rings) {
				return -1;
			}
			rings_spec = false;
			dev_start = false;
			ring_count = 0;
			/*dev_count++; */
		}
	} else
		return -1;

	return 0;
}

/*******************************************************************************
 * Function     : parse_config_file
 *
 * Arguments    : config_file - Path of the configuration file
 *
 * Return Value : int32_t
 *
 * Description  : Parses the configuration file and reads the configuration
 *
 ******************************************************************************/
int32_t parse_config_file(int8_t *config_file)
{
	int32_t ret = 0;
	uint8_t line[100];	/* Local buffer to hold the strings in file */

	int8_t *label = NULL;
	int8_t *value = NULL;
	struct file *file = NULL;
	struct inode *inode = NULL;

	loff_t pos = 0;

	mm_segment_t old_fs;

	old_fs = get_fs();

	print_info("Using configuration file: %s\n", dev_config_file);

	set_fs(KERNEL_DS);

	file = filp_open(config_file, O_RDWR, 0);

	if (IS_ERR(file)) {
		print_error("No file at path [%s]\n", config_file);

		set_fs(old_fs);
		return -1;
	}

	inode = file->f_path.dentry->d_inode;

	if (0 > i_size_read(inode->i_mapping->host)) {
		print_error("ERROR:Empty file\n");
		ret = -1;
		goto out;
	}

	while (true) {
		/* This could fail even on the EOF */
		/*if(unlikely(get_line(file,&pos,line))) { */
		if (unlikely(get_line(file, &pos, line, sizeof(line)))) {
			print_debug("Error/End of file reached\n");
			/* Need to know how to distinguish
			 * between EOF and error */
			goto out;
		}

		print_debug("Line read from file [%s]\n", line);

		if (strlen(line)) {
			label = get_label(line);

			value = line + strlen(label) + 1;
			print_debug("Label [%s], value : [%d]\n", label,
				    str_to_int(value));

			if (unlikely(process_label(label, value) == -1)) {
				print_error("Processing label [%s] failed\n",
					    label);
				ret = -1;
				goto out;
			}
		}
	}

out:
	if (file) {
		filp_close(file, 0);
	}

	set_fs(old_fs);

	return ret;
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
static void cleanup_pci_device(struct c29x_dev *dev)
{
	uint32_t i;

	if (NULL == dev)
		return;

	sysfs_cleanup(dev);

	/* Free the BAR related resources */
	for (i = 0; i < MEM_TYPE_DRIVER; i++) {
		if (NULL != dev->bars[i].host_v_addr) {
			dev_print_dbg(dev, "IOunmap\n");
			/* io unmap */
			iounmap(dev->bars[i].host_v_addr);
		}

		if (0 != dev->bars[i].host_p_addr) {
			dev_print_dbg(dev, "Releasing region\n");
			/* Free the resource */
			/* Free the mem region */
			pci_release_region(dev->dev, i);
		}
	}

	if (0 == dev->intr_info.intr_vectors_cnt) {
		dev_print_dbg(dev, "Zero interrupt count");
		goto disable_dev;
	}

	fsl_release_irqs(dev);
	pci_disable_msi(dev->dev);

disable_dev:
	pci_disable_device(dev->dev);
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
	struct bh_handler *cursor = NULL;

	if (per_core == NULL)
		return;

	for_each_online_cpu(i)
	{
		if (!(wt_cpu_mask & (1 << i)))
			continue;

		cursor = per_cpu_ptr(per_core, i);
		if (NULL == cursor)
			return;
	}

	flush_workqueue(workq);
	destroy_workqueue(workq);

	free_percpu(per_core);
}

/*******************************************************************************
 * Function     : cleanup_config_list
 *
 * Arguments    : void
 *
 * Return Value : None
 *
 * Description  : Destroys the configuration list
 *
 ******************************************************************************/
static void cleanup_config_list(void)
{
	struct crypto_dev_config *config = NULL;
	struct crypto_dev_config *next_config = NULL;

	list_for_each_entry_safe(config, next_config, &crypto_dev_config_list,
				 list) {
		list_del(&(config->list));
		kfree(config);
	}
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
	struct c29x_dev *fsl_pci_dev = dev_get_drvdata(&(dev->dev));

	if (unlikely(NULL == fsl_pci_dev)) {
		dev_err(&dev->dev, "No such device\n");
		return;
	}

	stop_device(fsl_pci_dev->crypto_dev);
	/* To do crypto layer related cleanup corresponding to this device */
	cleanup_crypto_device(fsl_pci_dev->crypto_dev);
	/* Cleanup the PCI related resources */
	cleanup_pci_device(fsl_pci_dev);
	/* Delete the device from list */
	list_del(&(fsl_pci_dev->list));

	kfree(fsl_pci_dev);
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
	int local_cfg; /* clean-up is required on error path */
	int8_t pci_info[60];
	int8_t sys_pci_info[100];
	struct c29x_dev *fsl_pci_dev = NULL;
	struct crypto_dev_config *config = NULL;

	print_debug("========== PROBE FUNCTION ==========\n");

	if (!dev) {
		print_error("PCI device with VendorId:%0x DeviceId:%0x is not found\n",
				id->vendor, id->device);
		return err;
	}

	/* Allocate memory for the new PCI device data structure */
	fsl_pci_dev = kzalloc(sizeof(struct c29x_dev), GFP_KERNEL);
	if (!fsl_pci_dev) {
		print_error("Memory allocation failed\n");
		return -ENOMEM;
	}

	/* Set this device instance as private data inside the pci dev struct */
	dev_set_drvdata(&(dev->dev), fsl_pci_dev);

	fsl_pci_dev->dev = dev;
	fsl_pci_dev->id = id;

	/* Starts from 1 */
	fsl_pci_dev->dev_no = ++dev_no;

	snprintf(fsl_pci_dev->dev_name, FSL_PCI_DEV_NAME_MAX_LEN, "%s%d",
		 FSL_PCI_DEV_NAME, dev_no);

	DEV_PRINT_DEBUG("Found C29x Device");

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

	err = fsl_get_bar_map(fsl_pci_dev);
	if (err)
		goto clear_master;

	/* Call to the following function gets the number of
	 * application rings to be created for the device.
	 * The actual number of ring pairs created can be different
	 * and can only be known during the handshake.
	 * This number is the max limit. Number of iv's
	 * to ask = number of application rings.*/

	config = get_dev_config(fsl_pci_dev);
	if (config) {
		local_cfg = 0;
	} else {
		local_cfg = 1;
		/* FIX: IF NO CONFIGURATION IS SPECIFIED THEN
		 * TAKE THE DEFAULT CONFIGURATION */
		print_debug("NO CONFIG FOUND, CREATING DEFAULT CONFIGURATION\n");
		config = kzalloc(sizeof(struct crypto_dev_config), GFP_KERNEL);
		if (!config) {
			print_error("Mem allocation failed\n");
			err = -ENODEV;
			goto free_bar_map;
		}

		list_add(&(config->list), &(crypto_dev_config_list));
		print_debug("===== DEFAULT CONFIGURATION DETAILS ======\n");
		config->dev_no = fsl_pci_dev->dev_no;
		strcpy(config->fw_file_path, FIRMWARE_FILE_DEFAULT_PATH);
		print_debug("Firmware Path : %s\n", config->fw_file_path);
		create_default_config(config, 0, 2);
	}

	err = get_irq_vectors(fsl_pci_dev, config->num_of_rings);
	if (err)
		goto free_config;

	err = fsl_request_irqs(fsl_pci_dev);
	if (err)
		goto disable_msi;

	/* Now create all the SYSFS entries required for this device */
	err = init_sysfs(fsl_pci_dev);
	if (err) {
		print_error("Sysfs init failed !!\n");
		goto free_req_irq;
	}

	/* Add the PCI device to the crypto layer --
	 * This layer adds the device as crypto device.
	 * To have kernel dependencies separate, all the
	 * crypto device related handling will be done
	 * by the crypto layer.
	 */
	fsl_pci_dev->crypto_dev = fsl_crypto_layer_add_device(fsl_pci_dev, config);
	if (!fsl_pci_dev->crypto_dev) {
		dev_err(&dev->dev, "Adding device as crypto dev failed\n");
		err = -ENODEV;
		goto deinit_sysfs;
	}

	/* Updating the information to sysfs entries */
	print_debug("Updating sys info\n");
	snprintf(pci_info, 60, "VendorId:%0x DeviceId:%0x BusNo:%0x\nCAP:PCIe\n",
		 id->device, id->vendor, fsl_pci_dev->dev->bus->number);
	strcpy(sys_pci_info, pci_info);
	strcat(sys_pci_info, "MSI CAP\n");

	set_sysfs_value(fsl_pci_dev, PCI_INFO_SYS_FILE,
			(uint8_t *) sys_pci_info, strlen(sys_pci_info));
	set_sysfs_value(fsl_pci_dev, FIRMWARE_PATH_SYSFILE,
			config->fw_file_path, strlen(config->fw_file_path));
	set_sysfs_value(fsl_pci_dev, FIRMWARE_VERSION_SYSFILE,
			(uint8_t *) "FSL-FW-1.1.0\n", strlen("FSL-FW-1.1.0\n"));

	g_fsl_pci_dev = fsl_pci_dev;

	/* Add this node to the pci device's linked list */
	list_add(&(fsl_pci_dev->list), &pci_dev_list);

	return 0;

deinit_sysfs:
	sysfs_cleanup(fsl_pci_dev);
free_req_irq:
	fsl_release_irqs(fsl_pci_dev);
disable_msi:
	pci_disable_msi(fsl_pci_dev->dev);
free_config:
	if (local_cfg) {
		list_del(&(config->list));
		kfree(config);
	}
free_bar_map:
	fsl_free_bar_map(fsl_pci_dev->bars, MEM_TYPE_DRIVER);
clear_master:
	pci_clear_master(dev);
free_dev:
	dev_err(&dev->dev, "Probe of device [%d] failed\n", fsl_pci_dev->dev_no);
	kfree(fsl_pci_dev);
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

	if (-1 == wt_cpu_mask) {
		print_info("CPU mask for NAPI threads is not specified, using one thread per cpu\n");
		for_each_online_cpu(ret)
			wt_cpu_mask |= 1 << ret;
	} else {
		print_info("CPU mask for NAPI threads is specified, configured value: 0x%x\n",
				wt_cpu_mask);
	}

	if ( -1 == napi_poll_count ) {
		napi_poll_count = 1;
		print_info("NAPI poll count is not specified, using default value: %d\n",
				napi_poll_count);
	} else {
		print_info("NAPI poll count is specified, configured value: %d\n",
				napi_poll_count);
	}

	/* Read the configuration file - Path will be passed as module param */
	ret = parse_config_file(dev_config_file);
	if (ret) {
		print_error("Invalid path/configuration file\n");
		return ret;
	}

	ret = init_common_sysfs();
	if(ret) {
		print_error("Sysfs creation failed\n");
		goto free_config;
	}

	/* Create the per core data structures */
	ret = create_per_core_info();
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

	/* For P4080 RC DMA channels will be used for transfer */
	ret = init_rc_dma();
	if (ret) {
		print_error("ERROR: init_rc_dma\n");
		goto unreg_drv;
	}

	ret = fsl_cryptodev_register();
	if (ret) {
		print_error("ERROR: fsl_cryptodev_register\n");
		goto free_rc_dma;
	}

#ifndef VIRTIO_C2X0
	ret = fsl_algapi_init();
	if (ret) {
		print_error("ERROR: fsl_algapi_init\n");
		goto unreg_cdev;
	}
#endif

	ret = rng_init();
	if (ret) {
		print_error("ERROR: rng_init\n");
		goto free_algapi;
	}

#ifdef VIRTIO_C2X0
	INIT_LIST_HEAD(&virtio_c2x0_cmd_list);
	INIT_LIST_HEAD(&virtio_c2x0_hash_sess_list);
	INIT_LIST_HEAD(&virtio_c2x0_symm_sess_list);
	spin_lock_init(&cmd_list_lock);
	spin_lock_init(&hash_sess_list_lock);
	spin_lock_init(&symm_sess_list_lock);
#else
	/* FIXME: proper clean-up for tests */
	init_all_test();
#endif
	return 0;

free_algapi:
#ifndef VIRTIO_C2X0
	fsl_algapi_exit();
unreg_cdev:
#endif
	fsl_cryptodev_deregister();
free_rc_dma:
	cleanup_rc_dma();
unreg_drv:
	pci_unregister_driver(&fsl_cypto_driver);
free_percore:
	cleanup_percore_list();
free_sysfs:
	clean_common_sysfs();
free_config:
	cleanup_config_list();

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
#ifndef VIRTIO_C2X0
	clean_all_test();
#endif

#ifdef RNG_OFFLOAD 
	rng_exit();
#endif
#ifndef VIRTIO_C2X0
	fsl_algapi_exit();
#endif

#ifdef USE_HOST_DMA
	cleanup_rc_dma();
#endif
	/* Unregister the fsl_crypto device node */
	fsl_cryptodev_deregister();

	/* Clean up all the devices and the resources */
	pci_unregister_driver(&fsl_cypto_driver);

	clean_common_sysfs();

	/* Cleanup the configuration file linked list */
	cleanup_config_list();

	/* Cleanup the per core linked list */
	cleanup_percore_list();

	return;
}

/* Registering Init/Exit function of driver with kernel */
module_init(fsl_crypto_drv_init);
module_exit(fsl_crypto_drv_exit);

MODULE_AUTHOR("FSL");
MODULE_DESCRIPTION("FSL c29x Device driver ");
MODULE_VERSION("Version 1.0.1");
MODULE_LICENSE("Dual BSD/GPL");
