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
#include "sysfs.h"
#include "fsl_c2x0_driver.h"

/* Variables holding the names of sysfs entries to be created */
int8_t *dev_sysfs_sub_dirs[5] = { "fw", "pci", "crypto", "stat", "test-i" };

/*int8_t *test_sysfs_sub_dirs[] = {"RSA", "DSA", "ECDSA", "DH", "ECDH"};*/

int8_t *dev_sysfs_file[1] = { "state" };

int8_t *fw_sysfs_file_names[NUM_OF_FW_SYSFS_FILES] = {
	"state", "fw_version", "fw_path", "fw_trigger"
};
int8_t *pci_sysfs_file_names[NUM_OF_PCI_SYSFS_FILES] = { "info" };
int8_t *crypto_sysfs_file_names[NUM_OF_CRYPTO_SYSFS_FILES] = { "info" };

int8_t *stat_sysfs_file_names[NUM_OF_STATS_SYSFS_FILES] = {
	"req_count", "resp_count"
};

int8_t *test_sysfs_file_names[NUM_OF_TEST_SYSFS_FILES] = {
	"test_name", "res", "perf", "repeat"
};

uint8_t dev_sysfs_file_str_flag[1] = { 1 };
uint8_t fw_sysfs_file_str_flag[NUM_OF_FW_SYSFS_FILES] = { 1, 1, 1, 1 };
uint8_t pci_sysfs_file_str_flag[NUM_OF_PCI_SYSFS_FILES] = { 1 };
uint8_t crypto_sysfs_file_str_flag[NUM_OF_CRYPTO_SYSFS_FILES] = { 1 };
uint8_t stat_sysfs_file_str_flag[NUM_OF_STATS_SYSFS_FILES] = { 0, 0 };
uint8_t test_sysfs_file_str_flag[NUM_OF_TEST_SYSFS_FILES] = { 1, 1, 1, 0 };

void *napi_loop_count_file;

ssize_t common_sysfs_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct k_obj_attribute *pci_attr =
	    container_of(attr, struct k_obj_attribute, attr);
	struct k_sysfs_file *sysfs_file =
	    container_of(pci_attr, struct k_sysfs_file, attr);
	size_t buf_len;
	if (sysfs_file->str_flag) {
		sprintf(buf, "%s\n", sysfs_file->buf);
		buf_len = sysfs_file->buf_len;
	} else {
		sprintf(buf, "%u\n", sysfs_file->num);
		buf_len = sizeof(sysfs_file->num);
		buf_len = strlen(buf);
	}

	return buf_len;
}

ssize_t common_sysfs_store(struct kobject *kobj, struct attribute *attr,
				  const char *buf, size_t size)
{
	struct k_obj_attribute *pci_attr =
	    container_of(attr, struct k_obj_attribute, attr);
	struct k_sysfs_file *sysfs_file =
	    container_of(pci_attr, struct k_sysfs_file, attr);

	if (sysfs_file->str_flag) {
		size = min_t(size_t, size, MAX_SYSFS_BUFFER);

		strncpy(sysfs_file->buf, buf, (size - 1));
		sysfs_file->buf[size - 1] = '\0';
		sysfs_file->buf_len = size;
		sysfs_file->cb(sysfs_file->name, sysfs_file->buf,
			       sysfs_file->buf_len);

	} else {
		sysfs_file->num = simple_strtol(buf, NULL, 10);
		sysfs_file->cb(sysfs_file->name,
			       (uint8_t *) (&(sysfs_file->num)), size);
	}

	return size;
}

static const struct sysfs_ops common_sysfs_ops = {
	.show = &common_sysfs_show,
	.store = &common_sysfs_store,
};

static struct kobj_type sysfs_entry_type = {
	.sysfs_ops = &common_sysfs_ops
};

struct k_sysfs_file *create_sysfs_file(int8_t *name, struct sysfs_dir *parent,
		uint8_t str_flag)
{
	int err;
	struct k_sysfs_file *newfile =
	    kzalloc(sizeof(struct k_sysfs_file), GFP_KERNEL);
	if (!newfile)
		return NULL;

	strncpy(newfile->name, name, K_SYSFS_FILE_NAME_LEN - 1);
	newfile->name[K_SYSFS_FILE_NAME_LEN - 1] = '\0';

	sysfs_attr_init(&newfile->attr.attr);
	newfile->str_flag = str_flag;
	newfile->attr.attr.name = newfile->name;
	newfile->attr.attr.mode = S_IRUGO | S_IWUSR;

	err = sysfs_create_file(&(parent->kobj), &(newfile->attr.attr));
	if (err) {
		kfree(newfile);
		return NULL;
	}
	return newfile;
}

struct k_sysfs_file *create_sysfs_file_cb(int8_t *name, struct sysfs_dir *parent,
		uint8_t str_flag, void (*cb) (char *, char *, int))
{
	struct k_sysfs_file *file = create_sysfs_file(name, parent, str_flag);
	if (file) {
		file->cb = cb;
	}
	return file;
}

struct sysfs_dir *create_sysfs_dir(char *name, struct sysfs_dir *parent)
{
	int ret = 0;
	struct sysfs_dir *newdir;

	newdir = kzalloc(sizeof(struct sysfs_dir), GFP_KERNEL);
	if(!newdir)
		return NULL;
	strncpy(newdir->name, name, SYSFS_DIR_NAME_LEN - 1);
	newdir->name[SYSFS_DIR_NAME_LEN - 1] = '\0';

	KOBJECT_INIT_AND_ADD((&(newdir->kobj)), &sysfs_entry_type,
			     ((parent == NULL) ? NULL : &(parent->kobj)),
			     name);

	if (ret) {
		kfree(newdir);
		return NULL;
	}
	return newdir;
}

void delete_sysfs_file(struct k_sysfs_file *file, struct sysfs_dir *parent)
{
	if (file) {
		sysfs_remove_file(&(parent->kobj), &(file->attr.attr));
		kfree(file);
	}
}

void delete_sysfs_dir(struct sysfs_dir *sys_dir)
{
	if (sys_dir) {
		kobject_put(&(sys_dir->kobj));
		kobject_del(&(sys_dir->kobj));
		kfree(sys_dir);
	}
}

void clean_common_sysfs(void)
{
    delete_sysfs_file(napi_loop_count_file, fsl_sysfs_entries);
    delete_sysfs_dir(fsl_sysfs_entries);

    fsl_sysfs_entries = NULL;
}

int32_t init_common_sysfs(void)
{
    /* Create a top level sysfs directory.
     * All the device specific entries will be added under this dir.
     */
    fsl_sysfs_entries = create_sysfs_dir("fsl_crypto", NULL);
    if (unlikely(NULL == fsl_sysfs_entries)) {
        print_error("Sysfs creation failed\n");
        return -1;
    }

    /* Create napi loop count file */
    napi_loop_count_file =
        create_sysfs_file_cb("napi_loop_count", fsl_sysfs_entries, 0,
                sysfs_napi_loop_count_set);
    if(unlikely(NULL ==  napi_loop_count_file)) {
        print_error("napi_loop_count sysfs creation failed \n");
        delete_sysfs_dir(fsl_sysfs_entries);
        return -1;
    }
    return 0;
}

int32_t init_sysfs(struct c29x_dev *fsl_pci_dev)
{
	uint32_t i = 0;

	fsl_pci_dev->sysfs.dev_dir =
	    create_sysfs_dir(fsl_pci_dev->dev_name, fsl_sysfs_entries);

	if (unlikely(NULL == fsl_pci_dev->sysfs.dev_dir)) {
		print_error("SysFS entry %s creation failed\n",
			    fsl_pci_dev->dev_name);
		/* Not treating this as FATAL error */
		return -1;
	}

	/* Now create the FW, PCI, CRYPTO subdirs
	 * inside the main device directory */
	fsl_pci_dev->sysfs.fw_sub_dir =
	    create_sysfs_dir(dev_sysfs_sub_dirs[0], fsl_pci_dev->sysfs.dev_dir);
	fsl_pci_dev->sysfs.pci_sub_dir =
	    create_sysfs_dir(dev_sysfs_sub_dirs[1], fsl_pci_dev->sysfs.dev_dir);
	fsl_pci_dev->sysfs.crypto_sub_dir =
	    create_sysfs_dir(dev_sysfs_sub_dirs[2], fsl_pci_dev->sysfs.dev_dir);
	fsl_pci_dev->sysfs.stats_sub_dir =
	    create_sysfs_dir(dev_sysfs_sub_dirs[3], fsl_pci_dev->sysfs.dev_dir);
#ifndef VIRTIO_C2X0
	fsl_pci_dev->sysfs.test_sub_dir =
	    create_sysfs_dir(dev_sysfs_sub_dirs[4], fsl_pci_dev->sysfs.dev_dir);
#endif

	if (unlikely((NULL == fsl_pci_dev->sysfs.fw_sub_dir)
		     || (NULL == fsl_pci_dev->sysfs.pci_sub_dir)
		     || (NULL == fsl_pci_dev->sysfs.crypto_sub_dir)
		     || (NULL == fsl_pci_dev->sysfs.stats_sub_dir)
#ifndef VIRTIO_C2X0
		     || (NULL == fsl_pci_dev->sysfs.test_sub_dir)
#endif
	    )) {
		print_error("SysFS entry %s creation failed\n",
			    fsl_pci_dev->dev_name);
		return -1;
	}

	/*  For each directory create the files in it */
	/* state - field in the dev directory */
	fsl_pci_dev->sysfs.dev_file.name = dev_sysfs_file[0];
	fsl_pci_dev->sysfs.dev_file.file =
	    create_sysfs_file(fsl_pci_dev->sysfs.dev_file.name,
			      fsl_pci_dev->sysfs.dev_dir,
			      dev_sysfs_file_str_flag[0]);
	if (unlikely(NULL == fsl_pci_dev->sysfs.dev_file.file)) {
		print_error("Dev file creation failed\n");
		return -1;
	}

	/* FW sysfs files */
	for (i = 0; i < NUM_OF_FW_SYSFS_FILES; i++) {
		fsl_pci_dev->sysfs.fw_files[i].name = fw_sysfs_file_names[i];
		fsl_pci_dev->sysfs.fw_files[i].cb = set_device;
		fsl_pci_dev->sysfs.fw_files[i].file =
		    create_sysfs_file(fsl_pci_dev->sysfs.fw_files[i].name,
				      fsl_pci_dev->sysfs.fw_sub_dir,
				      fw_sysfs_file_str_flag[i]);
		/* SET THE CALLBACK FOR FW_TRIGGER */
		fsl_pci_dev->sysfs.fw_files[i].file->cb = set_device;

		if (unlikely(NULL == fsl_pci_dev->sysfs.fw_files[i].file)) {
			print_error("Dev file creation failed\n");
			return -1;
		}
	}

	/* PCI sysfs files */
	for (i = 0; i < NUM_OF_PCI_SYSFS_FILES; i++) {
		fsl_pci_dev->sysfs.pci_files[i].name = pci_sysfs_file_names[i];
		fsl_pci_dev->sysfs.pci_files[i].file =
		    create_sysfs_file(fsl_pci_dev->sysfs.pci_files[i].name,
				      fsl_pci_dev->sysfs.pci_sub_dir,
				      pci_sysfs_file_str_flag[i]);
		if (unlikely(NULL == fsl_pci_dev->sysfs.pci_files[i].file)) {
			print_error("Dev file creation failed\n");
			return -1;
		}
	}

	/* CRYPTO sysfs files */
	for (i = 0; i < NUM_OF_CRYPTO_SYSFS_FILES; i++) {
		fsl_pci_dev->sysfs.crypto_files[i].name =
		    crypto_sysfs_file_names[i];
		fsl_pci_dev->sysfs.crypto_files[i].file =
		    create_sysfs_file(fsl_pci_dev->sysfs.crypto_files[i].name,
				      fsl_pci_dev->sysfs.crypto_sub_dir,
				      crypto_sysfs_file_str_flag[i]);
		if (unlikely(NULL == fsl_pci_dev->sysfs.crypto_files[i].file)) {
			print_error("Dev file creation failed\n");
			return -1;
		}
	}

	/* STATS sysfs file */
	for (i = 0; i < NUM_OF_STATS_SYSFS_FILES; i++) {
		fsl_pci_dev->sysfs.stats_files[i].name =
		    stat_sysfs_file_names[i];
		fsl_pci_dev->sysfs.stats_files[i].file =
		    create_sysfs_file(fsl_pci_dev->sysfs.stats_files[i].name,
				      fsl_pci_dev->sysfs.stats_sub_dir, 0);
		if (unlikely(NULL == fsl_pci_dev->sysfs.stats_files[i].file)) {
			print_error("Dev file creation failed\n");
			return -1;
		}
	}

#ifndef VIRTIO_C2X0
	/* Test sysfs file */
	for (i = 0; i < NUM_OF_TEST_SYSFS_FILES; i++) {
		fsl_pci_dev->sysfs.test_files[i].name =
		    test_sysfs_file_names[i];
		fsl_pci_dev->sysfs.test_files[i].cb = c2x0_test_func;
		fsl_pci_dev->sysfs.test_files[i].file =
		    create_sysfs_file_cb(fsl_pci_dev->sysfs.test_files[i].name,
					 fsl_pci_dev->sysfs.test_sub_dir,
					 test_sysfs_file_str_flag[i],
					 fsl_pci_dev->sysfs.test_files[i].cb);
	}
#endif
	return 0;
}

void sysfs_cleanup(struct c29x_dev *fsl_pci_dev)
{
	uint32_t i = 0;

	for (i = 0; i < NUM_OF_FW_SYSFS_FILES; i++) {
		delete_sysfs_file(fsl_pci_dev->sysfs.fw_files[i].file,
				  fsl_pci_dev->sysfs.fw_sub_dir);
	}

	for (i = 0; i < NUM_OF_PCI_SYSFS_FILES; i++) {
		delete_sysfs_file(fsl_pci_dev->sysfs.pci_files[i].file,
				  fsl_pci_dev->sysfs.pci_sub_dir);
	}

	for (i = 0; i < NUM_OF_CRYPTO_SYSFS_FILES; i++) {
		delete_sysfs_file(fsl_pci_dev->sysfs.crypto_files[i].file,
				  fsl_pci_dev->sysfs.crypto_sub_dir);
	}
	for (i = 0; i < NUM_OF_STATS_SYSFS_FILES; i++) {
		delete_sysfs_file(fsl_pci_dev->sysfs.stats_files[i].file,
				  fsl_pci_dev->sysfs.stats_sub_dir);
	}
	for (i = 0; i < NUM_OF_TEST_SYSFS_FILES; i++) {
		delete_sysfs_file(fsl_pci_dev->sysfs.test_files[i].file,
				  fsl_pci_dev->sysfs.test_sub_dir);
	}

	/* Delete the subdirs */
	delete_sysfs_dir(fsl_pci_dev->sysfs.fw_sub_dir);
	delete_sysfs_dir(fsl_pci_dev->sysfs.pci_sub_dir);
	delete_sysfs_dir(fsl_pci_dev->sysfs.crypto_sub_dir);
	delete_sysfs_dir(fsl_pci_dev->sysfs.stats_sub_dir);
	delete_sysfs_dir(fsl_pci_dev->sysfs.test_sub_dir);

	/* Delete the driver sysfs file */
	delete_sysfs_file(fsl_pci_dev->sysfs.dev_file.file,
			  fsl_pci_dev->sysfs.dev_dir);
	delete_sysfs_dir(fsl_pci_dev->sysfs.dev_dir);
}

struct k_sysfs_file *get_sys_file(struct c29x_dev *fsl_pci_dev, sys_files_id_t id)
{
	struct k_sysfs_file *file;

	if (id > DEVICE_SYS_FILES_START && id < DEVICE_SYS_FILES_END) {
		file = fsl_pci_dev->sysfs.dev_file.file;
	} else if (id > FIRMWARE_SYS_FILES_START && id < FIRMWARE_SYS_FILE_END) {
		id -= FIRMWARE_SYS_FILES_START + 1;
		file = fsl_pci_dev->sysfs.fw_files[id].file;
	} else if (id > PCI_SYS_FILES_START && id < PCI_SYS_FILES_END) {
		id -= PCI_SYS_FILES_START + 1;
		file = fsl_pci_dev->sysfs.pci_files[id].file;
	} else if (id > CRYPTO_SYS_FILES_START && id < CRYPTO_SYS_FILES_END) {
		id -= CRYPTO_SYS_FILES_START + 1;
		file = fsl_pci_dev->sysfs.crypto_files[id].file;
	} else if (id > STATS_SYS_FILES_START && id < STATS_SYS_FILES_END) {
		id -= STATS_SYS_FILES_START + 1;
		file = fsl_pci_dev->sysfs.stats_files[id].file;
	} else if (id > TEST_SYS_FILES_START && id < TEST_SYS_FILES_END) {
		id -= TEST_SYS_FILES_START + 1;
		file = fsl_pci_dev->sysfs.test_files[id].file;
	} else {
		file = NULL; /* this should not be the case */
	}

	return file;
}

void set_sysfs_value(struct c29x_dev *fsl_pci_dev, sys_files_id_t id,
		     uint8_t *value, size_t len)
{
	struct k_sysfs_file *file = get_sys_file(fsl_pci_dev, id);

	if (file->str_flag) {
		memcpy(file->buf, value, len);
	} else {
		file->num = *((uint32_t *) (value));
	}

	file->buf_len = len;
}
