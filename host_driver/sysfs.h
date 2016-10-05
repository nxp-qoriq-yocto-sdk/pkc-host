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

#ifndef FSL_PKC_SYSFS_H
#define FSL_PKC_SYSFS_H

#include <linux/version.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>

/** SYSFS RELATED INLINE FUNCTIONS **/
#define NUM_OF_PCI_SYSFS_FILES    PCI_SYS_FILES_END - PCI_SYS_FILES_START - 1
#define NUM_OF_STATS_SYSFS_FILES  STATS_SYS_FILES_END - STATS_SYS_FILES_START - 1
#define NUM_OF_TEST_SYSFS_FILES   TEST_SYS_FILES_END - TEST_SYS_FILES_START - 1

#define MAX_SYSFS_BUFFER		200

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
#define KOBJECT_INIT_AND_ADD(_kobj, _ktype, _parent, _name) {\
					_kobj->ktype = _ktype; \
					_kobj->parent = _parent; \
					kobject_init(_kobj);\
					kobject_set_name(_kobj, _name); \
					kobject_add(_kobj);
}
#else
#define KOBJECT_INIT_AND_ADD(_kobj, _ktype, _parent, _name) \
	ret = kobject_init_and_add(_kobj, _ktype, _parent, _name);
#endif

typedef enum sys_files_id {
	/* Block of enums for files in pci dir */
	PCI_SYS_FILES_START,
	PCI_INFO_SYS_FILE,
	PCI_SYS_FILES_END,

	/* Block of enums for files in stat dir */
	STATS_SYS_FILES_START,
	STATS_REQ_COUNT_SYS_FILE,
	STATS_RESP_COUNT_SYS_FILE,
	STATS_SYS_FILES_END,

	/* Block of enums for files in test dir */
	TEST_SYS_FILES_START,
	TEST_NAME_SYS_FILE,
	TEST_RES_SYS_FILE,
	TEST_PERF_SYS_FILE,
	TEST_REPEAT_SYS_FILE,
	TEST_SYS_FILES_END
} sys_files_id_t;

typedef struct sysfs_file {
	char *name;
	struct k_sysfs_file *file;
	void (*cb) (char *, char *, int);
} sysfs_file_t;

typedef struct dev_sysfs_entries {
	struct sysfs_dir *dev_dir;

	struct sysfs_dir *pci_sub_dir;
	struct sysfs_dir *stats_sub_dir;
	struct sysfs_dir *test_sub_dir;

	sysfs_file_t pci_files[NUM_OF_PCI_SYSFS_FILES];
	sysfs_file_t stats_files[NUM_OF_STATS_SYSFS_FILES];
	sysfs_file_t test_files[NUM_OF_TEST_SYSFS_FILES];
} dev_sysfs_entries_t;

struct k_obj_attribute {
	struct attribute attr;
	 ssize_t(*show) (struct kobject *, struct attribute *attr, char *buf);
	 ssize_t(*store) (struct kobject *, struct attribute *attr,
			  const char *buf, size_t count);
};

#define SYSFS_DIR_NAME_LEN 16
struct sysfs_dir {
	struct kobject kobj;
	uint8_t name[SYSFS_DIR_NAME_LEN];
};

#define K_SYSFS_FILE_NAME_LEN 16
struct k_sysfs_file {
	struct k_obj_attribute attr;
	uint8_t name[K_SYSFS_FILE_NAME_LEN];
	uint8_t str_flag;
	uint8_t buf[MAX_SYSFS_BUFFER];
	uint32_t num;
	size_t buf_len;
	void (*cb) (char *, char *, int);
};
struct c29x_dev;
/* Head of all the sysfs entries */
extern struct sysfs_dir *fsl_sysfs_entries;

/* CALLBACK FUN FOR FW TRIGGER */
extern void set_device(char *, char *, int);
extern void c2x0_test_func(char *fname, char *test_name, int len);

void set_sysfs_value(struct c29x_dev *fsl_pci_dev, sys_files_id_t id,
		     uint8_t *value, size_t len);

int32_t init_sysfs(struct c29x_dev *fsl_pci_dev);
int32_t init_common_sysfs(void);
void sysfs_cleanup(struct c29x_dev *fsl_pci_dev);
void clean_common_sysfs(void);


#endif
