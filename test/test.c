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

#include "common.h"
#include "fsl_c2x0_driver.h"
#include "algs.h"
#include "test.h"

#define MAX_TEST_THREAD_SUPPORT 200
#define TEST_NAME_LENGTH 100

static char g_test_name[TEST_NAME_LENGTH];
static struct task_struct *task[MAX_TEST_THREAD_SUPPORT];
static int32_t no_thread;
static int32_t g_is_test_in_progress;

static uint64_t s_time;
static uint64_t e_time;

static uint32_t exit;
static uint32_t newtest;

atomic_t total_enq_cnt;
atomic_t total_deq_cnt;
static atomic_t total_err_cnt;

static atomic_t hold_off;
static atomic_t test_done;
static atomic_t timer_started;
static atomic_t flag;

static uint32_t total_succ_jobs;
static uint32_t total_enq_req;

static int32_t timer_set;
static int time_duration;

static int (*testfunc) (void);
static int threads_per_cpu;
static int cpu_mask;
static struct timer_list test_timer;

#ifdef CONFIG_PPC
inline uint64_t get_cpu_ticks(void)
{
	uint32_t l = 0, h = 0;

	asm volatile ("mfspr %0, 526" : "=r" (l));
	asm volatile ("mfspr %0, 527" : "=r" (h));

	return ((uint64_t) h << 32) | l;
}
#else
inline uint64_t get_cpu_ticks(void)
{
	uint32_t h = 0, l = 0;
	__asm__ __volatile__("rdtsc" : "=a"(l), "=d"(h));
	return ((uint64_t) h << 32) | l;
}
#endif

inline void check_test_done(void)
{
	if (!newtest)
		return;

	print_debug("No of job successfully finished: %d\n", total_succ_jobs);
	newtest = 0;
	atomic_set(&hold_off, 1);
	print_debug("Set hold_off\n");
	testfunc = NULL;
	no_thread = 0;
	while (atomic_read(&total_deq_cnt) != atomic_read(&total_enq_cnt)) {
		print_debug("Enq is not equal to deq\n");
		print_debug("Total enq: %d, Total deq: %d\n",
				atomic_read(&total_enq_cnt),
				atomic_read(&total_deq_cnt));
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
	exit = 1;
	if (timer_set) {
		del_timer(&test_timer);
	}
	timer_set = 0;
	print_debug("Total enq: %d, Total deq: %d\n",
		atomic_read(&total_enq_cnt), atomic_read(&total_deq_cnt));
	print_debug("s_time: %llx, e_time: %llx\n", s_time, e_time);
	print_debug("*** Test Complete ***\n");

	{
	uint8_t sysfs_val[30];
	uint8_t cycle_diff_s[16];
	uint8_t cpu_freq_s[10];
	uint64_t cycle_diff = e_time - s_time;
	uint32_t cpu_freq;

#ifdef CONFIG_PPC
	cpu_freq = ppc_proc_freq / 1000000;
#else
	cpu_freq = cpu_khz / 1000;
#endif
	print_debug("Cpu Freq: %d\n", cpu_freq);
	snprintf(cpu_freq_s, sizeof(cpu_freq_s), "%d", cpu_freq);
	print_debug("Cpu Freq_s: %s\n", cpu_freq_s);
	print_debug("Diff: %llx\n", cycle_diff);
	print_debug("total_jobs_s: %0x\n", total_succ_jobs);
	/* Write to the sysfs file entry */

	snprintf(cycle_diff_s, sizeof(cycle_diff_s), "%0llx", cycle_diff);
	print_debug("cycle_diff_s: %s\n", cycle_diff_s);

	strcpy(sysfs_val, cycle_diff_s);
	print_debug("sysfs val: %s\n", sysfs_val);

	strcat(sysfs_val, " ");
	print_debug("sysfs val space: %s\n", sysfs_val);

	strcat(sysfs_val, cpu_freq_s);
	print_debug("sysfs_val: %s\n", sysfs_val);

	set_sysfs_value(g_fsl_pci_dev, TEST_PERF_SYS_FILE, (uint8_t *) sysfs_val,
			strlen(sysfs_val));

	set_sysfs_value(g_fsl_pci_dev, TEST_REPEAT_SYS_FILE,
			(uint8_t *) &total_succ_jobs, sizeof(uint32_t));

	set_sysfs_value(g_fsl_pci_dev, TEST_RES_SYS_FILE, "SUCCESS",
			strlen("SUCCESS"));

	set_sysfs_value(g_fsl_pci_dev, TEST_NAME_SYS_FILE, "INVALID",
			strlen("INVALID"));
	}
	atomic_set(&total_deq_cnt, 0);
	atomic_set(&total_enq_cnt, 0);
	atomic_set(&flag, 0);
	atomic_set(&test_done, 0);
}

void start_test(void)
{
	newtest = 1;
	print_debug("This Thread is invoked by CPU: %d\n", smp_processor_id());
	if (!atomic_read(&timer_started)) {
		print_debug("start stopwatch: s_time is set by thread %d\n",
				smp_processor_id());
		s_time = get_cpu_ticks();
		atomic_set(&timer_started, 1);
	}
	while (!exit) {
		while (!atomic_read(&hold_off)) {
			if (testfunc() == 0) {
				atomic_set(&total_err_cnt, 0);
				if (atomic_inc_return(&total_enq_cnt) >= total_enq_req) {
					atomic_set(&hold_off, 1);
					print_debug("Test is in hold off state\n");
					break;
				}
				print_debug("Enq: %d\n", atomic_read(&total_enq_cnt));
			} else {
				if(atomic_inc_return(&total_err_cnt) > 100000) {
					print_debug("Total Error count : %d exceed MAX_LIMIT.... Exiting Test\n",
							atomic_read(&total_err_cnt));
					atomic_set(&hold_off, 1);
					atomic_set(&test_done, 1);
				}
#ifndef ENHANCE_KERNEL_TEST				
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(usecs_to_jiffies(1));
#endif
			}
		}
		print_debug("Waitingggg......\n");
		if (atomic_read(&test_done) && newtest) {
			print_debug("Test request count exceed\n");
			strcpy(g_test_name, "INVALID");
			g_is_test_in_progress = 0;
			if (!timer_set) {
				print_debug("Total_job_count inside thread\n");
				total_succ_jobs = atomic_read(&total_deq_cnt);
			}
			check_test_done();
		}
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
}

static void test_timer_expired(unsigned long data)
{
	total_succ_jobs = atomic_read(&total_deq_cnt);
	atomic_set(&hold_off, 1);
	print_debug("Tot jobs completed.. :%d\n", total_succ_jobs);
	total_enq_req = 0;
	if ((atomic_read(&total_deq_cnt) >= total_enq_req)) {
		if (!atomic_read(&flag)) {
			e_time = get_cpu_ticks();
			atomic_set(&test_done, 1);
			atomic_set(&flag, 1);
		}
	}
}

int valid_test(void)
{
	int ret = 1;
	char *test_name = g_test_name;
	if ((!strcmp(test_name, "RSA_PUB_OP_1K")) ||
	    (!strcmp(test_name, "RSA_PUB_OP_2K")) ||
	    (!strcmp(test_name, "RSA_PUB_OP_4K")) ||
	    (!strcmp(test_name, "RSA_PRV_OP_1K")) ||
	    (!strcmp(test_name, "RSA_PRV_OP_2K")) ||
	    (!strcmp(test_name, "RSA_PRV_OP_4K")) ||
	    (!strcmp(test_name, "DSA_VERIFY_TEST_1K")) ||
	    (!strcmp(test_name, "DSA_SIGN_TEST_1K")) ||
	    (!strcmp(test_name, "DSA_VERIFY_TEST_2K")) ||
	    (!strcmp(test_name, "DSA_SIGN_TEST_2K")) ||
	    (!strcmp(test_name, "DSA_VERIFY_TEST_4K")) ||
	    (!strcmp(test_name, "DSA_SIGN_TEST_4K")) ||
	    (!strcmp(test_name, "DSA_KEYGEN_TEST")) ||
	    (!strcmp(test_name, "ECDSA_KEYGEN_TEST")) ||
	    (!strcmp(test_name, "DH_KEYGEN_TEST")) ||
	    (!strcmp(test_name, "DSA_SIGN_VERIFY_TEST")) ||
	    (!strcmp(test_name, "ECDH_TEST")) ||
	    (!strcmp(test_name, "ECDSA_SIGN_TEST")) ||
	    (!strcmp(test_name, "ECDSA_VERIFY_TEST")) ||
	    (!strcmp(test_name, "ECP_SIGN_TEST_256")) ||
	    (!strcmp(test_name, "ECP_VERIFY_TEST_256")) ||
	    (!strcmp(test_name, "ECP_SIGN_TEST_384")) ||
	    (!strcmp(test_name, "ECP_VERIFY_TEST_384")) ||
	    (!strcmp(test_name, "ECP_SIGN_TEST_521")) ||
	    (!strcmp(test_name, "ECP_VERIFY_TEST_521")) ||
	    (!strcmp(test_name, "ECPBN_SIGN_TEST_283")) ||
	    (!strcmp(test_name, "ECPBN_VERIFY_TEST_283")) ||
	    (!strcmp(test_name, "ECPBN_SIGN_TEST_409")) ||
	    (!strcmp(test_name, "ECPBN_VERIFY_TEST_409")) ||
	    (!strcmp(test_name, "ECPBN_SIGN_TEST_571")) ||
	    (!strcmp(test_name, "ECPBN_VERIFY_TEST_571")) ||
	    (!strcmp(test_name, "DH_TEST_1K")) ||
	    (!strcmp(test_name, "DH_TEST_2K")) ||
	    (!strcmp(test_name, "DH_TEST_4K")) ||
		(!strcmp(test_name, "ECDH_KEYGEN_P256")) ||
		(!strcmp(test_name, "ECDH_KEYGEN_P384")) ||
		(!strcmp(test_name, "ECDH_KEYGEN_P521")) ||
		(!strcmp(test_name, "ECDH_KEYGEN_B283")) ||
		(!strcmp(test_name, "ECDH_KEYGEN_B409")) ||
		(!strcmp(test_name, "ECDH_KEYGEN_B571"))) {
		ret = 1;
	} else {
		ret = 0;
	}
	return ret;
}

void clean_all_test(void)
{
	/* FIXME: stop all test threads before driver exits */
	cleanup_rsa_test();
	cleanup_dsa_test();
	cleanup_ecdh_test();
	cleanup_ecdsa_test();
	cleanup_dh_test();
	cleanup_ecp_test();
	cleanup_ecpbn_test();
	cleanup_ecdh_keygen_test();
}

/* FIXME: we have a lot of undue faith in success of this function. Fix all
 * tests to return error codes on initialization */
void init_all_test(void)
{
	init_1k_rsa_pub_op_req();
	init_2k_rsa_pub_op_req();
	init_4k_rsa_pub_op_req();
	init_1k_rsa_prv3_op_req();
	init_2k_rsa_prv3_op_req();
	init_4k_rsa_prv3_op_req();
	init_dsa_verify_test_1k();
	init_dsa_sign_test_1k();
	init_dsa_verify_test_2k();
	init_dsa_sign_test_2k();
	init_dsa_verify_test_4k();
	init_dsa_sign_test_4k();
	init_ecdh_test();
	init_ecdsa_verify_test();
	init_ecdsa_sign_test();
	init_ecp_sign_test_256();
	init_ecp_verify_test_256();
	init_ecp_sign_test_384();
	init_ecp_verify_test_384();
	init_ecp_sign_test_521();
	init_ecp_verify_test_521();
	init_ecpbn_sign_test_283();
	init_ecpbn_verify_test_283();
	init_ecpbn_sign_test_409();
	init_ecpbn_verify_test_409();
	init_ecpbn_sign_test_571();
	init_ecpbn_verify_test_571();
	init_dh_test_1k();
	init_dh_test_2k();
	init_dh_test_4k();
	init_ecdh_keygen_test_p256();
	init_ecdh_keygen_test_p384();
	init_ecdh_keygen_test_p521();
	init_ecdh_keygen_test_b283();
	init_ecdh_keygen_test_b409();
	init_ecdh_keygen_test_b571();
}

int test(void *data)
{
	char *test_name = g_test_name;
	int8_t run = 1;

	print_debug("*** Thread  %p is invoked ***\n", data);
	/* This need to call once to initialize all the test */
	if (!strcmp(test_name, "RSA_PUB_OP_1K")) {
		print_debug("RSA_PUB_OP_1K invoking\n");
		testfunc = test_rsa_pub_op_1k;
	} else if (!strcmp(test_name, "RSA_PUB_OP_2K")) {
		print_debug("RSA_PUB_OP_2K invoking\n");
		testfunc = test_rsa_pub_op_2k;
	} else if (!strcmp(test_name, "RSA_PUB_OP_4K")) {
		print_debug("RSA_PUB_OP_4K invoking\n");
		testfunc = test_rsa_pub_op_4k;
	} else if (!strcmp(test_name, "RSA_PRV_OP_1K")) {
		print_debug("RSA_PRV_OP_1K invoking\n");
		testfunc = test_rsa_priv_op_1k;
	} else if (!strcmp(test_name, "RSA_PRV_OP_2K")) {
		print_debug("RSA_PRV_OP_2K invoking\n");
		testfunc = test_rsa_priv_op_2k;
	} else if (!strcmp(test_name, "RSA_PRV_OP_4K")) {
		print_debug("RSA_PRV_OP_4K invoking\n");
		testfunc = test_rsa_priv_op_4k;
	} else if (!strcmp(test_name, "DSA_VERIFY_TEST_1K")) {
		print_debug("DSA_VERIFY_TEST_1K invoking\n");
		testfunc = dsa_verify_test_1k;
	} else if (!strcmp(test_name, "DSA_SIGN_TEST_1K")) {
		print_debug("DSA_SIGN_TEST_1K invoking\n");
		testfunc = dsa_sign_test_1k;
	} else if (!strcmp(test_name, "DSA_VERIFY_TEST_2K")) {
		print_debug("DSA_VERIFY_TEST_2K invoking\n");
		testfunc = dsa_verify_test_2k;
	} else if (!strcmp(test_name, "DSA_SIGN_TEST_2K")) {
		print_debug("DSA_SIGN_TEST_2K invoking\n");
		testfunc = dsa_sign_test_2k;
	} else if (!strcmp(test_name, "DSA_VERIFY_TEST_4K")) {
		print_debug("DSA_VERIFY_TEST_4K invoking\n");
		testfunc = dsa_verify_test_4k;
	} else if (!strcmp(test_name, "DSA_SIGN_TEST_4K")) {
		print_debug("DSA_SIGN_TEST invoking\n");
		testfunc = dsa_sign_test_4k;
	} else if (!strcmp(test_name, "DSA_SIGN_VERIFY_TEST")) {
		print_debug("DSA_SIGN_VERIFY_TEST invoking\n");
		testfunc = dsa_sign_verify_test;
	} else if (!strcmp(test_name, "DSA_KEYGEN_TEST")) {
		print_debug("DSA_KEYGEN_TEST invoking\n");
		testfunc = dsa_keygen_test;
	} else if (!strcmp(test_name, "ECDSA_KEYGEN_TEST")) {
		print_debug("ECDSA_KEYGEN_TEST invoking\n");
		testfunc = ecdsa_keygen_test;
 	} else if (!strcmp(test_name, "DH_KEYGEN_TEST")) {
		print_debug("DH_KEYGEN_TEST invoking\n");
        testfunc = dh_keygen_test;
	} else if (!strcmp(test_name, "ECDH_TEST")) {
		print_debug("ECDH_TEST invoking\n");
		testfunc = ecdh_test;
	} else if (!strcmp(test_name, "ECDSA_VERIFY_TEST")) {
		print_debug("ECDSA_VERIFY_TEST invoking\n");
		testfunc = ecdsa_verify_test;
	} else if (!strcmp(test_name, "ECDSA_SIGN_TEST")) {
		print_debug("ECDSA_TEST invoking\n");
		testfunc = ecdsa_sign_test;
	} else if (!strcmp(test_name, "ECP_SIGN_TEST_256")) {
		print_debug("ECP_SIGN_TEST_256 invoking\n");
		testfunc = ecp_sign_test_256;
	} else if (!strcmp(test_name, "ECP_VERIFY_TEST_256")) {
		print_debug("ECP_VERIFY_TEST_256 invoking\n");
		testfunc = ecp_verify_test_256;
	} else if (!strcmp(test_name, "ECP_SIGN_TEST_384")) {
		print_debug("ECP_SIGN_TEST_384 invoking\n");
		testfunc = ecp_sign_test_384;
	} else if (!strcmp(test_name, "ECP_VERIFY_TEST_384")) {
		print_debug("ECP_VERIFY_TEST_384 invoking\n");
		testfunc = ecp_verify_test_384;
	} else if (!strcmp(test_name, "ECP_SIGN_TEST_521")) {
		print_debug("ECP_SIGN_TEST_521 invoking\n");
		testfunc = ecp_sign_test_521;
	} else if (!strcmp(test_name, "ECP_VERIFY_TEST_521")) {
		print_debug("ECP_VERIFY_TEST_521 invoking\n");
		testfunc = ecp_verify_test_521;
	} else if (!strcmp(test_name, "ECPBN_SIGN_TEST_283")) {
		print_debug("ECPBN_SIGN_TEST_283 invoking\n");
		testfunc = ecpbn_sign_test_283;
	} else if (!strcmp(test_name, "ECPBN_VERIFY_TEST_283")) {
		print_debug("ECPBN_VERIFY_TEST_283 invoking\n");
		testfunc = ecpbn_verify_test_283;
	} else if (!strcmp(test_name, "ECPBN_SIGN_TEST_409")) {
		print_debug("ECPBN_SIGN_TEST_409 invoking\n");
		testfunc = ecpbn_sign_test_409;
	} else if (!strcmp(test_name, "ECPBN_VERIFY_TEST_409")) {
		print_debug("ECPBN_VERIFY_TEST_409 invoking\n");
		testfunc = ecpbn_verify_test_409;
	} else if (!strcmp(test_name, "ECPBN_SIGN_TEST_571")) {
		print_debug("ECPBN_SIGN_TEST_571 invoking\n");
		testfunc = ecpbn_sign_test_571;
	} else if (!strcmp(test_name, "ECPBN_VERIFY_TEST_571")) {
		print_debug("ECPBN_VERIFY_TEST_571 invoking\n");
		testfunc = ecpbn_verify_test_571;
	} else if (!strcmp(test_name, "DH_TEST_1K")) {
		print_debug("DH_TEST_1K invoking\n");
		testfunc = dh_test_1k;
	} else if (!strcmp(test_name, "DH_TEST_2K")) {
		print_debug("DH_TEST_2K invoking\n");
		testfunc = dh_test_2k;
	} else if (!strcmp(test_name, "DH_TEST_4K")) {
		print_debug("DH_TEST_4K invoking\n");
		testfunc = dh_test_4k;
	} else if (!strcmp(test_name, "ECDH_KEYGEN_P256")) {
        print_debug("ECDH_KEYGEN_P256 invoking\n");
        testfunc = ecdh_keygen_test_p256;
    } else if (!strcmp(test_name, "ECDH_KEYGEN_P384")) {
        print_debug("ECDH_KEYGEN_P384 invoking\n");
        testfunc = ecdh_keygen_test_p384;
    } else if (!strcmp(test_name, "ECDH_KEYGEN_P521")) {
        print_debug("ECDH_KEYGEN_P521 invoking\n");
        testfunc = ecdh_keygen_test_p521;
    } else if (!strcmp(test_name, "ECDH_KEYGEN_B283")) {
        print_debug("ECDH_KEYGEN_B283 invoking\n");
        testfunc = ecdh_keygen_test_b283;
    } else if (!strcmp(test_name, "ECDH_KEYGEN_B409")) {
        print_debug("ECDH_KEYGEN_B409 invoking\n");
        testfunc = ecdh_keygen_test_b409;
    } else if (!strcmp(test_name, "ECDH_KEYGEN_B571")) {
        print_debug("ECDH_KEYGEN_B571 invoking\n");
        testfunc = ecdh_keygen_test_b571;
	} else {
		print_debug("Invalid test name... :%s\n", test_name);
		run = 0;
	}

	if (run) {
		start_test();
	}
	strcpy(g_test_name, "INVALID");
	g_is_test_in_progress = 0;
	print_debug("Returning from thread\n");
	return 0;
}

int parsing_test_command(char *test_name)
{
	int i = 0;

	while ((i < (TEST_NAME_LENGTH - 1)) && (test_name[i] != '\0') &&
			(test_name[i] != ' ')) {
		g_test_name[i] = test_name[i];
		i++;
	}

	g_test_name[i] = '\0';
	if (!valid_test() || (test_name[i] == '\0'))
		return -1;

	i++;
	cpu_mask = 0;
	while ((test_name[i] != '\0') && (test_name[i] != ' '))
		cpu_mask = (cpu_mask * 10) + (test_name[i++] - '0');

	if (test_name[i] == '\0')
		return -1;

	i++;			/* skiping the space */
	threads_per_cpu = 0;
	while ((test_name[i] != '\0') && (test_name[i] != ' '))
		threads_per_cpu =
		    (threads_per_cpu * 10) + (test_name[i++] - '0');

	if (test_name[i] == '\0')
		return -1;

	i++;			/* skiping the space */
	time_duration = 0;
	while ((test_name[i] != '\0') && (test_name[i] != ' '))
		time_duration =
		    (time_duration * 10) + (test_name[i++] - '0');

	if (test_name[i] == '\0')
		return -1;

	i++;			/* Skiping the space */
	total_enq_req = 0;
	while ((test_name[i] != '\0') && (test_name[i] != ' '))
		total_enq_req =
		    (total_enq_req * 10) + (test_name[i++] - '0');

	if (0 == total_enq_req) {
		total_enq_req = 0xffffffff;
	}

	if (time_duration > 0) {
		total_enq_req = 0xffffffff;
		timer_set = 1;
	}
	return 0;
}

void c2x0_test_func(char *fname, char *test_name, int len)
{
	int loop;

	print_debug("Test name: %s\n", test_name);
	if (strcmp(fname, "test_name")) {
		print_debug("Returning from here...\n");
		return;
	}
	if (!strcmp(test_name, "INVALID"))
		return;

	if (!strcmp(test_name, "current_test_stop_request")) {
		total_succ_jobs = atomic_read(&total_deq_cnt);
		e_time = get_cpu_ticks();
		atomic_set(&hold_off, 1);
		print_debug("Test stopped by user\n\n");
		strcpy(g_test_name, "INVALID");
		g_is_test_in_progress = 0;
		check_test_done();
		return;
	}

	if (g_is_test_in_progress) {
		print_debug("Some test is in progress....\n");
		return;
	}

	g_is_test_in_progress = 1;

	if (-1 == parsing_test_command(test_name)) {
		print_debug("Invalid test\n");;
		return;
	}

	print_debug("Test Name: %s, Cpu: %d, Thread: %d, Timer: %d sec, req count: %d\n",
	     g_test_name, cpu_mask, threads_per_cpu, time_duration, total_enq_req);
	/* Start up the threads per CPU */
	for (loop = 0; loop < threads_per_cpu; loop++) {
		int cpu_loop;
		/* Traverse through CPUs */
		for (cpu_loop = 0; cpu_loop < num_online_cpus(); cpu_loop++) {
			if (!(cpu_mask & (1 << cpu_loop)))
				continue;
			/* Start the test thread */
			task[no_thread] = kthread_create(test, NULL, "test_thread");
			if (IS_ERR(task[no_thread])) {
				print_debug("task creation failed\n");
				return;
			}
			kthread_bind(task[no_thread], cpu_loop);
			print_debug("Thread %d created with: %d cpu\n",
				    no_thread, cpu_loop);
			no_thread++;
		}
	}
	if(no_thread > MAX_TEST_THREAD_SUPPORT)
	{
		print_error("Max thread limit exeed\n");
		return;
	}
	print_debug("no of thread created: %d\n", no_thread);
	atomic_set(&timer_started, 0);
	atomic_set(&hold_off, 0);
	exit = 0;

	print_debug("Wake up all test threads\n");
	for (loop = 0; loop < no_thread; loop++)
		wake_up_process(task[loop]);

	if (timer_set) {
		print_debug("Registering the kernel timer\n");
		setup_timer(&test_timer, test_timer_expired, 0);
		mod_timer(&test_timer,
			  jiffies + msecs_to_jiffies(time_duration * 1000));
	}
}

void common_dec_count(void)
{
	print_debug("Checking Tot: %d, Dec count: %d\n ", total_enq_req,
		    atomic_read(&total_deq_cnt));
	if ((atomic_inc_return(&total_deq_cnt) >= total_enq_req)) {
		if (!atomic_read(&flag)) {
			e_time = get_cpu_ticks();
			atomic_set(&test_done, 1);
			atomic_set(&flag, 1);
		}
	}
}
