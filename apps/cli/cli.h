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

#define FAILURE 0
#define SUCCESS 1
#define RESETME -1
#define QUIT	2
#define RESETVALUE RESETME
#define FAILED RESETVALUE
#define ALIVE  556

#define DATE_MASK   0xff000000
#define DATE_SHIFT  24

#define MONTH_MASK  0x00f00000
#define MONTH_SHIFT 20

#define YEAR_MASK   0x000fff00
#define YEAR_SHIFT  8

#define MAJOR_MASK  0x000000f0
#define MAJOR_SHIFT 4

#define MINOR_MASK  0x0000000f

#define ASSIGN32(l,r) (l = be32toh(r))

const char *crypto_help =
"\n try\n \
----\n \
debug dev-id <DEVICE ID>                        rehandshake dev-id <DEVICE ID> configfile <FILE PATH>\n \
devstat dev-id <DEVICE ID>                      pingdev dev-id <DEVICE ID>\n \
resetdev dev-id <DEVICE ID>                     resetsec dev-id <DEVICE ID> sec-id <SEC ID>\n \
ringstat dev-id <DEVICE ID> ring-id <RING ID>   secstat dev-id <DEVICE ID>\n \
exit\n";

const char *per_cmd_crypto_help[] = {
"\nHelp:\n \
Perform debug for Perticular Device\n \
Syntax: debug dev-id <DEVICE ID>\n",

"\nHelp:\n \
Displays device statistics\n \
Syntax: devstat dev-id <DEVICE ID>\n",

"\nHelp:\n \
If configuration of device needs to be change then\n \
Again perform handshake\n \
Syntax: rehandshake dev-id <DEVICE ID> configfile <FILE PATH>\n",

"\nHelp:\n \
Check the Device for alive status\n \
syntax: pingdev dev-id <DEVICE ID>\n",

"\nHelp:\n \
Reset the Device\n \
Syntax: resetdev dev-id <DEVICE ID>\n",

"\nHelp:\n \
Reset the Sec Engine from a Device\n \
Syntax: resetsec dev-id <DEVICE ID> sec-id <SEC ID>\n",

"\nHelp:\n \
Display ring statistics\n \
Syntax: ringstat dev-id <DEVICE ID> ring-id <RING ID>\n",

"\nHelp:\n \
Display sec engine related statistics\n \
Syntax: secstat dev-id <DEVICE ID>\n",
};

const char *debug_help =
"\n try\n \
----\n \
md ADDRESS \n \
mw ADDRESS VALUE \n \
print_debug VALUE(1[ENABLE]/0[DISABLE])\n \
print_error VALUE(1[ENABLE]/0[DISABLE])\n \
exit\n";

const char *dev_prompt 	 = "cryptodev> ";
const char *debug_prompt = "c29x_fw=> ";

#define MAIN_COMMANDS 8
const char *main_cmds[] = {"debug","devstat","rehandshake","pingdev","resetdev","resetsec","ringstat","secstat","exit"};
typedef enum main_commands {
    DEBUG,
    DEVSTAT,
    REHANDSHAKE,
	PINGDEV,
    RESETDEV,
    RESETSEC,
    RINGSTAT,
	SECSTAT,
    EXIT
}cmd_type_t;

#define RSRC_COMMANDS 4
const char *rsrc_cmds[] = {"dev-id","ring-id","sec-id","configfile"};
enum rsrc_commands {
    DEVID,
    RINGID,
    SECID,
    CONFIGFILE,
};

#define DEBUG_COMMANDS 4
const char *debug_cmds[] = {"md","mw","print_debug","print_error"};
typedef enum debug_commands {
	MD,
	MW,
	PRINT_DEBUG,
	PRINT_ERROR,
}dgb_cmd_type_t;

/* OUTPUT STRUCTURES FOR STAT */

#define MAX_SEC_NO 3
/* OUTPUT STRUCTURES FOR STAT */
/* SEC STAT */
typedef struct fsl_sec_stat {
	unsigned int    sec_ver;
	unsigned int    cha_ver;
	unsigned int    no_of_sec_engines;
	unsigned int    no_of_sec_jr;
	unsigned int    jr_size;
	struct sec_ctrs_t {
		unsigned int sec_tot_req_jobs;
		unsigned int sec_tot_resp_jobs;
	}sec[MAX_SEC_NO];
}fsl_sec_stat_t;

/* DEVICES STAT */
typedef struct fsl_dev_stat_op {
    unsigned int fwversion;
    unsigned int totalmem;
    unsigned int codemem;
    unsigned int heapmem;
    unsigned int freemem;
    unsigned int num_of_sec_engine;     /* ALREADY IN crypto_dev_config_t */
    unsigned int no_of_app_rings;       /* ALREADY IN crypto_dev_config_t */
    unsigned int total_jobs_rx;         /* ALREADY IN struct crypto_h_mem_layout */
    unsigned int total_jobs_pending;    /* ALREADY IN struct crypto_h_mem_layout */
}fsl_dev_stat_op_t;

/* RESOURCE STAT */
struct fsl_ring_stat_op {
    unsigned int depth;             /* ALREADY IN struct ring_info  */
    unsigned int tot_size;          /* REALLY NEED THIS ???         */
	unsigned int priority;			/* PRIORITY OF RING  */
	unsigned int affinity;			/* AFFINITY OF RING  */
	unsigned int order;				/* ORDER OF RING 	*/
    unsigned int free_count;        /* DEPTH - CURRENT JOBS */
    unsigned int jobs_processed;    /* ALREADY IN struct  ring_counters_mem */
    unsigned int jobs_pending;      /* ALREADY IN struct  ring_counters_mem */
    unsigned int budget;
}__packed;
typedef struct fsl_ring_stat_op  fsl_ring_stat_op_t;

/* DEBUG */
typedef struct debug_op {
    unsigned int total_ticks;
    unsigned int pcie_data_consume_ticks;   /* WRITE OUT HOST TO CARD + CARD TO HOST */
    unsigned int job_wait_ticks;            /* WAIT TIME IN JOB QUEUE */
    unsigned int job_process_ticks;         /* PROCESS TIME */
    unsigned int sec_job_ticks;             /* TICKS FOR SEC TO COMPLETE JOB */
}debug_op_t;

typedef struct ping_op {
    unsigned int resp;
}ping_op_t;

typedef union op_buffer {
    ping_op_t           ping_op;
/*    debug_op_t          debug_op;	*/
	unsigned int 		debug_op[64];
    fsl_ring_stat_op_t  ring_stat_op;
    fsl_dev_stat_op_t   dev_stat_op;
	fsl_sec_stat_t      sec_op;
}op_buffer_t;

typedef struct debug_ip {
	dgb_cmd_type_t cmd_id;
	unsigned int address;
	unsigned int val;
}debug_ip_t;

/*******************************************************************************
Description : Identifies the user command arguments
Fields      : cmd_type      : type of command
              rsrc          : resource on which command will operate
              result        : result fail/success
              op_buffer     : output buffer
*********************************************************************************/
struct user_command_args {
    cmd_type_t cmd_id;
    int dev_id;

    union rsrc_t {
        int sec_id;
        int ring_id;
		debug_ip_t dgb;
        char config[200];
    }rsrc;

	int *result;
    op_buffer_t *op_buffer;
}cmd;

/* IOCTL COMMAND */
#define CMDOPERATION _IOWR('c',201,struct user_command_args)
#define CHECKCMD _IOWR('c',209,struct user_command_args)

void readcmdline(char *, const char *);
void parselinetocmds(char *, int *, char **);
int  isvalidnum(char *);
int  prepare_command(int , char **);
int  exe_command();
void show_help();
