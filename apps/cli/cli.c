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

#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "cli.h"

int fd=0;
/*******************************************************************************
 * Function     : main
 *
 * Arguments    : argn - number of argumets ,argv - argument vector
 *
 * Return Value : int
 *
 * Description  : main function for handling cli
 *
 *******************************************************************************/
int main(int argn,char **argv)
{
	char line[150];
	int temp=0;

    if ((fd = open("/dev/fsl_cryptodev", O_RDWR, 0)) == -1) {
        perror("OPEN:");
        return -1;
    }

	if (argn>1)
	{	/* COMMAND LINE ARGUMENT */
		memset((void *)&cmd,RESETVALUE,sizeof(struct user_command_args));
		if (prepare_command(argn,argv))
			return exe_command();
		else
			if (-1 != cmd.cmd_id)   printf("%s\n",per_cmd_crypto_help[cmd.cmd_id]);
			else                    printf("%s\n",crypto_help);
		return 0;
	}

	while (1)
	{	/* INTERACTIVE COMMAND PROMPT */
		memset((void *)&cmd,RESETVALUE,sizeof(struct user_command_args));
		readcmdline(line, dev_prompt);
		parselinetocmds(line,&argn,argv);
		if (prepare_command(argn,argv))
		{
			if (EXIT == cmd.cmd_id)
            {
                close(fd);
				return 0;
            }

		if ( -1 == exe_command())
				goto help;

			for (temp=1;temp<=argn;++temp)	/* FREE THE COMMAND */
				free(argv[temp]);
		}
		else
        {

help:
			for (temp=1;temp<=argn;++temp)		/* FREE THE COMMAND */
			free(argv[temp]);
			if (-1 != cmd.cmd_id) 	printf("%s\n",per_cmd_crypto_help[cmd.cmd_id]);
			else					printf("%s\n",crypto_help);
        }
    }

	return 0;
}

/*******************************************************************************
 * Function     : readcmdline
 *
 * Arguments    : line
 *
 * Return Value : void
 *
 * Description  : reads commands from console
 *
 *******************************************************************************/
void readcmdline(char *line,const char *prompt)
{
	int cursor=0;
    printf("%s",prompt);
    do
	{
        scanf("%c",&(line[cursor++]));
    }while (line[cursor-1] != '\n');
	line[cursor-1] = '\0';
	return;
}
/*******************************************************************************
 * Function     : parselinetocmds
 *
 * Arguments    : line - buffer of commands
 *				  argn - argument counter
 *				  argv - pointer to string array
 *
 * Return Value : void
 *
 * Description  : parse the commands form input buffer
 *
 *******************************************************************************/
void parselinetocmds(char *line,int *argn,char **argv)
{
	char *temp_arg,*save_ptr;
	*argn = 1;
	temp_arg = strtok_r(line," ",&save_ptr);
	while (temp_arg != '\0')
	{
		argv[*argn] = malloc(strlen(temp_arg));
		strcpy(argv[*argn],temp_arg);
		temp_arg = NULL;
		(*argn)++;
		temp_arg = strtok_r(NULL," ",&save_ptr);
	}
	argv[*argn] = '\0';
	--(*argn);
	line[0] = '\0';
}
/*******************************************************************************
 * Function     : isvalid num
 *
 * Arguments    : argv - pointer to string
 *
 * Return Value : on success - int else FAILURE
 *
 * Description  : checks whether no is valid or not
 *
 *******************************************************************************/
int isvalidnum(char *argbuf)
{
	char localbuf[10];
	int no;

	no = atoi(argbuf);
	sprintf(localbuf,"%d",no);

	if (memcmp(localbuf,argbuf,strlen(argbuf)))
	{
		printf("ERROR:Invalid Input [%s]\n",argbuf);
		return -1;
	}
	return no;
}
/*******************************************************************************
 * Function     : prepare_command
 *
 * Arguments    : argn - argument counter
 *				  argv - pointer to string array
 *
 * Return Value : on success - SUCCESS else FAILURE
 *
 * Description  : prepares the command
 *
 *******************************************************************************/
int prepare_command(int argn,char **argv)
{
	int counter=1,cmd_counter=0,temp=0;
	for (cmd_counter=0;cmd_counter<=MAIN_COMMANDS && argv[counter];cmd_counter++)
	{
		if (strcmp(main_cmds[cmd_counter],argv[counter]) == 0)
		{
			counter++;
			cmd.cmd_id = cmd_counter;
			break;
		}
	}

	if (cmd_counter == MAIN_COMMANDS+1 ) /* NO COMMAND */
	{
		printf("ERROR:No such a command [%s]\n",argv[counter]);
		return FAILURE;
	}
	for (;counter<=argn;++counter)
	{
		for (cmd_counter=0; cmd_counter<RSRC_COMMANDS && argv[counter];++cmd_counter)
	{
			if (strcmp(rsrc_cmds[cmd_counter],argv[counter]) == 0)
			{
				counter++;
				if (argv[counter])
				{
					switch (cmd_counter)
					{
						case DEVID:
							if (FAILED == (temp = isvalidnum(argv[counter])))	return FAILURE;
							cmd.dev_id  = temp;
							break;

						case RINGID:
							if (FAILED == (temp = isvalidnum(argv[counter])))  return FAILURE;
							cmd.rsrc.ring_id  = temp;
							break;

						case SECID:
							if (FAILED == (temp = isvalidnum(argv[counter])))  return FAILURE;
							cmd.rsrc.sec_id   = temp;
							break;

                        case CONFIGFILE:
                            strcpy(cmd.rsrc.config, argv[counter]);
                            break;
					}/* switch(cmd_counter) */
				}
				break;
			}
		}
		if (cmd_counter == RSRC_COMMANDS)
		{
			printf("ERROR:No such a command [%s]\n",argv[counter]);
			return FAILURE;
		}
	}
	return SUCCESS;
}


unsigned int str_to_hex(const char *s)
{
    unsigned int result = 0;
    int c ;
    if ('0' == *s && 'x' == *(s+1)) {
        s += 2;
    }
    while (*s) {
        result = result << 4;
        if(c=(*s-'0'),(c>=0 && c <=9))
            result|=c;
        else if(c=(*s-'A'),(c>=0 && c <=5))
            result|=(c+10);
        else if(c=(*s-'a'),(c>=0 && c <=5))
            result|=(c+10);
        else {
            printf("Wrong address value entered. HELP : md 0x<addr>/md <addr>\n");
            return -1;
        }
        ++s;
    }
    return result;
}

int prepare_debug_command(int argn,char **argv)
{
	int cmd_counter=0, counter=1;
    for (cmd_counter=0; cmd_counter<DEBUG_COMMANDS && argv[counter]; cmd_counter++)
    {
		if (strcmp("exit", argv[counter]) == 0 || strcmp("EXIT", argv[counter]) == 0)
			return QUIT;

        if (strcmp(debug_cmds[cmd_counter], argv[counter]) == 0)
        {
			counter++;
			if (argv[counter])
            {
				unsigned int addr = 0;
		addr = str_to_hex(argv[counter]);
                if (-1 == addr)
                    return FAILURE;
                cmd.rsrc.dgb.address  = addr;
/*
			cmd.rsrc.dgb.address  = (unsigned int)strtol(argv[counter], NULL, 16);
*/
				counter++;

				switch (cmd_counter)
				{
					case MD:
						cmd.rsrc.dgb.cmd_id = MD;
						return SUCCESS;

					case MW:
						if (argv[counter])
						{
							cmd.rsrc.dgb.cmd_id = MW;
/*							cmd.rsrc.dgb.val = strtol(argv[counter], NULL, 16);	*/
							cmd.rsrc.dgb.val = str_to_hex(argv[counter]);
							if (-1 == addr)
			                    return FAILURE;
							counter++;
							return SUCCESS;
						}

					case PRINT_DEBUG:
					case PRINT_ERROR:
						cmd.rsrc.dgb.cmd_id = cmd_counter;
						cmd.rsrc.dgb.val = cmd.rsrc.dgb.address;
						return SUCCESS;
				}
			}
        }
    }
	return FAILURE;
}

int exe_debug_command()
{
	cmd.op_buffer = (op_buffer_t *)malloc(sizeof(op_buffer_t));
    cmd.result    = (int *)malloc(sizeof(int));

    if( -1 == ioctl(fd, CMDOPERATION , &cmd))
	printf("OOPS ... invalid dev_id \n\n");
    else
	{
		if (!*(cmd.result))
		{
			switch (cmd.rsrc.dgb.cmd_id)
			{
				case MD:
				{
                    int i=0;
                    int j=0;
                    int k=0;
#define DEBUG_ROW_COUNT 16
#define DEBUG_COL_COUNT 5
                    for(j=0; j<DEBUG_ROW_COUNT; j++){
                        for (i=0; i<DEBUG_COL_COUNT; ++i){
				ASSIGN32(cmd.op_buffer->debug_op[k], cmd.op_buffer->debug_op[k]);
                            if(!i)
                                printf("%08x  :\t", cmd.rsrc.dgb.address + (DEBUG_COL_COUNT - 1) * 4 * j);
                            else
                                printf("%08x\t", cmd.op_buffer->debug_op[k++]);
                        }
                        printf("\n");
                    }
                }
				break;

				case MW:
					printf("%x wrote at address %x\n", cmd.rsrc.dgb.val, cmd.rsrc.dgb.address);
					break;

				case PRINT_DEBUG:
                case PRINT_ERROR:
					break;
			}
		}
		else
			printf("OOPS ... something went wrong \n\n");
	}

	free(cmd.result);
    free(cmd.op_buffer);
	return 1;
}

void debug(int dev_id)
{
	char line[150];
	int argn, temp=0, ret=0;
	char *argv[5];

	while (1)
	{
		readcmdline(line, debug_prompt);
		parselinetocmds(line, &argn, argv);
		ret = prepare_debug_command(argn, argv);

		for (temp=1;temp<=argn;++temp)
	    free(argv[temp]);

		if (QUIT == ret)
			break;

		if (ret)
		{
			/* EXECUTE COMMAND */
			exe_debug_command();
		}
		else
			printf("%s\n", debug_help);
	}

}

/*******************************************************************************
 * Function     : exe_command
 *
 * Arguments    :
 *
 * Return Value : int
 *
 * Description  : executes the command
 *
 *******************************************************************************/
int exe_command()
{
	int ret = 0;

	switch (cmd.cmd_id)
	{
		case DEBUG:	/* DEBUG COMMAND */
				if (RESETVALUE >= cmd.dev_id)
					return -1;
				ret = ioctl(fd, CHECKCMD, &cmd);

				if( -1 == ret)
					printf("OOPS ... invalid dev_id \n\n");
				else if (EACCES == ret)
					printf("CLI is disabled.. HIGH PERF mode is defined \n\n");
				else
					debug(cmd.dev_id);

				return 0;

		case DEVSTAT: /* DEVSTAT COMMAND */
				if (RESETVALUE >= cmd.dev_id)
					return -1;
                cmd.op_buffer = (op_buffer_t *)malloc(sizeof(op_buffer_t));
				cmd.result    = (int *)malloc(sizeof(int));
				ret = ioctl(fd, CMDOPERATION , &cmd);

                if (-1 == ret)
                    printf("OOPS ... invalid dev_id \n\n");
				else if (EACCES == ret)
					printf("CLI is disabled.. HIGH PERF mode is defined \n\n");
				else
                    if (!*(cmd.result))
                    {
						unsigned int fwversion  =  0;
						ASSIGN32(cmd.op_buffer->dev_stat_op.fwversion, cmd.op_buffer->dev_stat_op.fwversion);
						ASSIGN32(cmd.op_buffer->dev_stat_op.totalmem, cmd.op_buffer->dev_stat_op.totalmem);
						ASSIGN32(cmd.op_buffer->dev_stat_op.codemem, cmd.op_buffer->dev_stat_op.codemem);
						ASSIGN32(cmd.op_buffer->dev_stat_op.heapmem, cmd.op_buffer->dev_stat_op.heapmem);
						ASSIGN32(cmd.op_buffer->dev_stat_op.freemem, cmd.op_buffer->dev_stat_op.freemem);
						ASSIGN32(cmd.op_buffer->dev_stat_op.num_of_sec_engine, cmd.op_buffer->dev_stat_op.num_of_sec_engine);
						ASSIGN32(cmd.op_buffer->dev_stat_op.no_of_app_rings, cmd.op_buffer->dev_stat_op.no_of_app_rings);
						ASSIGN32(cmd.op_buffer->dev_stat_op.total_jobs_rx, cmd.op_buffer->dev_stat_op.total_jobs_rx);
						ASSIGN32(cmd.op_buffer->dev_stat_op.total_jobs_pending, cmd.op_buffer->dev_stat_op.total_jobs_pending);

						fwversion = cmd.op_buffer->dev_stat_op.fwversion;

						printf("DEVICE STATISTICS\n");
						printf("DEVICE ID                   :%d\n",cmd.dev_id);
						printf("FIRMWARE VERSION            :%u/%u/20%u -- V %u.%u\n",(fwversion & DATE_MASK)>>DATE_SHIFT,
                                                                                      (fwversion & MONTH_MASK)>>MONTH_SHIFT,
                                                                                      (fwversion & YEAR_MASK)>>YEAR_SHIFT,
                                                                                      (fwversion & MAJOR_MASK)>>MAJOR_SHIFT,
                                                                                      fwversion  & MINOR_MASK);
						printf("TOTAL MEMORY                :%u\n",cmd.op_buffer->dev_stat_op.totalmem);
						printf("CODE MEMORY                 :%u\n",cmd.op_buffer->dev_stat_op.codemem);
						printf("HEAP MEMORY                 :%u\n",cmd.op_buffer->dev_stat_op.heapmem);
						printf("FREE MEMORY                 :%u\n",cmd.op_buffer->dev_stat_op.freemem);
						printf("NO OF SEC ENGINES           :%u\n",cmd.op_buffer->dev_stat_op.num_of_sec_engine);
			    printf("NO OF RINGS                 :%u\n",cmd.op_buffer->dev_stat_op.no_of_app_rings);
						printf("TOTAL JOBS RECEIVED         :%u\n",cmd.op_buffer->dev_stat_op.total_jobs_rx);
			printf("TOTAL JOBS PROCESSED        :%u\n",cmd.op_buffer->dev_stat_op.total_jobs_pending);
	                    printf("TOTAL JOBS PENDING          :%u\n\n",cmd.op_buffer->dev_stat_op.total_jobs_rx -
	                                                         cmd.op_buffer->dev_stat_op.total_jobs_pending );
                    }
                    else
						printf("OOPS ... something went wrong\n\n");

				free(cmd.result);
                free(cmd.op_buffer);
                return 0;

		case REHANDSHAKE: /* DEVICE HANDSHAKE AGAIN */
				if (RESETVALUE >= cmd.dev_id || RESETVALUE >= cmd.rsrc.config[0])
					return -1;

				cmd.result    = (int *)malloc(sizeof(int));
				ret = ioctl(fd, CHECKCMD, &cmd);

				if (-1 == ret)
					printf("OOPS ... invalid parameters \n\n");
				else if (EACCES == ret)
					printf("CLI is disabled.. HIGH PERF mode is defined \n\n");
				else
				{
					printf("DOING HANDSHAKE FOR DEVICE :%d WITH CONFIG FILE :%s \n",cmd.dev_id,cmd.rsrc.config);
					if (-1 == ioctl(fd, CMDOPERATION , &cmd))
						printf("OOPS ... invalid dev_id \n\n");
					else
						if (!*(cmd.result))
							printf("HANDSHAKE SUCCESSFULL\n\n");
						else
							printf("OOPS ... something went wrong... Device is Down\n\n");
				}
				free(cmd.result);
				return 0;

		case PINGDEV: 	/* PING THE DEVICE COMMAND */
				if (RESETVALUE >= cmd.dev_id)
					return -1;
                cmd.op_buffer   = (op_buffer_t *)malloc(sizeof(op_buffer_t));
				cmd.result    = (int *)malloc(sizeof(int));
				ret = ioctl(fd, CMDOPERATION , &cmd);

                if (-1 == ret)
					printf("OOPS ... invalid dev_id \n\n");
				else if (EACCES == ret)
					printf("CLI is disabled.. HIGH PERF mode is defined \n\n");
				else
				{
					ASSIGN32(cmd.op_buffer->ping_op.resp, cmd.op_buffer->ping_op.resp);
	                if (ALIVE == cmd.op_buffer->ping_op.resp)
	                printf("DEVICE IS ALIVE\n\n");
		        else
					    printf("DEVICE IS DEAD\n\n");
				}
				free(cmd.result);
                free(cmd.op_buffer);
				return 0;

		case RESETDEV: /* DEVICE RESET COMMAND */
				if (RESETVALUE >= cmd.dev_id)
                    return -1;
				cmd.result    = (int *)malloc(sizeof(int));
				ret = ioctl(fd, CMDOPERATION , &cmd);

                if (-1 == ret)
                    printf("OOPS ... invalid dev_id \n\n");
				else if (EACCES == ret)
					printf("CLI is disabled.. HIGH PERF mode is defined \n\n");
				else
					if (!*(cmd.result))
	                printf("DEVICE HAS BEEN RESET\n\n");
		        else
		        printf("OOPS ... something went wrong\n\n");

	            free(cmd.result);
				return 0;

		case RESETSEC: /* RESET SEC COMMAND */
				if ((RESETVALUE >= cmd.dev_id) || (RESETVALUE >= cmd.rsrc.sec_id))
                    return -1;
				cmd.result    = (int *)malloc(sizeof(int));
				ret = ioctl(fd, CMDOPERATION , &cmd);

                if (-1 == ret)
                    printf("OOPS ... invalid dev_id/sec_id \n\n");
				else if (EACCES == ret)
					printf("CLI is disabled.. HIGH PERF mode is defined \n\n");
				else
					if (!*(cmd.result))
	                printf("SEC ENGINE HAS BEEN RESET\n\n");
		        else
		        printf("OOPS ... something went wrong\n\n");

				free(cmd.result);
                return 0;

		case RINGSTAT: /* RINGSTAT COMMAND */
				if ((RESETVALUE >= cmd.dev_id) || (RESETVALUE >= cmd.rsrc.ring_id))
			return -1;

                cmd.op_buffer = (op_buffer_t *)malloc(sizeof(op_buffer_t));
				cmd.result    = (int *)malloc(sizeof(int));
				ret = ioctl(fd, CMDOPERATION , &cmd);

                if (-1 == ret)
                    printf("OOPS ... invalid dev_id/ring_id \n\n");
				else if (EACCES == ret)
					printf("CLI is disabled.. HIGH PERF mode is defined \n\n");
				else
	                if (!*(cmd.result))
	                {
						ASSIGN32(cmd.op_buffer->ring_stat_op.tot_size, cmd.op_buffer->ring_stat_op.tot_size);
						ASSIGN32(cmd.op_buffer->ring_stat_op.depth, cmd.op_buffer->ring_stat_op.depth);
						ASSIGN32(cmd.op_buffer->ring_stat_op.priority, cmd.op_buffer->ring_stat_op.priority);
						ASSIGN32(cmd.op_buffer->ring_stat_op.affinity, cmd.op_buffer->ring_stat_op.affinity);
						ASSIGN32(cmd.op_buffer->ring_stat_op.order, cmd.op_buffer->ring_stat_op.order);
						ASSIGN32(cmd.op_buffer->ring_stat_op.free_count, cmd.op_buffer->ring_stat_op.free_count);
						ASSIGN32(cmd.op_buffer->ring_stat_op.jobs_processed, cmd.op_buffer->ring_stat_op.jobs_processed);
						ASSIGN32(cmd.op_buffer->ring_stat_op.jobs_pending, cmd.op_buffer->ring_stat_op.jobs_pending);

						printf("RING STATISTICS\n");
						printf("DEVICE ID                   :%d\n",cmd.dev_id);
						printf("RING ID                     :%d\n",cmd.rsrc.ring_id);
						printf("RING SIZE                   :%u\n",cmd.op_buffer->ring_stat_op.tot_size);
						printf("DEPTH                       :%u\n",cmd.op_buffer->ring_stat_op.depth);
		                printf("PRIORITY                    :%u\n",cmd.op_buffer->ring_stat_op.priority);
			        printf("AFFINITY                    :%u\n",cmd.op_buffer->ring_stat_op.affinity);
				printf("ORDER                       :%u\n",cmd.op_buffer->ring_stat_op.order);
						printf("FREE COUNT                  :%u\n",cmd.op_buffer->ring_stat_op.free_count);
						printf("JOBS PROCESSED              :%u\n",cmd.op_buffer->ring_stat_op.jobs_processed);
						printf("JOBS PENDING                :%u\n\n",cmd.op_buffer->ring_stat_op.jobs_pending);
		        }
		    else
			    printf("OOPS ... something went wrong\n\n");

                free(cmd.op_buffer);
				free(cmd.result);
                return 0;

		case SECSTAT: /* RINGSTAT COMMAND */
                if (RESETVALUE >= cmd.dev_id)
                    return -1;

                cmd.op_buffer = (op_buffer_t *)malloc(sizeof(op_buffer_t));
                cmd.result    = (int *)malloc(sizeof(int));
				ret = ioctl(fd, CMDOPERATION , &cmd);

                if (-1 == ret)
                    printf("OOPS ... invalid dev_id\n\n");
				else if (EACCES == ret)
					printf("CLI is disabled.. HIGH PERF mode is defined \n\n");
                else
			if (!*(cmd.result))
                    {
	                    int i=0;
						ASSIGN32(cmd.op_buffer->sec_op.sec_ver, cmd.op_buffer->sec_op.sec_ver);
						ASSIGN32(cmd.op_buffer->sec_op.no_of_sec_engines, cmd.op_buffer->sec_op.no_of_sec_engines);
						ASSIGN32(cmd.op_buffer->sec_op.no_of_sec_jr, cmd.op_buffer->sec_op.no_of_sec_jr);
                        printf("SEC STATISTICS\n");
                        printf("SEC VERSION                 :%x.%x\n",(cmd.op_buffer->sec_op.sec_ver & 0x0000ff00)>>8,
                                                                      (cmd.op_buffer->sec_op.sec_ver & 0x000000ff));
                        printf("NO OF SEC ENGINES           :%d\n",cmd.op_buffer->sec_op.no_of_sec_engines);
                        printf("NO OF SEC JOB RINGS         :%d\n",cmd.op_buffer->sec_op.no_of_sec_jr);
                        for (i=0;i<cmd.op_buffer->sec_op.no_of_sec_engines;++i)
                        {
							ASSIGN32(cmd.op_buffer->sec_op.sec[i].sec_tot_req_jobs, cmd.op_buffer->sec_op.sec[i].sec_tot_req_jobs);
							ASSIGN32(cmd.op_buffer->sec_op.sec[i].sec_tot_resp_jobs, cmd.op_buffer->sec_op.sec[i].sec_tot_resp_jobs);
				printf("SEC ID                      :%d\n",i+1);
				printf("\tSEC JOBS ADDED      :%u\n",cmd.op_buffer->sec_op.sec[i].sec_tot_req_jobs);
				printf("\tSEC JOBS PROCESSED  :%u\n",cmd.op_buffer->sec_op.sec[i].sec_tot_resp_jobs);
			}
			printf("\n");
			}
                    else
                        printf("OOPS ... something went wrong\n\n");

                free(cmd.op_buffer);
                free(cmd.result);
                return 0;

		default:
				return 0;
	}
}
