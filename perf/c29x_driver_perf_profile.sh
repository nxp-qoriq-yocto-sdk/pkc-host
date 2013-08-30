#!/bin/bash


command_str=""
ncpu=$(grep -c 'processor' /proc/cpuinfo)
test_stop=0
arch=$(uname -m)

help()
{
        echo "	          Help:"
        echo "	  =========================="
	echo "sh c29x_driver_perf_profile.sh <test_name> [ OPTION ]..."
	echo ""
	echo "Mandatory arguments."
	echo " -m  <cpu_mask>		: This enables cpu mask. Test thread will be created only those cpu, enabled by cpu_mask."
	echo " -t  <per_cpu_thread>	: This many number of test thread  will create per cpu."
	echo " -s  <time_duration> 	: The test will be running for time_duration second."
	echo " -r  <enque_request> 	: The test will enque total enque_request number of job."
	echo ""
	echo "NOTE :"
	echo "  Please note that '-s' has higer priority over '-r'. If '-s' is given then '-r' will be ignore."
	echo "  Without '-s' & '-r' , the test will run forever. Need to stop test by CTRL-C"
        echo ""
        echo "**************** Test name ****************"
        echo " RSA PUB Test		 :  RSA_PUB_OP_1K | RSA_PUB_OP_2K | RSA_PUB_OP_4K "
	echo " RSA PRV Test		 :  RSA_PRV_OP_1K | RSA_PRV_OP_2K | RSA_PRV_OP_4K "
	echo " DSA SIGN 		 :  DSA_SIGN_TEST_1K | DSA_SIGN_TEST_2K | DSA_SIGN_TEST_4K"
        echo " DSA VERIFY Test 	 :  DSA_VERIFY_TEST_1K | DSA_VERIFY_TEST_2K | DSA_VERIFY_TEST_4K"
	echo " DSA KEY GEN Test	 :  DSA_KEYGEN_TEST"
	echo " DSA SIGN VERIFY Test	 :  DSA_SIGN_VERIFY_TEST"
	echo " ECDSA KEY GEN Test	 :  ECDSA_KEYGEN_TEST"
	echo " DH KEY GEN Test	 :  DH_KEYGEN_TEST"
        echo " ECDH Test 		 :  ECDH_TEST "
	echo " ECDSA Test 		 :  ECDSA_VERIFY_TEST | ECDSA_SIGN_TEST "
    echo " ECP SIGN Test 		 :  ECP_SIGN_TEST_256 | ECP_SIGN_TEST_384 | ECP_SIGN_TEST_521 "
    echo " ECP VERIFY Test	 	:  ECP_VERIFY_TEST_256 | ECP_VERIFY_TEST_384 | ECP_VERIFY_TEST_521 "
    echo " ECPBN SIGN Test         :  ECPBN_SIGN_TEST_283 | ECPBN_SIGN_TEST_409 | ECPBN_SIGN_TEST_571 "
    echo " ECPBN VERIFY Test   :  ECPBN_VERIFY_TEST_283 | ECPBN_VERIFY_TEST_409 | ECPBN_VERIFY_TEST_571 "
	echo " DH Test		 :  DH_TEST_1K | DH_TEST_2K | DH_TEST_4K"
	echo " ECDH KEY GEN		 : ECDH_KEYGEN_P256 | ECDH_KEYGEN_P384 | ECDH_KEYGEN_P521 "
	echo " 				| ECDH_KEYGEN_B283 | ECDH_KEYGEN_B409 | ECDH_KEYGEN_B571 "
	echo ""
	echo " Example : sh c29x_driver_perf_profile.sh RSA_PUB_OP_1K -m 0x2 -t 1 -s 10 -r 100000"
	echo ""
	echo ""
	exit 2
}

prepare_command()
{
	if [ $# -le 0 ]
	then
		help
	fi
	if [ "$1" == "--help" ] || [ "$1" == "-h" ]
	then
		help
	fi
	case "$1" in
		'RSA_PUB_OP_1K');;
		'RSA_PRV_OP_1K');;
		'RSA_PUB_OP_2K');;
		'RSA_PRV_OP_2K');;
		'RSA_PUB_OP_3K');;
		'RSA_PRV_OP_3K');;
		'RSA_PUB_OP_4K');;
		'RSA_PRV_OP_4K');;
		'DSA_VERIFY_TEST_1K');;
		'DSA_SIGN_TEST_1K');;
		'DSA_VERIFY_TEST_2K');;
		'DSA_SIGN_TEST_2K');;
		'DSA_VERIFY_TEST_4K');;
		'DSA_SIGN_TEST_4K');;
		'DSA_SIGN_VERIFY_TEST');;
		'DSA_KEYGEN_TEST');;
		'ECDSA_KEYGEN_TEST');;
		'DH_KEYGEN_TEST');;
		'ECDH_TEST');;
		'ECDSA_VERIFY_TEST');;
		'ECDSA_SIGN_TEST');;
        'ECP_SIGN_TEST_256');;
        'ECP_VERIFY_TEST_256');;
        'ECP_SIGN_TEST_384');;
        'ECP_VERIFY_TEST_384');;
        'ECP_SIGN_TEST_521');;
        'ECP_VERIFY_TEST_521');;
        'ECPBN_SIGN_TEST_283');;
        'ECPBN_VERIFY_TEST_283');;
        'ECPBN_SIGN_TEST_409');;
        'ECPBN_VERIFY_TEST_409');;
        'ECPBN_SIGN_TEST_571');;
        'ECPBN_VERIFY_TEST_571');;
		'DH_TEST_1K');;
		'DH_TEST_2K');;
		'DH_TEST_4K');;
		'ECDH_KEYGEN_P256');;
		'ECDH_KEYGEN_P384');;
		'ECDH_KEYGEN_P521');;
		'ECDH_KEYGEN_B283');;
		'ECDH_KEYGEN_B409');;
		'ECDH_KEYGEN_B571');;
		*)echo "*** ERROR !! Invalid test name.";
			echo "See help for more information";
			echo ""
			echo "	Example : sh c29x_driver_perf_profile.sh --help";
			echo ""
			exit 2;;
	esac

	test_name=$1
        cpu=1
	thread=1
	if [ "$2" != "-m" ] || [ "$2" != "-t" ]
	then
		if [ "$2" == "-m" ]
                then
		        cpu=$3
		fi
		if [ "$2" == "-t" ]
                then
			thread=$3
                fi
        else
		echo "*** ERROR !! Wrong input parameter"
                echo "See help for more information"
		echo ""
		echo "	Example : sh c29x_driver_perf_profile.sh --help";
		echo ""
		exit 2
	fi
        if [ "$4" != "-m" ] || [ "$4" != "-t" ]
        then
		if [ "$4" == "-m" ]
		then
			cpu=$5
		fi
		if [ "$4" == "-t" ]
                then
			thread=$5
                fi
        else
		echo "*** ERROR !! Wrong input parameter"
                echo "See help for more information"
		echo ""
		echo "	Example : sh c29x_driver_perf_profile.sh --help";
		echo ""
		exit 2
	fi
        thread=$(printf "%d\n" $thread)
        cpu_mask=$(printf "%d\n" $cpu)
        if [ $cpu_mask -lt 1 ]
        then
                cpu_mask=2
		echo ""
		echo "*** WORNING !! Default cpu mask is setting : 0x$cpu_mask"
        fi
        max_cpu=1
	c=1
	while [ $c -le $ncpu ]
	do
		max_cpu=`expr $max_cpu \* 2`
		c=`expr $c + 1`
	done

	max_cpu=`expr $max_cpu - 1`
        if [ $cpu_mask -gt $max_cpu ]
        then
                echo "*** ERROR !! number of cpu should less than max # cpu : $ncpu"
                echo "See help for more information"
		echo ""
		echo "	Example : sh c29x_driver_perf_profile.sh --help";
		echo ""
		exit 2
        fi

	if [ $thread -gt 32 ]
	then
		echo "*** ERROR !! number of thread should less than 32"
                echo "See help for more information"
		echo ""
		echo "	Example : sh c29x_driver_perf_profile.sh --help";
		echo ""
		exit 2
	fi

	if [ $thread -eq 0 ]
	then
		echo "*** ERROR !! number of thread can't be 0"
                echo "See help for more information"
		echo ""
		echo "	Example : sh c29x_driver_perf_profile.sh --help";
		echo ""
		exit
	fi
	timer_dur=0
	req_cnt=0
	if [ "$6" == "-s" ]
	then
		timer_dur=$7
		if [ "$8" == "-r" ]
		then
			req_cnt=$9
		fi
	else
		if [ "$6" == "-r" ]
		then
			req_cnt=$7
		fi
	fi

	if [ $timer_dur -gt 2000 ]
	then
		echo "*** ERROR !! time duration should less than 2000"
                echo "See help for more information"
		echo ""
		echo "	Example : sh c29x_driver_perf_profile.sh --help";
		echo ""
		exit
	fi

	if [ "$test_name" == "DSA_KEYGEN_TEST" ] || [ "$test_name" == "ECDSA_KEYGEN_TEST" ] || [ "$test_name" == "DH_KEYGEN_TEST" ]
	then
		echo ""
		echo "!!!!! Please note, $test_name is not a performance test. So It will only run for one iteration."
		cpu_mask=1
		thread=1
		timer_dur=0
		req_cnt=1
	fi

        cpu_mask_print=$(printf "%x\n" $cpu_mask)

        command_str=$test_name" "$cpu_mask" "$thread" "$timer_dur" "$req_cnt
	echo ""
	echo "Running test [$test_name], cpu_mask [0x$cpu_mask_print], threads per cpu [$thread], time duration [$timer_dur], max enqueues [$req_cnt]"
	echo ""

}
function result
{
	per_job_us=$(printf "%.2f\n" $per_job_us)
	t_job_s=$(printf "%.2f\n" $t_job_s)
	printf "\n\n\n"
        printf "\t Test Name          		:       $1\n"
        printf "\t Host CPU Frequency 		:       $cpu_frq\n"
        printf "\t # job finished successfully 	:       $repeat\n"
        printf "\t Per job in us      		:       $per_job_us\n"
	printf "\t Total jobs in 1 sec		:	$t_job_s\n\n"

}

function control_c {
	echo " "
        echo "Test stopped by user"
        path=/sys/fsl_crypto/fsl_crypto_1/test-i
        echo "current_test_stop_request" > $path/test_name
	test_stop=1
}

perf_test()
{
	command_str=""
        prepare_command $@

        count=100000
        path=/sys/fsl_crypto/fsl_crypto_1/test-i
        echo "INVALID" > $path/res
        echo "0" > $path/perf
        echo "INVALID" > $path/test_name
        echo "$command_str" > $path/test_name

        success=($(cat $path/res))
        echo "Press CTRL C to stop the test "

	date1=$(date +"%s")
        while [ "$success" != "SUCCESS" ]
        do
               success=($(cat $path/res))
               printf "."
               trap control_c SIGINT
	       if [ $test_stop -eq 1 ]
	       then
			break
	       fi
               sleep 0.1
               [ $count -eq 0 ] && { printf "\n\nTest failed\n"; exit 2; }
               count=`expr $count - 1`
        done

	date2=$(date +"%s")
	diff=$(($date2-$date1))

	test_t=$(cat $path/perf | awk '{print($1)}')
	test_t=($(echo "0x"$test_t))
        cpu_frq=$(cat $path/perf | awk '{print($2)}')
        repeat=($(cat $path/repeat))
	total_time=$(printf "%d\n" $test_t)
	if [ $timer_dur -eq 0 ]
	then
		if [ "$arch" == "ppc" ]
		then
			total_time_us="$(mini_calc $total_time $cpu_frq)"
			per_job_us="$(mini_calc $total_time_us $repeat)"
			sec_us=1000000
			t_job_s="$(mini_calc $sec_us $per_job_us)"
		else
			total_time_us=`echo "$total_time / $cpu_frq" | bc -l`
			per_job_us=`echo "$total_time_us / $repeat" | bc -l`
			sec_us=1000000
			t_job_s=`echo "$sec_us / $per_job_us" | bc -l`
		fi
	else
		if [ "$arch" == "ppc" ]
        then
			t_job_s="$(mini_calc $repeat $timer_dur)"
			sec_us=1000000
			tot_time=`expr $timer_dur \* $sec_us`
			per_job_us="$(mini_calc $tot_time $repeat)"
		else
			t_job_s=`echo "$repeat / $timer_dur" | bc -l`
			sec_us=1000000
			per_job_us=`echo "($timer_dur * $sec_us) / $repeat" | bc -l`
		fi
	fi
			echo " "
			echo " "
			echo "Test Complete, Details below :- "
			printf "\n\t Test Time Duration : $(($diff / 60)) minutes and $(($diff % 60)) seconds"
	result $@
}


perf_test $@
#prepare_command $@
