#!/bin/sh

timeout=120
check_capture_file_function()
{
    file_path="$1"
    file_size=0
    current_time=$(date "+%s")
    timeout_time=$(($current_time + $timeout))
    match_cnt=0
 
    while true; do
        current_time=$(date "+%s")
        if [ $current_time -gt $timeout_time ]; then
            echo "timeout"
            return
        fi

        if [ ! -e $file_path ]; then
            sleep 1
            continue
        fi
 
        current_file_size=$(wc -c $file_path | awk '{print $1}')
        #echo "current file_size: $current_file_size file_size: $file_size"
        if [ $file_size -ne $current_file_size ]; then
            match_cnt=0
            file_size=$current_file_size
            sleep 1
            continue
        fi

        match_cnt=$(($match_cnt + 1))
        #echo "match_cnt: $match_cnt"

        if [ $match_cnt -eq 3 ]; then
            echo 'done'
            return
        fi
 
    done
}

case "$1" in
    check_capture_file)
        check_capture_file_function "$2"
        ;;
    *)
        echo "Usage:"
        echo "$0 {check_capture_file} {file_path}"
esac
