#!/bin/bash
save_path="../outputs/DynBox"
analysisTime="outputs/analysis_time"
if [ ! -d $save_path ]; then
    mkdir $save_path
fi

rm $analysisTime
declare -a AppNames=("nginx" "httpd" "redis" "sqlite" "memcached" "bind" "tar")
for val in ${AppNames[@]}; do
   startTime=$(date +%s%N)
   python3.8 dynbox/buildDybBox.py -t $val
   endTime=$(date +%s%N)
   typeset ELAPSE=$((($endTime- $startTime)/1000000))
   echo "$val analysis time=${ELAPSE}ms" >> $analysisTime
done

