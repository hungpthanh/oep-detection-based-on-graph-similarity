#!/bin/bash
filename=$1
n=1
while read line; do
# reading each line
command="java -jar be-pum-V2.jar asm/testcase/$line"
timeout 30m $command
#command
done < $filename