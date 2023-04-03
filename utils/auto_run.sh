#!/bin/bash
filename='data/demo.txt'
n=1
while read line; do
# reading each line
command="java -jar be-pum-V2.jar asm/testcase/$line"
echo $command
#command
done < $filename