#!/bin/bash

if [ $# -ne 2 ]
then
	echo "Usage : bash $0 <SERVER_START_PORT> <SERVER_END_PORT>"
	exit
fi

re='^[0-9]+$'

for num in $@
do
	if ! [[ $num =~ $re ]] ; then
   		echo "error: Not a number $num"
		exit
	fi
done
declare -A Cache_Control_list
Cache_Control_list=( [0]="no-store" [1]="no-cache" [2]="s-maxage=60, proxy-validate")
# Cache_Control_list=( [0]="s-maxage=60, proxy-validate")

# Cache_Control_list = {0:"no-store", 1:"no-cache", 2:"s-maxage=60, proxy-validate"}
for i in $(seq $1 $2)
do

  idx=$(( $RANDOM % 3 ))
  # idx=0
  # echo $idx
  # idx=$(idx % 3)
  # echo $idx
  option="${Cache_Control_list[$idx]}"
  echo $option
	screen -dm python server.py $i $option
done
