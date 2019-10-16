#!/bin/bash

if [ $# -ne 2 ]
then
	echo "Usage : bash $0 <Client_START_PORT> <CLIENT_END_PORT>"
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
#
idx=0
for i in $(seq $1 $2)
do
  base_port=20101
  server_port=$(($base_port+$idx))
  echo $server_port
  echo "python2 client.py $i 20100 $server_port"
	screen -dm python2 client.py $i 20100 $server_port
  # idx=$(($idx+1))
done
