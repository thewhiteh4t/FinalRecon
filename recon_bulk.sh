#!/bin/bash

oldIFS=$IFS
IFS=$'\n'
while IFS='' read -r line || [[-n "$line" ]];
do 
	domain=$line
	python3 finalrecon.py --headers https://$domain -o csv
IFS=$oldIFS
done < "$1"

