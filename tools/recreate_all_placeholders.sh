#!/bin/bash

if [ "$#" -ne 2 ]; then
	>&2 echo "usage: $0 NS ACCOUNT"
	exit 1
fi

NS=$1
ACCOUNT=$2

echo "" > /tmp/empty;

openio container list --oio-ns ${NS} --oio-account ${ACCOUNT} -c Name -f value \
	| while read line ; do
		# Check if it isn't a bucket
		if [[ ${line} = *'%2F'* ]]; then
			# Check if the container exists
			container=${line%\%2F*}; openio container show ${container} --oio-ns ${NS} --oio-account ${ACCOUNT} &> /dev/null
			if [ $? -eq 0 ]; then
				echo "object create '${line%\%2F*}' /tmp/empty --name '${line##*%2F}/'"
			fi;
		fi;
	done \
	| openio --oio-ns ${NS} --oio-account ${ACCOUNT}

rm /tmp/empty
