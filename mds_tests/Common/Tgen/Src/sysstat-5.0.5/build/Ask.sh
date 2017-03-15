#!/bin/sh
#
# Ask a question and return the answer

QUESTION=$1
DEFAULT=$2
TEXT_FILE=$3
while :; do
	echo -n "${QUESTION} [${DEFAULT}] " >/dev/tty
	read ANSWER
	if [ "${ANSWER}" = "" ]; then
		echo ${DEFAULT}
		break
	elif [ "${ANSWER}" = "?" ]; then
		cat build/.text/${TEXT_FILE} >/dev/tty
	else
		echo ${ANSWER}
		break
	fi
done

