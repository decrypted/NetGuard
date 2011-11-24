#!/bin/sh
LOCK="/tmp/lock.snmpmon"

umask 0

#TODO lockfile
#if lockfile -! -l 259200 -r 0 "$LOCK"; then
#    echo "not able to get a lock $?" | mail -s "command failed" root
#    exit 1
#fi

trap "rm -f $LOCK" exit
trap "rm -f $LOCK" SIGINT

OPTIONS=""
FILES=./switches/*
for SWITCH in $FILES
do
    SWITCH="${SWITCH##*/}"
    #echo $SWITCH
    ./snmpmon_host.sh $SWITCH
done
