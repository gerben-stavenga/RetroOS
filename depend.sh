#!/bin/sh
CC=$1
DIR=$2
shift 2
case "$DIR" in
"" | ".")
$CC -MM -MG -c "$@" | sed -e 's@^\(.*\).o:@\1.d \1.o:@g'
;;
*)
$CC -MM -MG -c "$@" | sed -e "s@^\(.*\).o:@$DIR\/\1.d $DIR\/\1.o:@g"
;;
esac
