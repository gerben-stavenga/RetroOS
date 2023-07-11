#!/bin/sh
DIR=$1
shift 1
case "$DIR" in
"" | ".")
i686-elf-g++ -MM -MG -c "$@" | sed -e 's@^\(.*\).o:@\1.d \1.o:@g'
;;
*)
i686-elf-g++ -MM -MG -c "$@" | sed -e "s@^\(.*\).o:@$DIR\/\1.d $DIR\/\1.o:@g"
;;
esac
