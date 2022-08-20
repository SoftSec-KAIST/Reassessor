#!/bin/bash

function classify
{
    error_type=$1
    arch=$2
    pie_option=$3
    mkdir -p $arch/$pie_option
    echo "grep '^$error_type' /data3/1_reassessor/result/*/*/$arch/*/$pie_option/*/*/diff/error_ascii.txt > $arch/$pie_option/$error_type.txt &"
    #grep '^$error_type' ../../new_result4/*/$arch/*/$pie_option/*/*/error_ascii/* > $arch/$pie_option/$error_type.txt &

}
ARCHS=( x86 x64 )
PIES=( pie nopie )
for i in $(seq 1 1 8); do
    for ARCH in "${ARCHS[@]}"; do
        for PIE in "${PIES[@]}"; do
            #echo classify E$i\FN $ARCH $PIE
            classify E$i\FN $ARCH $PIE
            classify E$i\FP $ARCH $PIE
        done
    done
done
