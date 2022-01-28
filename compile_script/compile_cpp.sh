#!/bin/bash

function run()
{
    src=$1
    dst=$2
    work=$(dirname $dst)
    mkdir -p $work
    if [[ $src == *"nopie"* ]]; then
        PIE="-no-pie -fno-pie"
    else
        PIE="-pie -fpie"
    fi

    if [[ $src == *"x86"* ]]; then
        ARCH="-m32"
        COPT="/usr/lib/i386-linux-gnu/libstdc++.so.6 /lib/i386-linux-gnu/libm.so.6 /lib/i386-linux-gnu/libgcc_s.so.1"
    else
        ARCH=""
        COPT="/usr/lib/x86_64-linux-gnu/libstdc++.so.6  /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/libgcc_s.so.1 "
    fi
    if [[ $src == *"icc"* ]]; then
        COMP=/opt/intel/oneapi/compiler/2021.3.0/linux/bin/intel64/icpc
    else
        COMP=g++
    fi




    filesize=$(stat -c%s "$src")

    touch $dst
    if (( filesize < 100 )); then
        echo "$src is empty"
    else
        echo "$COMP $src -o $dst $PIE $ARCH -ldl $COPT"
        $COMP $src -o $dst $PIE $ARCH -ldl $COPT
    fi
    touch $dst
}
run $1 $2
