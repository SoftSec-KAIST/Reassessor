#!/bin/bash

function run()
{
    src=$1
    dst=$2
    work=$(dirname $dst)
    name=$(basename $2)
    echo "mkdir -p $work"
    mkdir -p $work
    if [[ $src == *"nopie"* ]]; then
        PIE="-no-pie -fno-pie"
    else
        PIE="-pie -fpie"
    fi

    if [[ $src == *"x86"* ]]; then
        ARCH="-m32"
    else
        ARCH=""
    fi
    if [[ $src == *"icc"* ]]; then
        COMP=/opt/intel/oneapi/compiler/2021.3.0/linux/bin/intel64/icc
    else
        COMP=gcc
    fi

    COPT=""
    if [[ $name == "chcon" || $name == "cp" || $name == "ginstall" || $name == "id" || $name == "mkdir" || $name == "mkfifo" || $name == "mknod" || $name == "mv" || $name == "runcon" || $name == "stat" ]]; then
        COPT="/lib/x86_64-linux-gnu/libselinux.so.1"
    fi
    if [[ $name == "dir" ]]; then
        COPT="/lib/x86_64-linux-gnu/libcap.so.2 /lib/x86_64-linux-gnu/libselinux.so.1"
    fi
    if [[ $name == "expr" ]]; then
        COPT="/usr/lib/x86_64-linux-gnu/libgmp.so.10"
    fi
    if [[ $name == "factor" ]]; then
        COPT="/usr/lib/x86_64-linux-gnu/libgmp.so.10"
    fi
    if [[ $name == "ls" ]]; then
        COPT="/lib/x86_64-linux-gnu/libcap.so.2 /lib/x86_64-linux-gnu/libselinux.so.1"
    fi
    if [[ $name == "sort" ]]; then
        COPT="-lpthread"
    fi
    if [[ $name == "timeout" ]]; then
        COPT="-lrt -lpthread"
    fi
    if [[ $name == "vdir" ]]; then
        COPT="/lib/x86_64-linux-gnu/libcap.so.2 /lib/x86_64-linux-gnu/libselinux.so.1"
    fi
    if [[ $name == *"400"* ]]; then
        COPT="/lib/x86_64-linux-gnu/libm.so.6  /lib/x86_64-linux-gnu/libc.so.6  /lib64/ld-linux-x86-64.so.2"
    fi
    if [[ $name == *"433"* ]]; then
        COPT="/lib/x86_64-linux-gnu/libm.so.6  /lib/x86_64-linux-gnu/libc.so.6  /lib64/ld-linux-x86-64.so.2"
    fi
    if [[ $name == *"435"* ]]; then
        COPT="/lib/x86_64-linux-gnu/libm.so.6  /lib/x86_64-linux-gnu/libc.so.6  /lib64/ld-linux-x86-64.so.2"
    fi
    if [[ $name == *"445"* ]]; then
        COPT="/lib/x86_64-linux-gnu/libm.so.6  /lib/x86_64-linux-gnu/libc.so.6  /lib64/ld-linux-x86-64.so.2"
    fi
    if [[ $name == *"456"* ]]; then
        COPT="/lib/x86_64-linux-gnu/libm.so.6  /lib/x86_64-linux-gnu/libc.so.6  /lib64/ld-linux-x86-64.so.2"
    fi
    if [[ $name == *"462"* ]]; then
        COPT="/lib/x86_64-linux-gnu/libm.so.6  /lib/x86_64-linux-gnu/libc.so.6  /lib64/ld-linux-x86-64.so.2"
    fi
    if [[ $name == *"464"* ]]; then
        COPT="/lib/x86_64-linux-gnu/libm.so.6  /lib/x86_64-linux-gnu/libc.so.6  /lib64/ld-linux-x86-64.so.2"
    fi
    if [[ $name == *"470"* ]]; then
        COPT="/lib/x86_64-linux-gnu/libm.so.6  /lib/x86_64-linux-gnu/libc.so.6  /lib64/ld-linux-x86-64.so.2"
    fi
    if [[ $name == *"482"* ]]; then
        COPT="/lib/x86_64-linux-gnu/libm.so.6  /lib/x86_64-linux-gnu/libc.so.6  /lib64/ld-linux-x86-64.so.2"
    fi



    touch $dst
    filesize=$(stat -c%s "$src")

    if (( filesize < 100 )); then
        echo "$src is empty"
    else
        if [ -z "$COPT" ]; then
            #echo "$src is out of interest"
            echo "$COMP $src -o $dst $PIE $ARCH -ldl $COPT"
            $COMP $src -o $dst $PIE $ARCH -ldl $COPT
        else
            #echo "$src is out of interest"
            echo "$COMP $src -o $dst $PIE $ARCH -ldl $COPT"
            $COMP $src -o $dst $PIE $ARCH -ldl $COPT
        fi
    fi
}
run $1 $2
