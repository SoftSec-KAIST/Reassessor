#!/bin/bash

function run()
{
    src=$1
    dst=$2
    work=$(dirname $dst)
    name=$(basename $2)
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
    if [[ $name == "sort" ]]; then
        COPT="-lpthread"
    fi
    if [[ $name == "timeout" ]]; then
        COPT="-lrt -lpthread"
    fi
    if [[ $name == *"400"* ]]; then
        COPT="/lib32/libm.so.6"
    fi
    if [[ $name == *"433"* ]]; then
        COPT="/lib32/libm.so.6"
    fi
    if [[ $name == *"435"* ]]; then
        COPT="/lib32/libm.so.6"
    fi
    if [[ $name == *"445"* ]]; then
        COPT="/lib32/libm.so.6"
    fi
    if [[ $name == *"456"* ]]; then
        COPT="/lib32/libm.so.6"
    fi
    if [[ $name == *"462"* ]]; then
        COPT="/lib32/libm.so.6"
    fi
    if [[ $name == *"464"* ]]; then
        COPT="/lib32/libm.so.6"
    fi
    if [[ $name == *"470"* ]]; then
        COPT="/lib32/libm.so.6"
    fi
    if [[ $name == *"482"* ]]; then
        COPT="/lib32/libm.so.6"
    fi


    filesize=$(stat -c%s "$src")

    touch $dst
    if (( filesize < 100 )); then
        echo "$src is empty"
    else
        if [ -z "$COPT" ]; then
            #echo "$src is out of interest"
            echo "$COMP $src -o $dst $PIE $ARCH -ldl"
            $COMP $src -o $dst $PIE $ARCH -ldl
        else
            #echo "$src is out of interest"
            echo "$COMP $src -o $dst $PIE $ARCH -ldl $COPT"
            $COMP $src -o $dst $PIE $ARCH -ldl $COPT
        fi
    fi
}
run $1 $2
