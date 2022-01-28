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
    else
        ARCH=""
    fi
    if [[ $src == *"icc"* ]]; then
        COMP=/opt/intel/oneapi/compiler/2021.3.0/linux/bin/intel64/ifort
        FOPT="-nofor-main"
    else
        COMP=gfortran
        FOPT=""
    fi

    filesize=$(stat -c%s "$src")

    touch $dst
    if (( filesize < 100 )); then
        echo "$src is empty"
    else
        echo "$COMP $src -o $dst $PIE $ARCH -ldl $FOPT"
        $COMP $src -o $dst $PIE $ARCH -ldl $FOPT
    fi
}
run $1 $2
