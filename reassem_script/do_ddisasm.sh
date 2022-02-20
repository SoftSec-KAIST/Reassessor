#!/bin/bash
in_dir=/data2/benchmark
in_dir=$1
out_dir=/home/hskim/data/sok/reassem/result
out_dir=$2
tool=ddisasm
run(){
    #echo $dir
    #mkdir -p $dir
    #touch $dst
    echo "docker run --rm -v $in_dir/:/input -v $out_dir/:/output grammatech/ddisasm:1.5.2 sh -c \"ddisasm /input/$1 --asm /output/ddisasm/$3.s\" "
    #docker run --rm -v $in_dir/:/input -v $out_dir/:/output grammatech/ddisasm:1.5.2 sh -c "ddisasm /input/$1 --asm /output/$2.s"
}
run $3
