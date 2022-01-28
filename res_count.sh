#!/bin/bash

res_dir=/home/hskim/data/sok/reassessor/result2

function run()
{
    type=$1
    tools=("ramblr" "retro_sym" "ddisasm")
    array1=("$1 FP ")
    for tool in "${tools[@]}"; do
        ret=$(grep "^$1" $res_dir/*/*/*/*/*/$tool/* | grep FP | grep -v "416.gamess\|447.dealII" | wc -l)
        #ret=$(grep "^$1" $res_dir/*/*/*/*/*/$tool/* | grep FP | wc -l)
        array1+=" $ret"
    done
    echo ${array1[@]}

    array2=("$1 FN ")
    for tool in "${tools[@]}"; do
        ret=$(grep "^$1" $res_dir/*/*/*/*/*/$tool/* | grep FN | grep -v "416.gamess\|447.dealII" | wc -l)
        #ret=$(grep "^$1" $res_dir/*/*/*/*/*/$tool/* | grep FN | wc -l)
        array2+=" $ret"
    done
    echo ${array2[@]}
    echo '-----------------------------------'
}
run "T1 "
run "T2 "
run "T3 "
run "T4 "
run "T5 "
run "T6 "
run "T7 "
run "T8 "
