#!/bin/bash

calc(){ awk "BEGIN { print "$*" }"; }

function atomic_fn()
{
    tot=$(ls ./output/*/*/*/*/*/*/reassem/*.s | wc -l | awk '{print $1}')

    grep FN triage/*/x*/*/E1FN.txt | sed "s/.*FN.txt://g" > atomic_fn_cases.txt
    grep FN triage/*/x*/*/E3FN.txt | sed "s/.*FN.txt://g">> atomic_fn_cases.txt
    grep FN triage/*/x*/*/E5FN.txt | sed "s/.*FN.txt://g">> atomic_fn_cases.txt

    grep FN triage/*/x*/*/E1FN.txt | awk -F':' '{print $2}' | sort -u > atomic_fn.txt
    grep FN triage/*/x*/*/E3FN.txt | awk -F':' '{print $2}' | sort -u >> atomic_fn.txt
    grep FN triage/*/x*/*/E5FN.txt | awk -F':' '{print $2}' | sort -u >> atomic_fn.txt
    cases=$(wc -l atomic_fn.txt | awk '{print $1}')

    sort -u atomic_fn.txt > atomic_fn_sorted.txt
    reassem=$(wc -l atomic_fn_sorted.txt | awk '{print $1}')
    result=$(calc $(($reassem))/$(($tot))*100)
    printf "Number of reassembly file that have E1/E2/E3 FNs %s %% (%s/%s)\n" $result $reassem $tot
}
function atomic_fp()
{
    tot=$(ls ./output/*/*/*/*/*/*/reassem/*.s | wc -l | awk '{print $1}')

    grep ":2:" triage/*/x*/*/E1FP.txt | sed "s/.*FP.txt://g" > atomic_fp_cases.txt
    grep ":4:" triage/*/x*/*/E3FP.txt | sed "s/.*FP.txt://g">> atomic_fp_cases.txt
    grep ":6:" triage/*/x*/*/E5FP.txt | sed "s/.*FP.txt://g">> atomic_fp_cases.txt

    grep ":2:" triage/*/x*/*/E1FP.txt | awk -F':' '{print $2}' | sort -u > atomic_fp.txt
    grep ":4:" triage/*/x*/*/E3FP.txt | awk -F':' '{print $2}' | sort -u >> atomic_fp.txt
    grep ":6:" triage/*/x*/*/E5FP.txt | awk -F':' '{print $2}' | sort -u >> atomic_fp.txt
    cases=$(wc -l atomic_fp.txt | awk '{print $1}')

    sort -u atomic_fp.txt > atomic_fp_sorted.txt
    reassem=$(wc -l atomic_fp_sorted.txt | awk '{print $1}')

    result=$(calc $(($reassem))/$(($tot))*100)
    printf "Number of reassembly file that have E1/E2/E3 FPs %s %% (%s/%s)\n" $result $reassem $tot
}
function label_err_fp()
{
    tot=$(ls ./output/*/*/*/*/*/*/reassem/*.s | wc -l | awk '{print $1}')

    grep "(ADDR:" triage/*/x*/*/E*FP.txt | sed "s/.*FP.txt://g" > label_err_fp_cases.txt

    grep "(ADDR:" triage/*/x*/*/E*FP.txt | awk -F':' '{print $2}' | sort -u > label_err_fp.txt
    case=$(wc -l label_err_fp.txt | awk '{print $1}')

    sort -u label_err_fp.txt > label_err_fp_sorted.txt
    reassem=$(wc -l label_err_fp_sorted.txt | awk '{print $1}')

    result=$(calc $(($reassem))/$(($tot))*100)
    printf "Number of reassembly file that have wrong labels %s %% (%s/%s)\n" $result $reassem $tot
}

atomic_fn
atomic_fp
label_err_fp
