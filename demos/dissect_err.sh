#!/bin/bash

function atom_fn()
{
    tot=$(ls ./output/*/*/*/*/*/*/reassem/*.s | wc -l | awk '{print $1}')

    grep FN triage/*/x*/*/E1FN.txt | awk -F':' '{print $2}' | sort -u > atom_fn.txt
    grep FN triage/*/x*/*/E3FN.txt | awk -F':' '{print $2}' | sort -u >> atom_fn.txt
    grep FN triage/*/x*/*/E5FN.txt | awk -F':' '{print $2}' | sort -u >> atom_fn.txt
    cases=$(wc -l atom_fn.txt | awk '{print $1}')

    sort -u atom_fn.txt > atom_fn_sorted.txt
    reassem=$(wc -l atom_fn_sorted.txt | awk '{print $1}')

    printf "Number of reassembly file that have E1/E2/E3 FNs %s/%s\n" $reassem $tot
}
function atom_fp()
{
    tot=$(ls ./output/*/*/*/*/*/*/reassem/*.s | wc -l | awk '{print $1}')

    grep ":2:" triage/*/x*/*/E1FP.txt | awk -F':' '{print $2}' | sort -u > atom_fp.txt
    grep ":4:" triage/*/x*/*/E3FP.txt | awk -F':' '{print $2}' | sort -u >> atom_fp.txt
    grep ":6:" triage/*/x*/*/E5FP.txt | awk -F':' '{print $2}' | sort -u >> atom_fp.txt
    cases=$(wc -l atom_fp.txt | awk '{print $1}')

    sort -u atom_fp.txt > atom_fp_sorted.txt
    reassem=$(wc -l atom_fp_sorted.txt | awk '{print $1}')

    printf "Number of reassembly file that have E1/E2/E3 FPs %s/%s\n" $reassem $tot
}
function label_err()
{
    tot=$(ls ./output/*/*/*/*/*/*/reassem/*.s | wc -l | awk '{print $1}')

    grep "(ADDR:" triage/*/x*/*/E*FP.txt | awk -F':' '{print $2}' | sort -u > label_fp.txt
    case=$(wc -l label_fp.txt | awk '{print $1}')

    sort -u label_fp.txt > label_fp_sorted.txt
    reassem=$(wc -l label_fp_sorted.txt | awk '{print $1}')

    printf "Number of reassembly file that have wrong labels %s/%s\n" $reassem $tot
}

atom_fn
atom_fp
label_err

