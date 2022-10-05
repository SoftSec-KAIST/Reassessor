#!/bin/bash

function run()
{
    type=$1
    tool=$2

    mkdir -p triage/$tool

    #Safe
    grep '\[0\]' triage/$tool/x*/*pie/$type\FP.txt  | grep $tool > triage/$tool/$type\_safe.txt
    e0=$(wc -l triage/$tool/$type\_safe.txt | awk '{print $1}')

    #LABEL_SEMANTICS
    grep '\[5\]' triage/$tool/x*/*pie/$type\FP.txt  | grep $tool > triage/$tool/$type\_semantics.txt
    e5=$(wc -l triage/$tool/$type\_semantics.txt | awk '{print $1}')
    #DIFF_ADDRS
    grep '\[6\]' triage/$tool/x*/*pie/$type\FP.txt  | grep $tool > triage/$tool/$type\_diff_addrs.txt
    e6=$(wc -l triage/$tool/$type\_diff_addrs.txt | awk '{print $1}')
    #DIFF_BASES
    grep '\[9\]' triage/$tool/x*/*pie/$type\FP.txt  | grep $tool > triage/$tool/$type\_diff_type7.txt
    e9=$(wc -l triage/$tool/$type\_diff_type7.txt | awk '{print $1}')

    #DIFF_SECTIONS
    grep '\[7\]' triage/$tool/x*/*pie/$type\FP.txt  | grep $tool > triage/$tool/$type\_diff_sections.txt
    e7=$(wc -l triage/$tool/$type\_diff_sections.txt | awk '{print $1}')
    #CODE_REGION
    grep '\[8\]' triage/$tool/x*/*pie/$type\FP.txt  | grep $tool > triage/$tool/$type\_code_region.txt
    e8=$(wc -l triage/$tool/$type\_code_region.txt | awk '{print $1}')


    #FIXED_ADDR
    grep '\[10\]' triage/$tool/x*/*pie/$type\FN.txt  | grep $tool > triage/$tool/$type\_fixed_addr.txt
    e10=$(wc -l triage/$tool/$type\_fixed_addr.txt | awk '{print $1}')

    #SEC_OUTSIDE
    grep '\[11\]' triage/$tool/x*/*pie/$type\FP.txt  | grep $tool > triage/$tool/$type\_outside.txt
    e11=$(wc -l triage/$tool/$type\_outside.txt | awk '{print $1}')

    printf "%sFP(%8s): %10s | %10s %10s %10s | %10s %10s | %10s || %10s\n" $type $tool $e0 $e5 $e6 $e9 $e7 $e11 $e8 $e10
}

printf "%14s: %10s | %10s %10s %10s | %10s %10s | %10s || %10s \n" "" "Safe" "Semantics" "Addrs" "Type7" "Diff_Sec" "Outside" "Code_Reg" "fixed_addr"

run "E1" "ramblr"
run "E2" "ramblr"
run "E3" "ramblr"
run "E4" "ramblr"
run "E5" "ramblr"
run "E6" "ramblr"
run "E7" "ramblr"

run "E1" "retrowrite"
run "E2" "retrowrite"
run "E3" "retrowrite"
run "E4" "retrowrite"
run "E5" "retrowrite"
run "E6" "retrowrite"
run "E7" "retrowrite"

run "E1" "ddisasm"
run "E2" "ddisasm"
run "E3" "ddisasm"
run "E4" "ddisasm"
run "E5" "ddisasm"
run "E6" "ddisasm"
run "E7" "ddisasm"
