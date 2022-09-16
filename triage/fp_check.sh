#!/bin/bash

function run()
{
    type=$1
    tool=$2
    #Safe
    e0=$(grep '\[0\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)
    #FN
    #e1=$(grep '\[1\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)
    #Classic FP
    #e2=$(grep '\[2\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)

    #LABEL_UNDEF
    #e3=$(grep '\[3\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)
    #LABEL_DUP
    #e4=$(grep '\[4\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)
    #LABEL_SEMANTICS
    e5=$(grep '\[5\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)
    #DIFF_ADDRS
    e6=$(grep '\[6\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)
    #DIFF_BASES
    e9=$(grep '\[9\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)

    #DIFF_SECTIONS
    e7=$(grep '\[7\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)
    #CODE_REGION
    e8=$(grep '\[8\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)


    #FIXED_ADDR
    #e10=$(grep '\[10\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)
    e10=$(grep '\[10\]' x*/*pie/$type\FN.txt  | grep $tool | wc -l)

    #SEC_OUTSIDE
    e11=$(grep '\[11\]' x*/*pie/$type\FP.txt  | grep $tool | wc -l)

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

run "E1" "retro"
run "E2" "retro"
run "E3" "retro"
run "E4" "retro"
run "E5" "retro"
run "E6" "retro"
run "E7" "retro"

run "E1" "ddisasm"
run "E2" "ddisasm"
run "E3" "ddisasm"
run "E4" "ddisasm"
run "E5" "ddisasm"
run "E6" "ddisasm"
run "E7" "ddisasm"
