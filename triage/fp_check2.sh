#!/bin/bash

function run()
{
    type=$1
    tool=$2

    mkdir -p error_types/$tool

    #Safe
    grep '\[0\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_safe &

    #CLASSIC_FP
    grep '\[2\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_classic_fp &
    #LABEL_UNDEF
    grep '\[3\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_undef_label &
    #LABEL_DUP
    grep '\[4\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_dup_label &


    #LABEL_SEMANTICS
    grep '\[5\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_semantics &
    #DIFF_ADDRS
    grep '\[6\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_diff_addrs &
    #DIFF_BASES
    grep '\[9\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_diff_type7 &

    #DIFF_SECTIONS
    grep '\[7\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_diff_sections &
    #CODE_REGION
    grep '\[8\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_code_region &


    #FIXED_ADDR
    grep '\[10\]' x*/*pie/$type\FN.txt  | grep $tool > error_types/$tool/$type\_fixed_addr &

    #SEC_OUTSIDE
    grep '\[11\]' x*/*pie/$type\FP.txt  | grep $tool > error_types/$tool/$type\_outside &

}

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
