#!/bin/bash

function run()
{
    type=$1
    tool=$2

    mkdir -p triage/$tool

    #Reparable FP
    grep '\[0\]' triage/$tool/x*/*pie/$type\FP.txt  | grep $tool > triage/$tool/$type\_reparable_FP.txt
    e0=$(wc -l triage/$tool/$type\_reparable_FP.txt | awk '{print $1}')

    grep -v '\[0\]' triage/$tool/x*/*pie/$type\FP.txt  | grep $tool > triage/$tool/$type\_irreparable.txt
    e1=$(wc -l triage/$tool/$type\_irreparable.txt | awk '{print $1}')

    printf "%sFP(%8s): %15s  %15s \n" $type $tool $e0 $e1
}

printf "%14s: %15s  %15s \n" "" "Reparable" "Irreparable"

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
