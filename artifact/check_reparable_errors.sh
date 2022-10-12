#!/bin/bash

total=0
reparable=0

calc(){ awk "BEGIN { print "$*" }"; }
function run()
{
    type=$1
    tool=$2

    mkdir -p triage/$tool

    #Reparable FP
    grep '\[0\]' triage/$tool/x*/*pie/$type\FP.txt  | sed "s/.*FP.txt://g" > triage/$tool/$type\_reparable_errors.txt
    e0=$(wc -l triage/$tool/$type\_reparable_errors.txt | awk '{print $1}')

    grep -v '\[0\]' triage/$tool/x*/*pie/$type\FP.txt  | sed "s/.*FP.txt://g"  > triage/$tool/$type\_irreparable_errors.txt
    grep '\[.*\]' triage/$tool/x*/*pie/$type\FN.txt   | sed "s/.*FN.txt://g" >> triage/$tool/$type\_irreparable_errors.txt
    e1=$(wc -l triage/$tool/$type\_irreparable_errors.txt | awk '{print $1}')

    cat triage/$tool/$type\_reparable_errors.txt  >> reparable_errors.txt
    cat triage/$tool/$type\_irreparable_errors.txt  >> irreparable_errors.txt

    printf "%sFP(%10s): %15s  %15s \n" $type $tool $e0 $e1

    total=$total+$e0+$e1
    reparable=$reparable+$e0
}
truncate -s 0 reparable_errors.txt
truncate -s 0 irreparable_errors.txt

printf "%16s: %15s  %15s \n" "" "Reparable" "Irreparable"

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

x=$(calc $reparable)
y=$(calc $total)
result=$(calc $x/$y*100)
printf "%s %6.3f%% (%d/%d) symbolization errors are reparable\n" "Total" $result $x $y

