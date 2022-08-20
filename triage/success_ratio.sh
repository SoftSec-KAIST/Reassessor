#!/bin/bash

gt="/data3/1_reassessor/benchmark"
ramblr="/data3/1_reassessor/dataset/ramblr"
retro="/data3/1_reassessor/dataset/retrowrite"
ddisasm="/data3/1_reassessor/dataset/ddisasm"

function run()
{
    subdir=$1

    totB=$(ls $gt/$subdir/bin/*             | wc -l)

    ramblrR=$(ls $ramblr/$subdir/ramblr/*.s    | wc -l)
    ramblrC=$(ls $ramblr/$subdir/ramblr/bin/*    | wc -l)

    retroR=$(ls $retro/$subdir/retro_sym/*.s  | wc -l)
    retroC=$(ls $retro/$subdir/retro_sym/bin/*  | wc -l)

    ddisasmR=$(ls $ddisasm/$subdir/ddisasm/*.s  | wc -l)
    ddisasmC=$(ls $ddisasm/$subdir/ddisasm/bin/*  | wc -l)

    printf "%12s  %5s  %5s %5s  %5s %5s  %5s %5s \n" $subdir $totB $ramblrR $ramblrC $retroR $retroC $ddisasmR $ddisasmC

}

run "c*/*/g*/*/*"
run "b*/*/g*/*/*"
run "s*/*/g*/*/*"

run "c*/*/c*/*/*"
run "b*/*/c*/*/*"
run "s*/*/c*/*/*"

run "*/*/*/*/*"
