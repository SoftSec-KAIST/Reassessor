#!/bin/bash

function e7_pie_x64()
{
    tot=$(ls ./dataset/*/x64/*/pie/*/reloc/* | wc -l | awk '{print $1}')

    awk -F':' '{print $1}' triage/*/x64/pie/E7*.txt | sed "s/errors.*//g" | sort -u > e7_error.txt
    bin=$(wc -l e7_error.txt | awk '{print $1}')

    echo "Reassemblers fails on symbolizing Type 7 when they reassemble $bin/$tot binaries"
}
e7_pie_x64
