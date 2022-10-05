tot=$(ls ./output/*/*/*/*/*/*/reassem/*.s | wc -l | awk '{print $1}')

grep ":2:" triage/*/x*/*/E1FP.txt | awk -F':' '{print $2}' | sort -u > atom_fp.txt
grep ":4:" triage/*/x*/*/E3FP.txt | awk -F':' '{print $2}' | sort -u >> atom_fp.txt
grep ":6:" triage/*/x*/*/E5FP.txt | awk -F':' '{print $2}' | sort -u >> atom_fp.txt
cases=$(wc -l atom_fp.txt | awk '{print $1}')

sort -u atom_fp.txt > atom_fp_sorted.txt
reassem=$(wc -l atom_fp_sorted.txt | awk '{print $1}')


printf "Number of reassembly file that have E1/E2/E3 FPs %s/%s\n" $reassem $tot



