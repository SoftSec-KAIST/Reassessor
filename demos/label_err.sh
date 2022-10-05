#grep ":3)" x*/*/E*FP.txt | awk -F':' '{print $2}' | sort -u > label_fp.txt
grep "(ADDR:" triage/*/x*/*/E*FP.txt | awk -F':' '{print $2}' | sort -u > label_fp.txt
case=$(wc -l label_fp.txt | awk '{print $1}')

sort -u label_fp.txt > label_fp_sorted.txt
reassem=$(wc -l label_fp_sorted.txt | awk '{print $1}')

printf "Number of reassembly file that have wrong labels %s\n" $reassem




