grep FN triage/*/x*/*/E1FN.txt | awk -F':' '{print $2}' | sort -u > atom_fn.txt
grep FN triage/*/x*/*/E3FN.txt | awk -F':' '{print $2}' | sort -u >> atom_fn.txt
grep FN triage/*/x*/*/E5FN.txt | awk -F':' '{print $2}' | sort -u >> atom_fn.txt
cases=$(wc -l atom_fn.txt | awk '{print $1}')

sort -u atom_fn.txt > atom_fn_sorted.txt
reassem=$(wc -l atom_fn_sorted.txt | awk '{print $1}')

printf "Number of reassembly file that have E1/E2/E3 FNs %s\n" $reassem


