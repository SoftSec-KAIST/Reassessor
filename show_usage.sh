work_dir=/home/hskim/data/sok/reassessor

echo "python3 collect_loc_candidates.py /data2/benchmark $work_dir/func"

echo "python3 merge.py $work_dir/func  $work_dir/func/func_list.json"

echo "python3 match_src_to_bin.py /data2/benchmark $work_dir/func/func_list.json $work_dir/match"

echo "python3 multi.py /data2/benchmark $work_dir/match $work_dir/composite_ms /home/hskim/data/sok/reassem/result  $work_dir/pickles"

echo "python3 get_nofunc.py /data2/benchmark $work_dir/func/func_list.json $work_dir/nofunc"
work_dir=/home/hskim/data/sok/reassessor

#echo "python3 run_exp.py /data2/benchmark $work_dir/pickles $work_dir/result"

echo "python3 run_exp_pr.py /data2/benchmark $work_dir/pickles $work_dir/result $work_dir/probability $work_dir/prob_json"

#error probabilities
echo "python3 res_pr.py /data2/benchmark $work_dir/probability"

#disassem type
echo "python3 run_disasm_type_count.py /data2/benchmark $work_dir/pickles $work_dir/evaluation"

echo "python3 run_error_count.py /data2/benchmark $work_dir/result $work_dir/evaluation"


#----------------

echo "python3 res_pr_count.py /data2/benchmark $work_dir/evaluation"

echo "python3 res_error_count.py /data2/benchmark $work_dir/evaluation"

echo "python3 res_disasm_count.py /data2/benchmark $work_dir/evaluation"

echo "python3 res_type_count.py /data2/benchmark $work_dir/evaluation"

echo "python3 res_pickle_count.py /data2/benchmark $work_dir/pickles"

#python3 check_nofunc.py /data2/benchmark $work_Dir/nofunc

echo "python3 composite.py /data2/benchmark $work_dir/pickles $work_dir/triage3"
echo "python3 res_composite.py /data2/benchmark $work_dir/triage3"

echo "python3 run_disasm.py /data2/benchmark $work_dir/pickles $work_dir/nofunc $work_dir/disasm"
echo "python3 res_disasm_err.py /data2/benchmark $work_dir/disasm"


