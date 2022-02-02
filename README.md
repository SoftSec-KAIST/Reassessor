# reassessor
Symbol Error Detector

# 1. preprocessing

python3 collect\_loc\_candidates.py /data2/benchmark /home/hskim/data/sok/reassessor/func

python3 merge.py /home/hskim/data/sok/reassessor/func  /home/hskim/data/sok/reassessor/func/func\_list.json

python3 match\_src\_to\_bin.py /data2/benchmark /home/hskim/data/sok/reassessor/func/func\_list.json /home/hskim/data/sok/reassessor/match



# 2. pickle

python3 multi.py /data2/benchmark /home/hskim/data/sok/reassessor/match /home/hskim/data/sok/reassessor/composite\_ms /home/hskim/data/sok/reassem/result  /home/hskim/data/sok/reassessor/pickles

python3 run\_exp\_pr.py /data2/benchmark /home/hskim/data/sok/reassessor/pickles /home/hskim/data/sok/reassessor/result /home/hskim/data/sok/reassessor/probability /home/hskim/data/sok/reassessor/prob\_json

python3 res\_pr.py /data2/benchmark /home/hskim/data/sok/reassessor/probability


# 3. misc
python3 run\_disasm\_type\_count.py /data2/benchmark /home/hskim/data/sok/reassessor/pickles /home/hskim/data/sok/reassessor/evaluation

python3 run\_error\_count.py /data2/benchmark /home/hskim/data/sok/reassessor/result /home/hskim/data/sok/reassessor/evaluation

python3 res\_pr\_count.py /data2/benchmark /home/hskim/data/sok/reassessor/evaluation

python3 res\_error\_count.py /data2/benchmark /home/hskim/data/sok/reassessor/evaluation

python3 res\_disasm\_count.py /data2/benchmark /home/hskim/data/sok/reassessor/evaluation

python3 res\_type\_count.py /data2/benchmark /home/hskim/data/sok/reassessor/evaluation

python3 res\_pickle\_count.py /data2/benchmark /home/hskim/data/sok/reassessor/pickles

python3 composite.py /data2/benchmark /home/hskim/data/sok/reassessor/pickles /home/hskim/data/sok/reassessor/triage3
python3 res\_composite.py /data2/benchmark /home/hskim/data/sok/reassessor/triage3

python3 get\_nofunc.py /data2/benchmark /home/hskim/data/sok/reassessor/func/func\_list.json /home/hskim/data/sok/reassessor/nofunc
python3 run\_disasm.py /data2/benchmark /home/hskim/data/sok/reassessor/pickles /home/hskim/data/sok/reassessor/nofunc /home/hskim/data/sok/reassessor/disasm
python3 res\_disasm\_err.py /data2/benchmark /home/hskim/data/sok/reassessor/disasm


## Bug Report
https://github.com/HexHive/retrowrite/issues/29
https://github.com/angr/patcherex/issues/39
https://github.com/GrammaTech/ddisasm/issues/41

## Error
https://b2r2.work/fnNZNCacTr2S7WxmyaI4XA?edit
