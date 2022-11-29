Reassessor Artifact
========

[Reassessor](https://github.com/SoftSec-KAIST/Reassessor) is an automated tool
to find different types of errors that occur in current existing reassemblers.
The artifact includes the source code of Reassessor, Docker images, and dataset
binaries to reproduce key results of the paper. As a preprocessing step, we will 
run the-state-of-art reassemblers, Ramblr, RetroWrite, and Ddisasm, in a 
dockerized environment, to produce reassembly files. Next, we will run Reassessor 
to find reassembly errors. Reassessor takes in a compiler-generated assembly 
file and a reassembler-generated assembly file as input, and transforms assembly 
expressions into a canonical form to ease the comparison. Then, Reassessor 
returns a list of symbolization errors by comparing the two normalized assembly 
files. Lastly, we will collect reassembly errors Reassessor found and checks 
experimental results.

> **Note**
> The artifact requires at least 2.5 TB disk to retrieve all results. 
> Also, the artifact requires sufficient memory to run multiple docker
> images, because a single docker image may consume about 30~40 GB memory to
> reassemble large-size binaries.
> We performed the experiments on a Linux machine (Ubuntu 18.04 and Ubuntu 20.04) 
> equipped with 8 cores of CPUs and 128 GB of RAM.

# Preprocessing step for experiments

### 1. Download a dataset

Download our [dataset](https://doi.org/10.5281/zenodo.7178116) and uncompress
it in `artifact` folder.
> **Note**
> Our published dataset does not contain SPEC CPU 2006 binaries because of a
> licensing issue


```
$ cd artifact/
$ tar -xzf /path/to/dataset/benchmark.tar.gz .
$ ls dataset/
binutils-2.31.1  coreutils-8.30
```

### 2. Reassemble dataset binaries

Run `run_preproc.py` to generate reassembly files.
```
$ python3 run_preproc.py
```

`run_preproc.py` will run `Docker` commands to execute three reassemblers,
`Ramblr (commit 64d1049, Apr. 2022)`, `RetroWrite (commit 613562, Apr. 2022)`,
and `Ddisasm v1.5.3 (docker image a803c9, Apr. 2022)`.

(Optional) `run_preproc.py` supports multi-thread option so you can use it as
follows.
```
$ python3 run_preproc.py --core 4
```

Reassembly files will be generated at `./output` folder.

```
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd
addr2line   as-new   elfedit    ld-new  objcopy   ranlib   size     strip-new
ar          cxxfilt  gprof      nm-new  objdump   readelf  strings
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line
reassem
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line/reassem
ddisasm.s  ramblr.s
```

# Experiments

### 1. Search reassembly errors

This experiment will show that `Reassessor` is able to find diverse reassembly
errors, and then summarize the errors.

Run `run_reassessor.py` to search reassembly errors.

```
$ python3 run_reassessor.py --core 6
```

(Optional) The script also supports `docker` option (`--docker`), so you can
run dockerized `Reassessor` as follows.
```
$ python3 run_reassessor.py --docker
```

You can find report files that `Reassessor` made under the `errors` folders.

```
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line/errors
ddisasm  ramblr
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line/errors/ddisasm
disasm_diff.txt  sym_diff.txt  sym_errors.dat  sym_errors.json
```

Next, run `classify_errors.py` to classify reassembly errors that `Reassessor`
found.

```
$ python3 classify_errors.py --core 8
```

`classify_errors.py` will create `./triage` folder which contains three
`reassembler` folders:  `ramblr`, `retrowrite` and `ddisasm`.  Also,
`reassembler` folder has four sub-folders, `x64/pie`, `x64/nopie`, `x86/pie`,
and `x86/nopie`; each sub-folder has its own report files that contain
different types of reassembly errors.

```
$ ls triage
ddisasm  ramblr  retrowrite
$ ls triage/ddisasm/x64/nopie
E1FN.txt E1FP.txt E2FN.txt E2FP.txt E3FN.txt ...
```

Each report file has a different set of errors, and each line of the files
contains a relevant `file name`, `error type`, `reassembly code`, and
`compiler-generate code`.

Lastly, run  `get_summary.py` to examine report files containing reassembly
errors. `get_summary.py` will report the summarized results like Table 4 in our
paper.

```
$ python3 get_summary.py --core 8
```



### 2. Get the statistics of compiler-generate assembly files

This experiment examines all relocatable expressions in our benchmark and
reports the distributions of relocatable expressions for a different set of
assembly files. Also, the experiment will show that the proportion of
label-relative (Type VII) relocatable expressions in x86-64 PIE binaries is not
negligible. Moreover, it will report that existing reassembly tools,
`retrowrite` and `ddisasm`, had E7 symbolization errors for x86-64 PIE binaries
since they misidentified jump table bounds; this result implies that precise
CFG recovery is a necessary condition for sound reassembly of x86-64 PIEs.

> **Note**
> [Experiment 1](https://github.com/SoftSec-KAIST/Reassessor/tree/main/artifact#1-search-reassembly-errors)
> is required since `get_asm_statistics.py` and `get_e7_errors.sh` refer to data files that `Reassessor` made.

Run `get_asm_statistics.py` to check all relocation expression types in our
benchmark. `get_asm_statistics.py` will report the distributions of relocatable
expressions for a different set of assembly ﬁles.

```
$ python3 get_asm_statistics.py --core 8
```

Next, run `get_e7_errors.sh` to check the proportion of E7 errors 
from x86-64 PIE binaries.
```
$ /bin/bash get_e7_errors.sh
```


### 3. Dissect reassembly errors

This experiment will search previously unseen FN/FP patterns.

> **Note**
> [Experiment 1](https://github.com/SoftSec-KAIST/Reassessor/tree/main/artifact#1-search-reassembly-errors)
> is required since `dissect_errors.sh` examines symbolization errors that
> `Reassessor` made.

Run `dissect_errors.sh` to find unseen reassembly error cases we reported in
section 5.4.

```
$ /bin/bash dissect_errors.sh
```

`dissect_errors.sh` reports how many reassembly files have previously unseen
errors. Also, `dissect_errors.sh` generates the report files:
`atomic_fn_cases.txt`, `atomic_fp_cases.txt`, and `label_err_fp_cases.txt`.
Each line of the files contains a relevant `file name`, `error type`,
`reassembly code`, and `compiler-generate code`. `atomic_fn_cases.txt` contains
false negative cases where reassemblers misidentify atomic relocatable
expressions as literals. `atomic_fp_cases.txt` contains false positive cases
where reassemblers falsely symbolize atomic relocatable expressions as
composite forms. Lastly, `label_err_fp_cases.txt` contains cases where
symbolized labels have the same form as the original one, while only the
label values are misidentified.



### 4. Check reparable errors

This experiment will report how many symbolization errors would be reparable
when preventing data instrumentations.

> **Note**
> [Experiment 1](https://github.com/SoftSec-KAIST/Reassessor/tree/main/artifact#1-search-reassembly-errors)
> is required since `check_reparable_errors.sh` examines the report files
> that `classify_errors.sh` made.

Run `check_reparable_errors.sh` to get an empirical lower bound of the number
of reparable symbolization errors when preventing data instrumentation.

```
$ /bin/bash check_reparable_errors.sh
```

`check_reparable_errors.sh` will report the proportion of reparable errors that
satisfy four conditions we introduced in section 5.5.2. Also,
`check_reparable_errors.sh` will generate `reparable_errors.txt` file which
contains the list of reparable symbolization errors; each line of the file has
a relevant `file name`, `error type`, `reassembly code`, and `compiler-generate
code`.

