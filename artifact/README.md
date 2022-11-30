Reassessor Artifact
========

[Reassessor](https://github.com/SoftSec-KAIST/Reassessor) is a tool for finding
errors in the implementations of existing reassemblers.  This artifact includes
the source code of Reassessor, the dataset used in our paper, and several
scripts for reproducing the results in the paper. As a preprocessing step, one
needs to run three existing reassemblers on our dataset, including Ramblr,
RetroWrite, and Ddisasm. We provide a dockerized environment to run them. The
preprocessing step produces a re-assemblable assembly file for each binary, and
Reassessor uses those files to find reassembly errors. The next section details
each step to reproduce the results in our paper.

> **Note**
> The artifact requires at least 2.5TB disk to retrieve all results. Also, the
> artifact requires sufficient memory to run multiple docker images, because a
> single docker image may consume about 30~40GB memory to reassemble large-size
> binaries. We performed the experiments on a Linux machine (Ubuntu 18.04 and
> Ubuntu 20.04) equipped with 8 cores of CPUs and 128GB of RAM.

# Preprocessing step for experiments

### 1. Download a dataset

Download the [dataset](https://doi.org/10.5281/zenodo.7178116):

```
$ cd artifact/
$ tar -xzf /path/to/dataset/benchmark.tar.gz .
$ ls dataset/
binutils-2.31.1  coreutils-8.30
```
> **Note**
> Our published dataset does not contain SPEC CPU 2006 binaries because of a
> licensing issue

### 2. Reassemble dataset binaries

Run `run_preproc.py` to obtain reassembler-generated assembly code from each
reassembler:
```
$ python3 run_preproc.py
```

`run_preproc.py` will generate assembly files under the `./output` folder:

```
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd
addr2line   as-new   elfedit    ld-new  objcopy   ranlib   size     strip-new
ar          cxxfilt  gprof      nm-new  objdump   readelf  strings
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line
reassem
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line/reassem
ddisasm.s  ramblr.s
```

(Optional) `run_preproc.py` supports multi-thread option so you can use it as
follows:
```
$ python3 run_preproc.py --core 4
```


# Experiments

### 1. Search reassembly errors

The experiment will search for reassembly errors by running Reassessor.

Run `run_reassessor.py` to search reassembly errors.

```
$ python3 run_reassessor.py --core 6
```

You can find report files that `Reassessor` made under the `errors` folders.

```
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line/errors
ddisasm  ramblr
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line/errors/ddisasm
disasm_diff.txt  sym_diff.txt  sym_errors.dat  sym_errors.json
```

`disasm_diff.txt` contains a list of disassembly errors (one per line); each
line contains the relevant address, reassembler-generated assembly line, and
compiler-generated assembly line.  `sym_errors.dat` is a raw output file
containing a list of symbolization errors. This file is used to generate other
two files: `sym_errors.json` and `sym_diff.txt`. `sym_diff.txt` is a
human-readable representation of `sym_errors.dat`. Each line of the file
contains address, error type, reassembler-generated assembly code, and
compiler-generated code, for each error found. Finally, `sym_errors.json`
contains detailed information about each symbolization error found, including
the relevant assembly file, line number, relocatable expression type,
normalized code, repairability, and so on.  The file is written in the JSON
format.

Next, run `classify_errors.py` to collect and classify reassembly errors
from `sym_diff.txt` files:

```
$ python3 classify_errors.py --core 8
$ ls triage
ddisasm  ramblr  retrowrite
$ ls triage/ddisasm/x64/nopie
E1FN.txt E1FP.txt E2FN.txt E2FP.txt E3FN.txt ...
```
Each file has a different set of errors, and each line of the files contains a
relevant file name, error type, reassembler-generated assembly line, and
compiler-generated assembly line.

Lastly, run  `get_summary.py` to to get a summarized result presented in Table 4
in our paper:

```
$ python3 get_summary.py --core 8
```


### 2. Get the statistics of compiler-generated assembly files

This experiment examines all relocatable expressions in our benchmark and
reports the distributions of relocatable expressions for a different set of
assembly files. Also, the experiment will show that the proportion of
label-relative (Type VII) relocatable expressions in x8664 PIE binaries is not
negligible.


> **Note**
> [Experiment 1](https://github.com/SoftSec-KAIST/Reassessor/tree/main/artifact#1-search-reassembly-errors)
> is required since `get_asm_statistics.py` and `get_e7_errors.sh` refer to data files that `Reassessor` made.

Run `get_asm_statistics.py` to examine compiler-generated assembly files.

```
$ python3 get_asm_statistics.py --core 8
```

`get_asm_statistics.py` shows the distribution of relocatable expressions, and
the proportion of composite relocatable expressions. Also, it reports how many
binaries have abnormal cases including composite relocatable expressions
pointing to outside of valid memory ranges and code pointers referring to
non-function entries.

Next, run `get_e7_errors.sh` to find E7 errors for x86-64 PIE binaries.
```
$ /bin/bash get_e7_errors.sh
```


### 3. Dissect reassembly errors

This experiment will find previously unseen symbolization errors..

> **Note**
> [Experiment 1](https://github.com/SoftSec-KAIST/Reassessor/tree/main/artifact#1-search-reassembly-errors)
> is required since `dissect_errors.sh` examines symbolization errors that
> `Reassessor` made.

Run `dissect_errors.sh` to find previously unseen symbolization errors.

```
$ /bin/bash dissect_errors.sh
```

`dissect_errors.sh` reports how many reassembler-generated files have
previously unseen errors. Also, `dissect_errors.sh` generates the report files:
`atomic_fn_cases.txt`, `atomic_fp_cases.txt`, and `label_err_fp_cases.txt`.
Each line of the files contains a relevant file name, error type,
reassembler-generated assembly line, and compiler-generated assembly line.
`atomic_fn_cases.txt` contains false negative cases where reassemblers
misidentify atomic relocatable expressions as literals. `atomic_fp_cases.txt`
contains false positive cases where reassemblers falsely symbolize atomic
relocatable expressions as composite forms. Lastly, `label_err_fp_cases.txt`
contains cases where symbolized labels have the same form as in the original
one, while only the label values are misidentified.

### 4. Check reparable errors

This experiment measures an empirical lower bound of the number of reparable
symbolization errors when preventing data instrumentation. Specifically, this
experiment will count symbolization errors that satisfy the criteria we
suggested in Section 5.5.2.

> **Note**
> [Experiment 1](https://github.com/SoftSec-KAIST/Reassessor/tree/main/artifact#1-search-reassembly-errors)
> is required since `check_reparable_errors.sh` examines the report files
> that `classify_errors.sh` made.

Run `check_reparable_errors.sh` to get an empirical lower bound of the number
of reparable symbolization errors when preventing data instrumentation.

```
$ /bin/bash check_reparable_errors.sh
```

`check_reparable_errors.sh` reports how many symbolization errors satisfy the
reparable conditions we introduced in Section 5.5.2. Also, `reparable_errors.txt`
contains the list of reparable symbolization errors; each line of the file has
a relevant file name, error type, reassembler-generated assembly line, and
compiler-generated assembly line.

