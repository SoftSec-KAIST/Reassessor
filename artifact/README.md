Reassessor Artifact
========

[Reassessor](https://github.com/SoftSec-KAIST/Reassessor) is an automated tool
to find different types of errors that occur in current existing reassemblers.
This artifact is designed to run the experiments in our paper. "Reassembly is
Hard: A Reflection on Challenges and Strategies" which will appear in USENIX
Security 2023.  In the first step, we will run the-state-of-art reassemblers,
Ramblr, RetroWrite, and Ddisasm, in a dockerized environment to reassemble
dataset binaries. Then, we will run `Reassessor` to search reassembly errors.
Lastly, we collect reassembly errors `Reassessor` found and reproduce key
results of our paper.  


### 1. Download a dataset.

Download our [dataset](https://doi.org/10.5281/zenodo.7178116)
and uncompress it on `artifact` folder.

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

`run_preproc.py` will run `Docker` commands to execute three
reassemblers, Ramblr (commit 64d1049, Apr. 2022), RetroWrite (commit 613562,
Apr. 2022), and Ddisasm v1.5.3 (docker image a803c9, Apr. 2022).

(Optional) `run_preproc.py` supports multi-thread options so you can use it as follows.
```
$ python3 run_preproc.py --core $(nproc)
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

### 3. Search reassembly errors

Run `run_reassessor.py` to search reassembly errors.
```
$ python3 run_reassessor.py --core $(nproc)
```

(Optional) The script also supports `docker` option (`--docker`), so
you can run dockerized `Reassessor` as follows.
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

### 4. Get the statistics of compiler-generate assembly files.

Run `get_asm_statistics.py` to check all relocation expression types in our benchmark.
```
$ python3 get_asm_statistics.py --core $(nproc)
```

`get_asm_statistics.py` will report the distributions of relocatable expressions for a different set of assembly ﬁles.


### 5. Get the summary of reassembly errors

Run `get_summary.py` to examine report files containing reassembly errors  
```
$ python3 get_summary.py --core $(nproc)
```
`get_summary.py` will report the summarized results like Table 4 in our paper.


### 6. Dissect reassembly errors

Run `classify_errors.py` to classify reassembly errors that `Reassessor` found. 
```
$ python3 classify_errors.py --core $(nproc)
```

`classify_errors.py` will create `./triage` folder which contains three `reassembler`
folders: ddisasm, ramblr, and retrowrite.
Each folder consists with four sub-folder, x64/pie,
x64/nopie, x86/pie, and x86/nopie, and sub-folders have their own report files 
that contain different types of reassembly errors.

Run `dissect_errors.sh` to find unseen reassembly error
cases we reported in section 5.4.
```
$ /bin/bash dissect_errors.sh
```

### 7. Check reparable errors.

Run `check_reparable_errors.sh` to get an empirical
lower bound of the number of reparable symbolization errors when preventing
data instrumentation. 
```
$ /bin/bash check_reparable_errors.sh
```

`check_reparable_errors.sh` will report the proportion of reparable errors that
satisfy four conditions we introduced in section 5.5.2.



