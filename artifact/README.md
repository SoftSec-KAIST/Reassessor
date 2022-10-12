Reassessor Artifact
========

[Reassessor](https://github.com/SoftSec-KAIST/Reassessor) is an automated tool
to find different types of errors that occur in current existing reassemblers.
This artifact is designed to run the experiments in our paper. "Reassembly is
Hard: A Reflection on Challenges and Strategies" which will appear in USENIX
Security 2023.  In the first step, we will run the-state-of-art reassemblers,
Ramblr, RetroWrite, and Ddisasm, in a dockerized environment to reassemble
dataset binaries. Then, we will run R EASSESSOR to search reassembly errors.
Lastly, we collect reassembly errors R EASSESSOR found and reproduce key
results of our paper.  to search reassembly errors from reassembler-generated
assembly files.



1. Download & Uncompress our benchmark.

We publicize our benchmark at
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.7178116.svg)](https://doi.org/10.5281/zenodo.7178116)
You should download our dataset and uncompress it on <em>artifact</em> folder.

```
$ cd artifact/
$ tar -xzf /path/to/dataset/benchmark.tar.gz .
$ ls dataset/
binutils-2.31.1  coreutils-8.30
```
The `dataset` folder contains two `package` folders: `binutils-2.31.1` and
`coreutils-8.30`.  Each `package` folder contains two `architecture` folders:
`x64` and `x86`.  Also, the `architecture` folder consists with two `compiler`
folders: `clang` and `gcc`.  The `compiler` folder contains `pie option`
folders: `pie` and `nopie`.  Also, the `pie option` folder has 12
`optimization` folders: `o0-bfd`, `o0-gold`,  `o1-bfd`, `o1-gold`, `o2-bfd`,
`,o2-gold`, `o3-bfd`,  `o3-gold`, `ofast-bfd`,  `ofast-gold`, `os-bfd`,  and
`os-gold`. Lastly, each `optimization folder` contains assembly files, and
binary files.

```
$ ls dataset/binutils-2.31.1
x64  x86
$ ls dataset/binutils-2.31.1/x64
clang  gcc
$ ls dataset/binutils-2.31.1/x64/clang
nopie  pie
$ ls dataset/binutils-2.31.1/x64/clang/nopie
o0-bfd   o1-bfd   o2-bfd   o3-bfd   ofast-bfd   os-bfd
o0-gold  o1-gold  o2-gold  o3-gold  ofast-gold  os-gold
```

2. Perform Preprocessing to generate reassembly files

Next, you should run <em>run_preproc.py</em> to generate reassembly files.
```
$ python3 run_preproc.py
```
<em>run_preproc.py</em> will run `docker` commands to execute three
reassemblers, Ramblr (commit 64d1049, Apr. 2022), RetroWrite (commit 613562,
Apr. 2022), and Ddisasm v1.5.3 (docker image a803c9, Apr. 2022).

(Optional) <em>run_preproc.py</em> supports parallel options so you can use
`--core $(nproc)` options.

```
$ python3 run_preproc.py --core $(nproc)
```

Reassembly files will be stored at <em>./output</em> folder. The structure of
<em>./output</em> folder is similar to <em>./dataset</em> folder.

```
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd
addr2line   as-new   elfedit    ld-new  objcopy   ranlib   size     strip-new
ar          cxxfilt  gprof      nm-new  objdump   readelf  strings
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line
reassem
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line/reassem
ddisasm.s  ramblr.s
```

3. Run Reassessor to search reassembly errors

You should run <em>run_reassessor.py</em> to search reassembly errors.
```
$ python3 run_reassessor.py
```


(Optional) The script supports parallel options (`--core $(nproc)`)
```
$ python3 run_reassessor.py --core $(nproc)
```

(Optional) The script also supports docker option (`--docker`), so
you can run dockernized Reassessor.
```
$ python3 run_reassessor.py --docker
```

<em>run_reassessor.py</em> will search reassembly errors.
You can find report files under the `errors` folders.

```
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line/errors
ddisasm  ramblr
$ ls output/binutils-2.31.1/x64/clang/nopie/o0-bfd/addr2line/errors/ddisasm
disasm_diff.txt  sym_diff.txt  sym_errors.dat  sym_errors.json
```
Reassessor produces report files as follows: <em>ddisasm_diff.txt</em>, <em>sys_diff.txt</em>,
<em>sys_errors.json</em>, and <em>sys_errors.dat</em>. <em>sym_diff.txt</em>, <em>sym_errors.json</em>, and
<em>sym_errors.data</em> contain the same symbolization error list but they have
different representation formats. sym_diff.txt shows diffing of (re-)assembly
files: each line contains <em>Errors Type</em>, <em>Addr</em>, <em>Reassembly Code</em>, and <em>Compiler-generate code</em>
fields.
<em>sym_errors.json</em> contains details of symbolization errors in JSON format.
<em>sym_error.dat</em> is a data file containing raw metadata of symbolization errors
which is designed to analyze errors. Lastly, <em>disasm_diff.txt</em> contains
disassembly errors: each line contains <em>Address</em>, <em>Reassembly
Code</em>, and <em>Compiler-generate code</em> fields.



3. Get the summary of report files

You should run <em>get_summary.py</em> to summarize reassembly errors
<em>get_summary.py</em> will examine reprot files Reassessor made and
report summarized results like Table 4 in our paper.
```
$ python3 get_summary.py
```

(Optional) <em>get_summary.py</em> supports parallel options (`--core $(nproc)`)
```
$ python3 get_summary.py --core $(nproc)
```

6. Dissect reassembly errors

First, you should run <em>classify_errors.sh</em> file to collect classify
reassembly errors that Reassessor found. <em>classify_errors.sh</em> will
create <em>./triage</em> folder which contains three <em>reassembler</em>
folders: ddisasm, ramblr, and retrowrite.
Ecah <em>reassembler</em> folder consists with four sub-folder, x64/pie,
x64/nopie, x86/pie, and x86/nopie.
Each sub-folder has report files that contains reassembly errors.

```
$ /bin/bash classify_errors.sh
```

Next, you should run <em>dissect_errors.sh</em> to find unseen reassembly error
cases we reported in section 5.4.
```
$ /bin/bash dissect_errors.sh
```

Lastly, you should run <em>check_reparable_errors.sh</em> to get an empirical
lower bound of the number of reparable symbolization errors when preventing
data instrumentation. <em>check_reparable_errors.sh</em> will search errors that
satisfy four conditions we introduced in section 5.5.2.

```
$ /bin/bash check_reparable_errors.sh
```


5. Get the statistics of relocatable expressions.

Also, you can examine compiler-gnerated assembly files by running <em>get_asm_statistics.py</em>
```
$ python3 get_asm_statistics.py
```

(Optional) <em>get_asm_statistics.py</em> also supports parallel options (`--core $(nproc)`)
```
$ python3 get_asm_statistics.py --core $(nproc)
```

<em>get_asm_statistics.py</em> will report distributions of relocatable expression types.


