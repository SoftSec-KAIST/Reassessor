Reassessor
========

[Reassessor](https://github.com/SoftSec-KAIST/Reassessor) is an automated tool
to search symbolization errors from reassembler-generated assembly files. At a
high level, `Reassessor` searches errors by diffing the compiler
generated-assembly file and reassembly file. The details of the algorithm in
our paper "Reassembly is Hard: A Reflection on Challenges and Strategies" will
appear in USENIX Security 2023.

# Install

`Reassessor` currently works on only Linux machine and we tested on Ubuntu
18.04 and Ubuntu 20.04.

### 1. Clone Reassessor

```
$ git clone https://github.com/SoftSec-KAIST/Reassessor
$ cd Reassessor
```

### 2. Install Dependencies

`Reassessor` is written in python 3 (3.6), and it depends on
[pyelftools](https://github.com/eliben/pyelftools.git) (>= 0.29) and
[captone](https://pypi.org/project/capstone/) (>=4.0.2).

To install the dependencies, please run:

```
$ pip3 install -r requirements.txt
```

### 3. Install Reassessor

```
$ python3 setup.py install --user
```

# Usage

### Preprocessing Step

There is a preprocessing step that needs to be performed before
operating `Reassessor` to produce a compiler-generated assembly file,
a non-stripped binary file, and a reassembler-generated assembly file.


You can download our benchmark binary files and compiler-generated
assembly files at
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.7178116.svg)](https://doi.org/10.5281/zenodo.7178116).

> **Note**
> If you want to make your own binary set, you should build binaries with
> `--save-temps=obj` option to force the compilers to preserve all the
> intermediate files including assembly files generated during a
> compilation process. Also, you should enable the `-g` option to
> produce binaries with debugging information. Lastly, `-Wl,--emit-relocs`
> linker option is required especially when you build non-PIE
> (Position-dependent Executable) binaries. The linker option preserves
> relocation information.

Next, you can get reassembler-generated assembly files by running `preprocessing` module.

> **Note** The preprocessing step requires `Docker` engine to run reassemblers.
> Moreover, we assumed that you can run Docker commands as a non-root user since we wanted
> our scripts not to ask you for sudo password.

```
$ python3 -m reassessor.preprocessing <binary_path> <output_dir>
```

During the preprocessing step, `STRIP` module strips off debug symbols from the binary
to get a stripped binary. `Ddisasm` and `Ramblr` take the stripped binary as an input
binary. However, the stripping process is omitted for `RetroWrite` since it requires
debugging information to reassemble binaries.

The module produces the reassembly files under the `<output_dir>/reassem`.
```
$ ls <output_dir>/reassem
ddisasm.s  retrowrite.s
```
Note that each tool supports different sets of binaries: `Ramblr` only works with non-PIE
binaries and `RetroWrite` only works with x86-64 PIE binaries.
Thus, `preprocessing` module will generate a different set of reassembly files
depending on binary files.

> **Note**
> The `preprocessing` module runs the-state-of-art reassemblers, Ramblr (commit 64d1049, Apr. 2022),
> RetroWrite (commit 613562, Apr. 2022), and Ddisasm v1.5.3 (docker image
> digests: a803c9, Apr. 2022), in a dockerized environment, to produce reassembly files.
> If you want to run `Reassessor` with a new reassembler,
> you should update the execution commands in reassemble() method
> in [preprocessing.py](https://github.com/SoftSec-KAIST/Reassessor/blob/main/reassessor/preprocessing.py) file


### Run Reassessor

`Reassessor` takes in a compiler-generated assembly file and
a reassembler-generated assembly file and transforms assembly expressions
into a canonical form to ease the comparison. Then, `Reassessor` searches
errors by comparing the normalized assembly code.

To search reassembly errors, you should run `reassessor` module as follows:

```
$ python3 -m reassessor.reassessor <binary_path> <assembly_directory> <output_directory> \
  [--ramblr RAMBLR] [--retrowrite RETROWRITE] [--ddisasm DDISASM]
```

The `reassessor` module requires `<binary_path>`  and `<assembly_directory>` to
normalize compiler-generated assembly files. Also, it requires
`<reassembly files>` to normalize the target reassembly file; you can
specify the location of reassembly files by using `--ramblr`, `--retrowrite`,
and `--ddisasm` options. Then, `reassessor` module compares the normalized code
and produces report files on `<output_directory>`.

```
$ python3 -m reassessor.reassessor <binary_path> <assembly_directory> <output_directory> \
  --ddisasm <reassembly_code_path>
$ ls <output_directory>/norm_db
gt.db  ddisasm.db
$ ls <output_directory>/errors/ddisasm
disasm_diff.txt  sym_diff.txt  sym_errors.dat  sym_errors.json
```
The `reassessor` module generates normalized assembly files under
`<output_directory>/norm_db` folder. Also, the module produces four error report
files, `ddisasm_diff.txt`, `sys_diff.txt`, `sys_errors.json`, and `sys_errors.dat`,
under `<output_directory>/errors/<reassembler>` folder.

`sym_diff.txt`, `sym_errors.json`, and `sym_errors.data` contain the same symbolization
error list but they have different representation formats.
`sym_diff.txt` shows diffing of (re-)assembly files: each line
contains `error type`, `address`, `reassembly code`, and `compiler-generate code` fields.
`sym_errors.json` contains details of symbolization errors in JSON format.
`sym_error.dat` is a data file containing raw metadata of symbolization errors which is
designed to analyze errors. Lastly, `disasm_diff.txt` contains disassembly errors:
each line contains `address`, `reassembly code`, and `compiler-generate code` fields.


### Docker

You can use a `Docker` image to try out `Reassessor` quickly.

The following command will build the docker image name `Reassessor` using our
[Dockerfile](https://github.com/SoftSec-KAIST/Reassessor/blob/main/Dockerfile).
```
$ docker build --tag reassessor .
```

Next, you can use the `Docker` command to run `Reassessor`.
```
$ docker run --rm reassessor sh -c "/Reassessor/reassessor.py <binary_path> <assembly_directory> \
  <output_directory> [--ramblr RAMBLR] [--retrowrite RETROWRITE] [--ddisasm DDISASM]
```

# Example

You can test `Reassessor` with our sample program.

### 1. Build a source code
```
$ cd examples
$ make
$ cd ..
```

### 2. Reassemble the example program
```
$ mkdir output
$ python3 -m reassessor.preprocessing ./example/bin/hello ./output
$ ls ./output/reassem
ddisasm.s  retrowrite.s
```

### 3. Run Reassessor
```
$ python3 -m reassessor.reassessor ./example/bin/hello ./example/asm ./output  \
  --retrowrite ./output/reassem/retrowrite.s
$ ls ./output/norm_db
gt.db  retrowrite.db
$ ls ./output/errors/retrowrite
disasm_diff.txt  sym_diff.txt  sym_errors.dat  sym_errors.json
```

Also, you can use `Docker` command to run `Reassessor`.
```
$ docker run --rm -v $(pwd):/input reassessor sh -c "python3 -m reassessor.reassessor \
  /input/example/bin/hello /input/example/asm/ /input/output \
  --retrowrite /input/output/reassem/retrowrite.s"
```


### 4. Check Error Report
```
$ cat ./output/errors/retrowrite/sym_diff.txt
# Instrs to check: 48
# Data to check: 14
Relocatable Expression Type 4 [FP: 3(0) / FN: 0]
E4FP [0] (Disp:3:0) 0x1196  : movl .LC2024(%rip), %eax                  | movl bar+4(%rip), %eax
E4FP [0] (Disp:3:0) 0x11a7  : movl .LC2028(%rip), %eax                  | movl bar+8(%rip), %eax
E4FP [0] (Disp:3:0) 0x11b8  : movl .LC202c(%rip), %eax                  | movl bar+12(%rip), %eax
```

# Dataset
We publicize our benchmark at
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.7178116.svg)](https://doi.org/10.5281/zenodo.7178116).
(The dataset does not contain SPEC CPU 2006 binaries because of a licensing
issue.)


# Artifacts

We also publicize the artifacts to reproduce the experiments in our paper.
Please check our
[artifacts/](https://github.com/SoftSec-KAIST/Reassessor/tree/v1.0.0/artifact) folder.

# Contributions of our works

`Reassessor` found plentiful symbolization errors from stat-of-art
reassemblers. Also, we discovered unseen reassembly errors. We made PR and
issues to resolve the errors.

- Ramblr
    - [issue 3549](https://github.com/angr/angr/issues/3549) (1 Oct 2022)
    - [issue 39](https://github.com/angr/patcherex/issues/39) (21 Jan 2022)

- RetroWrite
    - [PR](https://github.com/HexHive/retrowrite/pull/36) (26 May 2022)
    - [issue 45](https://github.com/HexHive/retrowrite/issues/45) (1 Oct 2022)
    - [issue 38](https://github.com/HexHive/retrowrite/issues/38) (6 Jun 2022)
    - [issue 35](https://github.com/HexHive/retrowrite/issues/35) (9 May 2022)
    - [issue 29](https://github.com/HexHive/retrowrite/issues/29) (13 Oct 2021)

- Ddisasm
    - [issue 54](https://github.com/GrammaTech/ddisasm/issues/54) (1 Oct 2022)
    - [issue 41](https://github.com/GrammaTech/ddisasm/issues/41) (25 Jan 2022)


### Authors

This research project has been conducted by
[SoftSec Lab](https://softsec.kais.ac.kr) at KAIST and UT Dallas.
- Hyungseok Kim (KAIST)
- [Soomin Kim (KAIST)](https://softsec.kaist.ac.kr/~soomink/)
- Junoh Lee (KAIST)
- [Kangkook Jee (UT Dallas)](https://kangkookjee.io)
- [Sang Kil Cha (KAIST)](https://softsec.kaist.ac.kr/~sangkilc/)

### Citation

(TBD)
