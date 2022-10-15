Reassessor
========

[Reassessor](https://github.com/SoftSec-KAIST/Reassessor) is an automated tool
to search symbolization errors from reassembler-generated assembly files. The
details of the algorithm in our paper "Reassembly is Hard: A Reflection on
Challenges and Strategies" will appear in USENIX Security 2023.

# Install

### 1. Clone `Reassessor`
```
$ git clone https://github.com/SoftSec-KAIST/Reassessor
$ cd Reassessor
```

### 2. Install Dependencies

`Reassessor` is written in python3 (3.6), and
it depends on [pyelftools](https://github.com/eliben/pyelftools.git) (>= 0.29) and
[captone](https://pypi.org/project/capstone/) (>=4.0.2). 

To install the dependencies, please run:

```
$ pip3 install -r requirements.txt
```

Besides, this artifact requires `Docker` engine to run reassemblers. We assumed
that you can run Docker commands as a non-root user since we wanted our scripts
not to ask you for sudo password.

### 3. Install Reassessor

```
$ python3 setup.py install --user
```

# Usage

### (Optional) Reassemble binaries

If you already obtained reassembly files, skip this step.
Otherwise, you can run our preprocessing module to generate reassembly files.

```
$ python3 -m reassessor.preprocessing <binary_path> <output_dir>
```
Then, you can get the reassembly files under the `<output_dir>/reassem`.

The module uses our `Docker` images to run Ramblr (commit 64d1049, Apr. 2022),
RetroWrite (commit 613562, Apr. 2022), and Ddisasm v1.5.3 (docker image digests
a803c9, Apr. 2022).
Thus, it will download `Docker` images from [DockerHub](https://hub.docker.com).



### Run Reassessor

At a high level, `Reassessor` searches errors by diffing the compiler generated-assembly file and reassembly file.
Thus, `Reassessor` requires `<binary_path>`, `<assembly_directory>` to normalize compiler-generated assembly files,
and also it requires `reassembly files` to check.
Then, `Reassessor` will emit report files on `<output_directory>`.
```
$ python3 -m reassessor.reassessor <binary_path> <assembly_directory> <output_directory> \
  [--ramblr RAMBLR] [--retrowrite RETROWRITE] [--ddisasm DDISASM]
```

### Docker

You can use a `Docker` image to try out `Reassessor` quickly.
The following command will build the docker image name `Reassessor`,
using our [Dockerfile](https://github.com/SoftSec-KAIST/Reassessor/blob/main/Dockerfile).
```
$ docker build --tag reassessor .
```

Next, you should use the `Docker` command to run `Reassessor`.

```
$ docker run --rm reassessor sh -c "/Reassessor/reassessor.py <binary_path> <assembly_directory> \
  <output_directory> [--ramblr RAMBLR] [--retrowrite RETROWRITE] [--ddisasm DDISASM]
```

# Example

You can test `Reassessor` with our example program.

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
  /input/example/src/hello /input/example/ /input/output \
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
We publicize our benchmark at [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.7178116.svg)](https://doi.org/10.5281/zenodo.7178116)


# Artifacts

We also publicize the artifacts to reproduce the experiments in our paper.
Please check our [artifacts/](https://github.com/SoftSec-KAIST/Reassessor/tree/main/artifact).

# Contributions of our works

`Reassessor` found plentiful symbolization errors from stat-of-art reassemblers.
Also, we discovered unseened reassembly errors. We made PR and issues to resolve the errors.

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

This research project has been conducted by [SoftSec Lab](https://softsec.kais.ac.kr)
at KAIST and UT Dallas.
- Hyungseok Kim
- [Soomin Kim](https://softsec.kaist.ac.kr/~soomink/)
- Junoh Lee
- [Kangkook Jee](https://kangkookjee.io)
- [Sang Kil Cha](https://softsec.kaist.ac.kr/~sangkilc/)

### Citation

(TBD)
