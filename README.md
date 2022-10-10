# Reassessor

REASSESSOR is an automated tool to search symbolization errors from
reassembler-generated assembly files. The details of the algorithm in our
paper "Reassembly is Hard: A Reflection on Challenges and Strategies" which
will appear in USENIX Security 2023.

### Install

1. Clone Reassessor
```
$ git clone https://github.com/SoftSec-KAIST/Reassessor
$ Reassessor
```

2. Install Dependencies

Reassessor is written in Python(>= 3.6), and has dependency on
[pyelftools](https://github.com/eliben/pyelftools.git) and
[captone](https://pypi.org/project/capstone/).

To install the dependencies, please run:
```
$ pip3 install -r requirements.txt
```

2. Install Reassessor

Now you can install Reassessor as follows.
```
$ python3 setup.py install --user
```


### (Optional) Perform Preprocessing Step

If you alrady obtain reassembly files, you should skip this step.

Otherwise, you can run our preprocessing module to generate reassembly files.
```
$ python3 -m reassessor.preprocessing <binary_path> <output_dir>
```
Then, you can get the reassembly files under the <em><output\_dir>/reassem</em>.


The module uses our docker images to run Ramblr (commit 64d1049, Apr. 2022),
RetroWrite (commit 613562, Apr. 2022), and Ddisasm v1.5.3 (docker image digests
a803c9, Apr. 2022).
Thus, it will download docker images from [DockerHub](https://hub.docker.com).

If you want to change the reassembly command or docker images,
please edit <em>command\_line</em> used in
[reassembly()](https://github.com/SoftSec-KAIST/Reassessor/blob/main/reassessor/preprocessing.py) methods.


### Run Reassessor

You run Reassessor to search reassembly errors.
At a high level, Reassessor search errors by diffing the compiler generated-assembly file and reassembly file.
Thus, Reassessor requires <binary\_path>, <assembly\_directory> to normalize compiler-generated assembly files,
and it requires <em>reassembly files</em> to check.
Our current versions support Ramblr, RetroWrite, and Ddisasm.
Then, Reassessor will emit report files on <output\_directory>
```
$ python3 -m reassessor.reassessor <binary_path> <assembly_directory> <output_directory> [--ramblr RAMBLR] [--retrowrite RETROWRITE] [--ddisasm DDISASM]
```

### Docker
You can use a docker image to try out FunSeeker quickly.
The following command will build the docker image name `Reassessor`,
using our [Dockerfile](https://github.com/SoftSec-KAIST/Reassessor/blob/main/Dockerfile).
```
docker build --tag Reassessor .
```

Next, you should use the `docker` command to run `Reassessor`.

```
docker run --rm Reassessor sh -c "/Reassessor/reassessor.py <binary_path> <assembly_directory> <output_directory> [--ramblr RAMBLR] [--retrowrite RETROWRITE] [--ddisasm DDISASM]
```

### Example

You can run a our example code as follows.

1. Build a source code
```
$ cd examples
$ make
$ cd ..
```

2. Perform preprocessing step
```
$ mkdir output
$ python3 -m reassessor.preprocessing ./example/src/hello ./output
$ ls ./output/reassem
ddisasm.s  retrowrite.s
```

3. Run Reassessor
```
$ python3 -m reassessor.reassessor ./example/src/hello ./example ./output  --retrowrite ./output/reassem/retrowrite.s
$ ls ./output/norm_db
gt.db  retrowrite.db
$ ls ./output/errors/retrowrite
disasm_diff.txt  sym_diff.txt  sym_errors.dat  sym_errors.json
```

Also, you can use `docker` command to run Reassessor.
```
$ docker run --rm -v $(pwd):/input Reassessor sh -c "python3 -m Reassessor.reassessor.reassessor /input/example/src/hello /input/example/ /input/output --retrowrite /input/output/reassem/retrowrite.s"
```


4. Check Error Report
```
$ cat ./output/errors/retrowrite/sym_diff.txt
# Instrs to check: 48
# Data to check: 14
Relocatable Expression Type 4 [FP: 3(0) / FN: 0]
E4FP [0] (Disp:3:0) 0x1196  : movl .LC2024(%rip), %eax                  | movl bar+4(%rip), %eax
E4FP [0] (Disp:3:0) 0x11a7  : movl .LC2028(%rip), %eax                  | movl bar+8(%rip), %eax
E4FP [0] (Disp:3:0) 0x11b8  : movl .LC202c(%rip), %eax                  | movl bar+12(%rip), %eax
```

### Dataset
We publicize our benchmark at [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.7178116.svg)](https://doi.org/10.5281/zenodo.7178116)


### Artifacts

We also publicize the artifacts to reproduce the experiments in our paper.
Please check our [Artifacts/](https://github.com/SoftSec-KAIST/Reassessor/tree/main/artifact).

### Contributions of our works

Reassessor found several unseen reassembly errors.
We creates issues and a PR to resolve the errors.

- Ramblr
    - [issue 3549](https://github.com/angr/angr/issues/3549) (1 Oct 2022)
    - [issue 39](https://github.com/angr/patcherex/issues/39) (21 Jan 2022)

- RetroWrite
    - [issue 45](https://github.com/HexHive/retrowrite/issues/45) (1 Oct 2022)
    - [issue 38](https://github.com/HexHive/retrowrite/issues/38) (6 Jun 2022)
    - [PR 36](https://github.com/HexHive/retrowrite/pull/36) (26 May 2022)
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

If you plan to use Reassessor in your own research, please consider citing our
paper
