# Reassessor

REASSESSOR is an automated tool to search symbolization errors from
reassembler-generated assembly files. The details of the algorithm in our
paper "Reassembly is Hard: A Reflection on Challenges and Strategies" which
will appear in USENIX Security 2023.

### Build & Run

### Dependency
Reassessor has dependency on [pyelftools](https://github.com/eliben/pyelftools.git)
and [captone](https://pypi.org/project/capstone/)
```
pip3 install capstone pyelftools
```

Reassessor has some compatible issues with old pyelftools, so we recommend that
you install lastest version.
```
$ git clone https://github.com/eliben/pyelftools.git
$ cd pyelftools
$ python3 setup.py install --user
$ cd ..
```


```
$ python3 setup.py install
```

```
$ python3 reassessor.py [binary_path] [assembly_path] [output_dir]
```

```
$ cd examples
$ make
$ mkdir output
$ python3 reassessor.py ./hello ./src ./output
$ ls output/
$ ls output/errors/
```


### Docker
You can use Docker image to try out FunSeeker quickly.
```
docker build --tag reassessor .
docker run --rm reassessor sh -c "/Reassessor/reassessor.py [binary_path] [assembly_path] [output_dir]"
```

```
docker run --rm -v /path/to/binary:/bin_path -v /path/to/assembly:/assem_path -v /pat/to/output:/output reassessor sh -c /Reassessor/reassessor.py /bin_path/name_of_binary /assem_path/ /output/
```

### Dataset
TBD

### Demos

In the demos/ folder, you can get samples of our benchmark.
It may take few days since reassemblers.
```
cd demos/
./download.sh
./auto.sh
```


If you want to skip preprocessing steps, you should run as follows
```
cd demos/
./download.sh --all
./auto.sh --no-preprocessing
```




### Authors
This research project has been conducted by [SoftSec Lab](https://softsec.kais.ac.kr)
at KAIST and [CSG](https://cs.utdallas.edu/tag/computer-security-group-csg/) at UT Dallas.
- Hyungseok Kim
- [Soomin Kim](https://softsec.kaist.ac.kr/~soomink/)
- Junoh Lee
- [Kangkook Jee](https://kangkookjee.io)
- [Sang Kil Cha](https://softsec.kaist.ac.kr/~sangkilc/)

### Citation
If you plan to use Reassessor in your own research, please consider citing our
paper
