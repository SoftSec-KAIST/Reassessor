FROM ubuntu:22.04

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y wget git python3-setuptools python3-pip

RUN git clone https://github.com/eliben/pyelftools.git; \
    cd pyelftools; \
    python3 setup.py install; \
    cd -;

RUN pip3 install capstone

#RUN git clone https://github.com/SoftSec-KAIST/Reassessor.git

RUN mkdir Reassessor
COPY normalizer Reassessor/normalizer
COPY differ Reassessor/differ
COPY lib Reassessor/lib
COPY setup.py Reassessor/setup.py
COPY manager.py Reassessor/manager.py

RUN cd Reassessor; \
    python3 setup.py install;

