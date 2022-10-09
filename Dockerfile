FROM ubuntu:22.04

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y wget git python3-setuptools python3-pip

RUN pip3 install capstone pyelftools==0.29

#RUN git clone https://github.com/SoftSec-KAIST/Reassessor.git

RUN mkdir Reassessor
COPY reassessor Reassessor/reassessor
COPY setup.py Reassessor/setup.py

RUN cd Reassessor; \
    python3 setup.py install;\
    cd -


