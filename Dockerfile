FROM ubuntu:18.04

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y git python3-setuptools python3-pip

#RUN git clone https://github.com/SoftSec-KAIST/Reassessor.git

RUN mkdir Reassessor
COPY reassessor Reassessor/reassessor
COPY requirements.txt Reassessor/requirements.txt
COPY setup.py Reassessor/setup.py

RUN cd Reassessor; \
    pip3 install -r requirements.txt; \
    python3 setup.py install;\
    cd -


