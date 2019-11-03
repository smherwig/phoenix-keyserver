Overview
========

Private key server for the [Phoenix](https://github.com/smherwig/phoenix) SGX
microkernel.  The keyserver is also called *nsmserver* (Network Security Module
server), and has a companion OpenSSL engine called *nsm-engine*.


Building and Installing
=======================

The keyserver depends on [librho](https://github.com/smherwig/librho) and
[librpc](https://github.com/smherwig/phoenix-librpc).
I assume that dependencies are installed under `$HOME`; modify the keyserver's
Makefiles if this is not the case.


Next, download the keyserver and build the keyserver.

```
cd ~/src
git clone https://github.com/smherwig/phoenix-keyserver keyserver
cd keyserver/server
make
```

Build and install the nsm OpenSSL engine:

```
cd ~/src/keyserver/nsm-engine
make
make install INSTALL_TOP=$HOME
```


Packaging
=========

Assuming the keyserver repo is located in the directory
`$KEYSERVER_REPO`, then In the `makemanifest` repo, run

```
./make_sgx.py -g ~/ws/phoenix \
        -k enclave-key.pem \
        -p $KEYSERVER_REPO/deploy/manifest.conf \
        -t $PWD \
        -v  \
        -o nsmserver
cd nsmserver
cp manifest.sgx nsmserver.manifest.sgx
./nsmserver.manifest.sgx -r /srv tcp://127.0.0.1:9000
```

Micro-benchmarks
================

The micro-benchmarks require the [phoenix](https://github.com/smherwig/phoenix)
libOS and
[phoenix-makemanifest](https://github.com/smherwig/phoenix-makemanifest)
configuration packager. Download and setup these two projects.  The
instructions here assume that the phoenix source is located at
`$HOME/src/phoenix` and the phoenix-makemanifest project at
`$HOME/src/makemanifest`.


```
cd ~/src/keyserver/bench
./benchmark.py --iterations 10 --trimmed-mean --nsm
/home/$USER/lib/nsm-engine.so,tcp://127.0.0.1:9000 --output-file
nsm-sgx-rsa2048.dat
```

```
cd ~/src/keyserver/server
./nsmserver tcp://127.0.0.1:9000
```

```
cd ~/src/makemanfiest
./make_sgx.py -g ~/src/phoenix -k enclave-key.pem -p
~/src/keyserver/deploy/manifest.conf -t $PWD -v -o nsmserver
cd nsmserver
cp manifest.sgx nsmserver.manifest.sgx
./nsmserver.manifest.sgx tcp://127.0.0.1:9000
```
