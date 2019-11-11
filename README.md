Overview
========

Private key server for the [Phoenix](https://github.com/smherwig/phoenix) SGX
microkernel.  The keyserver is also called *nsmserver* (Network Security Module
server), and has a companion OpenSSL engine called *nsm-engine*.


<a name="building"/> Building and Installing
============================================

The keyserver depends on [librho](https://github.com/smherwig/librho) and
[librpc](https://github.com/smherwig/phoenix-librpc).
I assume that dependencies are installed under `$HOME`; modify the keyserver's
Makefiles if this is not the case.


Download and build the keyserver, `nsmserver`:

```
cd ~/src
git clone https://github.com/smherwig/phoenix-keyserver keyserver
cd keyserver/server
make
```

Build and install the nsm OpenSSL engine, `nsm-engine.so`:

```
cd ~/src/keyserver/nsm-engine
make
make install INSTALL_TOP=$HOME
```


<a name="packaging"/> Packaging
===============================

To package the keyserver to run on Graphene, first build the
[phoenix](https://github.com/smherwig/phoenix#building) libOS and clone the
[makemanifest](https://github.com/smherwig/phoenix-makemanifest) configuration
packager.  The instructions here assume that the phoenix source is located at
`$HOME/src/phoenix` and the makemanifest project at `$HOME/src/makemanifest`.


The keyserver can then be packaged with the commands:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix  -k ~/share/phoenix/enclave-key.pem -p ~/src/keyserver/deploy/manifest.conf -t $PWD -v -o nsmserver
```

To run the keyserver, enter:

```
./nsmserver.manifest.sgx -r /srv tcp://127.0.0.1:9000
```

This assumes that private keys are kept under the Graphene path `/srv` (which
`manifest.conf` maps to the host's `$HOME/src/keyserver/server`
directory)


<a name="micro-benchmarks"/> Micro-benchmarks
=============================================

To evaluate the keyserver's performance, we use the script
`~/src/keyserver/bench/benchmark.py` to measure the number of RSA-2048
signatures computed in 10 seconds.
Under the hood, the  script invokes the `openssl speed` command.  The script
has options to repeat the test a number of times and compute the 30% trimmed
mean of all runs.

For all tests, `benchmark.py` runs outside fo an enclave.  We benchmark OpenSSL

1.  running without the keyserver (`OpenSSL non-SGX`)
2.  running with a non-enclave keyserver (`non-SGX`)
3.  running with a enclaved keyserver (`SGX`)
4.  running with an enclaved keyserver that makes exitless system calls
    (`exitless`)


OpenSSL non-SGX
---------------

```
cd  ~/src/keyserver/bench
./benchmark.py --iterations 10 --trimmed-mean --output-file linux-rsa2048.dat
```

An example `linux-rsa2048.dat` output is:

```
1 1597.575000 6.347194
```

where the first column (`1`) is the number of concurrent processes computing
RSA signatures (`openssl speed`'s `-multi` option), the second column
(`1597.575000`) the 30% trimmed mean signs per second (here, the average of the
middle four runs), and `6.347194` the standard deviation of the middle
four runs.


Keyserver
---------

In order to run the benchmarks on the nsmserver, the nsmserver and nsm-engine
must both be built with the `-DNSM_DO_BENCH` define, and then re-installed.

For nsmserver, edit `~/src/keyserver/server/Makefile`:

```
CPPFLAGS= $(INCLUDES) -DNSM_DO_BENCH
#CPPFLAGS= $(INCLUDES)
```

and re-compile:

```
make clean; make
```

For nsm-engine, edit `~/src/keyserver/nsm-engine/Makefile`:

```
CFLAGS = -fPIC -Wall -Werror -I $(HOME)/include -I $(PWD)/../common \
                  -DNSM_DO_BENCH
#CFLAGS = -fPIC -Wall -Werror -I $(HOME)/include -I $(PWD)/../common
```

and re-compile and re-install:

```
make clean; make; make install INSTALL_TOP=$HOME
```

The reason for the special compilation is that the `openssl speed` command
hardcodes the key pairs for the RSA test, and the nsmserver and nsm-engine must
be made aware that this key pair should be used.


### non-SGX

In one terminal, run the nsmserver outside of an enclave:

```
cd ~/src/keyserver/server
./nsmserver tcp://127.0.0.1:9000
```

In a second terminal, run the `benchmark.py`:

```
cd ~/src/keyserver/bench ./benchmark.py --iterations 10 --trimmed-mean --nsm $HOME/lib/nsm-engine.so,tcp://127.0.0.1:9000 --output-file nsm-nonsgx-rsa2048.dat
```


### <a name="microbench-keyserver-sgx"/> SGX

Ensure that `~/src/keyserver/deploy/manifest.conf` has the directive:

```
THREADS 1
```

Follow the steps to [package](#packaging) the nsmserver.

In one terminal, run the nsmserver on Graphene:

```
cd ~/src/makemanifest/nsmsserver
./nsmserver.manifest.sgx tcp://127.0.0.1:9000
```

In a second terminal, run `benchmark.py`:

```
cd ~/src/keyserver/bench
./benchmark.py --iterations 10 --trimmed-mean --nsm $HOME/lib/nsm-engine.so,tcp://127.0.0.1:9000 --output-file nsm-sgx-rsa2048.dat
```

### exitless

Ensure that `~/src/keyserver/deploy/manifest.conf` has the directive:

```
THREADS 1 exitless
```

Repeat as before for [SGX](#microbench-keyserver-sgx), using an output file of
`nsm-exitless-rsa2048.dat` for `benchmark.py`.
