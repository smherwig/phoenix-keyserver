#!/bin/sh

PORT=$1

./nsmserver.manifest.sgx -v -r /srv tcp://127.0.0.1:$1
