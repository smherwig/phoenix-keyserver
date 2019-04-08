#!/bin/sh

PORT=$1

./keyserver.manifest.sgx -v -r /srv tcp://127.0.0.1:$1
