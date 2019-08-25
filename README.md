# phoenix-keyserver
Private key server for the Phoenix SGX microkernel


# Deployment

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


