#!/bin/bash

bindir=${srcdir}/..

# export the parent key as a public key
if which tpm2_createprimary>/dev/null; then
tpm2_createprimary --hierarchy=o --key-algorithm=ecc256 \
                   --attributes="fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda" \
                   --key-context=srk.ctx || exit 1
tpm2_readpublic --object-context=srk.ctx --format=pem --output=srk.pub || exit 1
tpm2_flushcontext --transient-object || exit 1
else
prim=$(tsscreateprimary -ecc nistp256 -hi o -opem srk.pub | sed 's/Handle //') || exit 1
tssflushcontext -ha ${prim} || exit 1
fi

# check an EC key with a cert and password
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out key.priv || exit 1
${bindir}/create_tpm2_key --import srk.pub --wrap key.priv -a -k passw0rd key.tpm || exit 1
openssl req -new -x509 -subj '/CN=test/' -key key.tpm -passin pass:passw0rd -engine tpm2 -keyform engine -out tmp.crt || exit 1
openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || exit 1

# Check the loadability of an importable key
NV=81000201
${bindir}/load_tpm2_key key.tpm ${NV} || exit 1
openssl req -new -x509 -subj '/CN=test/' -key //nvkey:${NV} -passin pass:passw0rd -engine tpm2 -keyform engine -out tmp.crt || exit 1
openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || exit 1

#check an RSA key with a cert and policy
openssl genrsa 2048 > key.priv || exit 1
${bindir}/create_tpm2_key --import srk.pub --wrap key.priv -a -k passw0rd -c policies/policy_authvalue.txt key.tpm || exit 1
openssl req -new -x509 -subj '/CN=test/' -key key.tpm -passin pass:passw0rd -engine tpm2 -keyform engine -out tmp.crt || exit 1
openssl verify -CAfile tmp.crt -check_ss_sig tmp.crt || exit 1

