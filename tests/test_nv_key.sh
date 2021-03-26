#!/bin/bash


bindir=${srcdir}/..

##
# test is
# 1. create a no password key and move it to nvram at index 81232323
# 2. extract public part of key
# 3. verify a signature
# 4. same for a key with a password
# 5. same for key with a password and da implications
##
nvkey=81232323
auth=a4ffg6

if which tpm2_create>/dev/null; then
tpm2_create --key-algorithm=rsa --parent-context=0x81000001 \
            --attributes="sign|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda" \
            --private=key.tpmpriv --public=key.tpmpub || exit 1
tpm2_load --parent-context=0x81000001 --private=key.tpmpriv --public=key.tpmpub \
          --key-context=key.ctx || exit 1
tpm2_evictcontrol --hierarchy=o --object-context=key.ctx 0x${nvkey} || exit 1
tpm2_flushcontext --transient-object
else
tsscreate -rsa -gp -hp 81000001 -opr key.tpmpriv -opu key.tpmpub || exit 1
key=$(tssload -hp 81000001 -ipu key.tpmpub -ipr key.tpmpriv|sed 's/Handle //') || exit 1
tssevictcontrol -hi o -ho ${key} -hp ${nvkey} || exit 1
tssflushcontext -ha ${key}
fi

openssl rsa -engine tpm2 -inform engine -in //nvkey:${nvkey} -pubout -out key1.pub || exit 1
echo "This is an internal key message" | openssl rsautl -sign -engine tpm2 -engine tpm2 -keyform engine -inkey //nvkey:${nvkey} -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1

if which tpm2_evictcontrol>/dev/null; then
tpm2_evictcontrol --hierarchy=o --object-context=0x${nvkey}
else
tssevictcontrol -hi o -hp ${nvkey} -ho ${nvkey}
fi

# now set a password
if which tpm2_create>/dev/null; then
tpm2_create --key-algorithm=rsa --parent-context=0x81000001 --key-auth=${auth} \
            --attributes="sign|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda" \
            --private=key.tpmpriv --public=key.tpmpub || exit 1
tpm2_load --parent-context=0x81000001 --private=key.tpmpriv --public=key.tpmpub \
          --key-context=key.ctx || exit 1
tpm2_evictcontrol --hierarchy=o --object-context=key.ctx 0x${nvkey} || exit 1
tpm2_flushcontext --transient-object
else
tsscreate -rsa -gp -hp 81000001 -pwdk ${auth} -opr key.tpmpriv -opu key.tpmpub || exit 1
key=$(tssload -hp 81000001 -ipu key.tpmpub -ipr key.tpmpriv|sed 's/Handle //') || exit 1
tssevictcontrol -hi o -ho ${key} -hp ${nvkey} || exit 1
tssflushcontext -ha ${key}
fi

openssl rsa -engine tpm2 -inform engine -passin pass:${auth} -in //nvkey:${nvkey} -pubout -out key1.pub || exit 1
echo "This is an internal key message" | openssl rsautl -sign -passin pass:${auth} -engine tpm2 -engine tpm2 -keyform engine -inkey //nvkey:${nvkey} -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1

if which tpm2_evictcontrol>/dev/null; then
tpm2_evictcontrol --hierarchy=o --object-context=0x${nvkey}
else
tssevictcontrol -hi o -hp ${nvkey} -ho ${nvkey}
fi

# password plus DA implications
if which tpm2_create>/dev/null; then
tpm2_create --key-algorithm=rsa --parent-context=0x81000001 --key-auth=${auth} \
            --attributes="sign|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth" \
            --private=key.tpmpriv --public=key.tpmpub || exit 1
tpm2_load --parent-context=0x81000001 --private=key.tpmpriv --public=key.tpmpub \
          --key-context=key.ctx || exit 1
tpm2_evictcontrol --hierarchy=o --object-context=key.ctx 0x${nvkey} || exit 1
tpm2_flushcontext --transient-object
else
tsscreate -rsa -gp -hp 81000001 -pwdk ${auth} -da -opr key.tpmpriv -opu key.tpmpub || exit 1
key=$(tssload -hp 81000001 -ipu key.tpmpub -ipr key.tpmpriv|sed 's/Handle //') || exit 1
tssevictcontrol -hi o -ho ${key} -hp ${nvkey} || exit 1
tssflushcontext -ha ${key}
fi

openssl rsa -engine tpm2 -inform engine -passin pass:${auth} -in //nvkey:${nvkey} -pubout -out key1.pub || exit 1
echo "This is an internal key message" | openssl rsautl -sign -passin pass:${auth} -engine tpm2 -engine tpm2 -keyform engine -inkey //nvkey:${nvkey} -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1

if which tpm2_evictcontrol>/dev/null; then
tpm2_evictcontrol --hierarchy=o --object-context=0x${nvkey}
else
tssevictcontrol -hi o -hp ${nvkey} -ho ${nvkey}
fi

# try with a different nvprefix
if which tpm2_create>/dev/null; then
tpm2_create --key-algorithm=rsa --parent-context=0x81000001 \
            --attributes="sign|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda" \
            --private=key.tpmpriv --public=key.tpmpub || exit 1
tpm2_load --parent-context=0x81000001 --private=key.tpmpriv --public=key.tpmpub \
          --key-context=key.ctx || exit 1
tpm2_evictcontrol --hierarchy=o --object-context=key.ctx 0x${nvkey} || exit 1
tpm2_flushcontext --transient-object
else
tsscreate -rsa -gp -hp 81000001 -opr key.tpmpriv -opu key.tpmpub || exit 1
key=$(tssload -hp 81000001 -ipu key.tpmpub -ipr key.tpmpriv|sed 's/Handle //') || exit 1
tssevictcontrol -hi o -ho ${key} -hp ${nvkey} || exit 1
tssflushcontext -ha ${key}
fi

openssl rsa -engine tpm2 -inform engine -passin pass:${auth} -in //nvkey:${nvkey} -pubout -out key1.pub || exit 1
export NVPREFIX="wibble:"
echo "This is an internal key message" | openssl rsautl -sign -passin pass:${auth} -engine tpm2 -engine tpm2 -keyform engine -inkey ${NVPREFIX}${nvkey} -out tmp.msg || exit 1
openssl rsautl -verify -in tmp.msg -inkey key1.pub -pubin || exit 1

if which tpm2_evictcontrol>/dev/null; then
tpm2_evictcontrol --hierarchy=o --object-context=0x${nvkey}
else
tssevictcontrol -hi o -hp ${nvkey} -ho ${nvkey}
fi

exit 0
