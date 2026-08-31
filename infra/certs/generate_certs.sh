#!/bin/bash
set -e
DIR="$(dirname "$0")"
cd "$DIR"
echo "[*] Generating CA and mTLS certs in $PWD"

# CA
if [ ! -f ca.key ]; then
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=MiniSOC-CA"
  echo "[+] CA ca.crt"
else
  echo "[=] CA exists"
fi

gen_cert() {
  NAME=$1
  CN=$2
  openssl genrsa -out ${NAME}.key 2048
  openssl req -new -key ${NAME}.key -out ${NAME}.csr -subj "/CN=${CN}"
  cat > ${NAME}.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${CN}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
  openssl x509 -req -in ${NAME}.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out ${NAME}.crt -days 365 -sha256 -extfile ${NAME}.ext
  rm ${NAME}.csr ${NAME}.ext
  echo "[+] ${NAME}.crt CN=${CN}"
}

gen_cert api api
gen_cert siem siem
gen_cert client client

chmod 600 *.key
chmod 644 *.crt
ls -lh
echo "[*] Verify"
openssl verify -CAfile ca.crt api.crt
openssl verify -CAfile ca.crt siem.crt
openssl verify -CAfile ca.crt client.crt
echo "[✓] mTLS certs ready — set MTLS_ENABLED=true to enforce"
