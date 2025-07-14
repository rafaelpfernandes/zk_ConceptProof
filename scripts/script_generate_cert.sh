#!/bin/bash

# Add the proof to the certificate config
sed -i "s|^1\.2\.3\.4\.5\.6\.7\.8 =.*|1.2.3.4.5.6.7.8 = ASN1:OCTETSTRING:$(cat "${9}" | tr -d '\n\r')|" /home/rafael/demoCA/conf/openssl-proof.cnf

# Generate the keys
sudo openssl genrsa -out /home/rafael/site/sk_pk.key.pem 2048

# Certificate Request
sudo openssl req -new -key /home/rafael/site/sk_pk.key.pem -out /home/rafael/site/request.csr.pem -config /home/rafael/demoCA/conf/openssl-proof.cnf -subj "/C=$7/ST=$6/L=$5/O=$3/OU=$4/CN=$2/emailAddress=$8"

# Sign the certificate
sudo openssl ca -batch -config /home/rafael/demoCA/conf/openssl-ca.cnf -in /home/rafael/site/request.csr.pem -out /home/rafael/site/certificadoF.crt

# Convert to .p12 format (accepted by the system on import)
sudo openssl pkcs12 -export -out /home/rafael/site/certificate.p12 -inkey /home/rafael/site/sk_pk.key.pem -in /home/rafael/site/certificadoF.crt -passout pass:

sudo chmod 644 /home/rafael/site/certificate.p12
