#!/bin/bash

base64 /home/rafael/project/zkp_data.txt > /home/rafael/project/zkp_data.b64

CONTENT_FROM_ZK=$(cat /home/rafael/project/zkp_data.b64 | tr -d '\n\r')

sed -i "s|^1\.2\.3\.4\.5\.6\.7\.8 =.*|1.2.3.4.5.6.7.8 = ASN1:OCTETSTRING:${CONTENT_FROM_ZK}|" /home/rafael/demoCA/conf/openssl-proof.cnf
