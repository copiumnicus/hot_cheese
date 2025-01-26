#!/bin/bash
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout src/conf/ssl-key.pem -out src/conf/ssl-cert.pem \
    -days 865 \
    -subj "/CN=localhost" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"