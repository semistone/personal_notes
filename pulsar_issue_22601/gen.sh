openssl genrsa -out bookkeeper.key.pem 2048
openssl pkcs8 -topk8 -inform PEM -outform PEM -in bookkeeper.key.pem -out bookkeeper.key-pk8.pem -nocrypt
openssl req -new -config bookkeeper.conf -key bookkeeper.key.pem -out bookkeeper.csr.pem -sha256
openssl x509 -req -in bookkeeper.csr.pem -CA ca-cert -CAkey ca-key -CAcreateserial -out `hostname`.cer  -days 36500 -extensions v3_ext -extfile bookkeeper.conf -sha2
56
openssl pkcs12  -export  -inkey bookkeeper.key.pem -name `hostname` -in `hostname`.cer -out bookkeeper.p12 -passin  pass: -passout pass:password

keytool -importkeystore -srckeystore bookkeeper.p12 -destkeystore keystore.jks  -srcstoretype pkcs12  -storepass password -srcstorepass password -alias `hostname` --
noprompt
keytool  -keystore truststore.jks -alias `hostname` -import -file `hostname`.cer  -storepass password
