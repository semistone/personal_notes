openssl req -new -x509 -keyout ca-key -out ca-cert -days 365
keytool  -keystore truststore.jks -alias CARoot -import -file ca-cert  -storepass password
