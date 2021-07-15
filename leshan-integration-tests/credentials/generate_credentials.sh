#!/bin/bash

# Keystore parameters

CLIENT_STORE=clientKeyStore.jks
CLIENT_STORE_PWD=client
SERVER_STORE=serverKeyStore.jks
SERVER_STORE_PWD=server
TRUSTED_CA_STORE=trustedCaKeyStore.jks
TRUSTED_CA_STORE_PWD=trusted
MANUFACTURER_CA_STORE=manufacturerCaKeyStore.jks
MANUFACTURER_CA_STORE_PWD=manufacturer
UNKNOWN_CA_STORE=unknownCaKeyStore.jks
UNKNOWN_CA_STORE_PWD=unknown

VALIDITY=36500 #days
DEFAULT_STORE_TYPE=JKS #PKCS12 is not supported by Java7

# Color output stuff
red=`tput setaf 1`
green=`tput setaf 2`
blue=`tput setaf 4`
bold=`tput bold`
H1=${green}${bold} 
H2=${blue} 
RESET=`tput sgr0`

# Generation of the Trusted CA keystore needed for Leshan integration tests.
echo "${H1}Trusted CA Keystore : ${RESET}"
echo "${H1}======================${RESET}"
echo "${H2}Creating the trusted root CA key and certificate...${RESET}"
keytool -genkeypair -alias rootCA -keyalg EC -dname 'CN=Leshan root CA' \
        -validity $VALIDITY \
        -storetype $DEFAULT_STORE_TYPE \
        -ext BasicConstraints:critical=ca:true \
        -ext KeyUsage:critical=keyCertSign,cRLSign \
        -keypass $TRUSTED_CA_STORE_PWD -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD
keytool -exportcert -alias rootCA -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD -file rootCA.der
echo
echo "${H2}Creating the intermediate CA key and certificate...${RESET}"
keytool -genkeypair -alias intermediateCA -keyalg EC -dname 'CN=Leshan intermediate CA' \
        -validity $VALIDITY \
        -storetype $DEFAULT_STORE_TYPE \
        -ext BasicConstraints:critical=ca:true,pathlen:0 \
        -ext KeyUsage:critical=keyCertSign,cRLSign \
        -keypass $TRUSTED_CA_STORE_PWD -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD
echo
keytool -certreq -alias intermediateCA -dname 'CN=Leshan intermediate CA' -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD | \
  keytool -gencert -alias rootCA -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD \
        -validity $VALIDITY \
        -ext BasicConstraints:critical=ca:true,pathlen:0 \
        -ext KeyUsage:critical=keyCertSign,cRLSign | \
  keytool -importcert -alias intermediateCA -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD
keytool -exportcert -alias intermediateCA -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD -file intermediateCA.der
echo

# Generation of the Manufacturer CA keystore needed for Leshan integration tests.
echo "${H1}Manufacturer CA Keystore : ${RESET}"
echo "${H1}======================${RESET}"
echo "${H2}Creating the trusted root CA key and certificate...${RESET}"
keytool -genkeypair -alias mfgProductsRootCA -keyalg EC -dname 'CN=Products Root CA,O=Manufacturer' \
        -validity $VALIDITY \
        -storetype $DEFAULT_STORE_TYPE \
        -ext BasicConstraints:critical=ca:true \
        -ext KeyUsage:critical=keyCertSign,cRLSign \
        -keypass $MANUFACTURER_CA_STORE_PWD -keystore $MANUFACTURER_CA_STORE -storepass $MANUFACTURER_CA_STORE_PWD 
keytool -exportcert -alias mfgProductsRootCA -keystore $MANUFACTURER_CA_STORE -storepass $MANUFACTURER_CA_STORE_PWD -file mfgProductsRootCA.der
echo
echo "${H2}Creating the Devices CA key and certificate...${RESET}"
keytool -genkeypair -alias mfgDevicesCA -keyalg EC -dname 'CN=Devices CA,O=Manufacturer' \
        -validity $VALIDITY \
        -storetype $DEFAULT_STORE_TYPE \
        -ext BasicConstraints:critical=ca:true,pathlen:0 \
        -ext KeyUsage:critical=keyCertSign,cRLSign \
        -keypass $MANUFACTURER_CA_STORE_PWD -keystore $MANUFACTURER_CA_STORE -storepass $MANUFACTURER_CA_STORE_PWD
echo
keytool -certreq -alias mfgDevicesCA -dname 'CN=Devices CA,O=Manufacturer' -keystore $MANUFACTURER_CA_STORE -storepass $MANUFACTURER_CA_STORE_PWD | \
  keytool -gencert -alias mfgProductsRootCA -keystore $MANUFACTURER_CA_STORE -storepass $MANUFACTURER_CA_STORE_PWD \
        -validity $VALIDITY \
        -ext BasicConstraints:critical=ca:true,pathlen:0 \
        -ext KeyUsage:critical=keyCertSign,cRLSign | \
    keytool -importcert -alias mfgDevicesCA -keystore $MANUFACTURER_CA_STORE -storepass $MANUFACTURER_CA_STORE_PWD
keytool -exportcert -alias mfgDevicesCA -keystore $MANUFACTURER_CA_STORE -storepass $MANUFACTURER_CA_STORE_PWD -file mfgDevicesCA.der
echo

# Generation of the Unknown CA keystore needed for Leshan integration tests.
echo "${H1}Unknown CA Keystore : ${RESET}"
echo "${H1}======================${RESET}"
echo "${H2}Creating an untrusted root CA key and certificate...${RESET}"
keytool -genkeypair -alias untrustedRootCA -keyalg EC -dname 'CN=Leshan untrusted root CA' \
        -validity $VALIDITY \
        -storetype $DEFAULT_STORE_TYPE \
        -ext BasicConstraints:critical=ca:true \
        -ext KeyUsage:critical=keyCertSign,cRLSign \
        -keypass $UNKNOWN_CA_STORE_PWD -keystore $UNKNOWN_CA_STORE -storepass $UNKNOWN_CA_STORE_PWD
keytool -exportcert -alias untrustedRootCA -keystore $UNKNOWN_CA_STORE -storepass $UNKNOWN_CA_STORE_PWD -file untrustedRootCA.der
echo
# Generation of the keystore needed for Leshan integration tests.
echo "${H1}Server Keystore : ${RESET}"
echo "${H1}==================${RESET}"
echo "${H2}Creating server key and self-signed certificate ...${RESET}"
keytool -genkeypair -alias server -keyalg EC -dname 'CN=localhost' \
        -validity $VALIDITY \
        -storetype $DEFAULT_STORE_TYPE \
        -ext BasicConstraints=ca:false \
        -ext KeyUsage:critical=digitalSignature,keyAgreement \
        -ext ExtendedkeyUsage=serverAuth,clientAuth \
        -keypass $SERVER_STORE_PWD -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD
keytool -exportcert -alias server -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD | \
  keytool -importcert -alias server_self_signed -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD -noprompt

echo
echo "${H2}Creating second server key and self-signed certificate ...${RESET}"
keytool -genkeypair -alias serverInt -keyalg EC -dname 'CN=Server signed with Intermediate CA' -ext san=dns:localhost \
        -validity $VALIDITY \
        -storetype $DEFAULT_STORE_TYPE \
        -ext BasicConstraints=ca:false \
        -ext KeyUsage:critical=digitalSignature,keyAgreement \
        -ext ExtendedkeyUsage=serverAuth,clientAuth \
        -keypass $SERVER_STORE_PWD -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD
keytool -exportcert -alias serverInt -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD | \
  keytool -importcert -alias serverInt_self_signed -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD -noprompt
echo
echo "${H2}Importing Root CA certificate ...${RESET}"
keytool -importcert -alias rootCA -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD -noprompt -file rootCA.der
echo
echo "${H2}Importing Intermediate CA certificate ...${RESET}"
keytool -importcert -alias intermediateCA -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD -noprompt -file intermediateCA.der
echo
echo "${H2}Creating server certificate signed by root CA...${RESET}"
keytool -certreq -alias server -dname 'CN=localhost' -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD | \
  keytool -gencert -alias rootCA -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD \
          -validity $VALIDITY \
          -ext BasicConstraints=ca:false \
          -ext KeyUsage:critical=digitalSignature,keyAgreement \
          -ext ExtendedkeyUsage=serverAuth,clientAuth | \
    keytool -importcert -alias server -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD
echo
echo "${H2}Creating server certificate signed by intermediate CA...${RESET}"
keytool -certreq -alias serverInt -dname 'CN=Server signed with Intermediate CA' -ext san=dns:localhost -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD | \
  keytool -gencert -alias intermediateCA -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD \
          -validity $VALIDITY \
          -ext BasicConstraints=ca:false \
          -ext KeyUsage:critical=digitalSignature,keyAgreement \
          -ext ExtendedkeyUsage=serverAuth,clientAuth \
          -ext san=dns:localhost | \
    keytool -importcert -alias serverInt -keystore $SERVER_STORE -storepass $SERVER_STORE_PWD

echo
echo "${H1}Client Keystore : ${RESET}"
echo "${H1}==================${RESET}"
echo "${H2}Creating client key and self-signed certificate with expected CN...${RESET}"
keytool -genkeypair -alias client -keyalg EC -dname 'CN=leshan_integration_test' \
        -validity $VALIDITY \
        -storetype $DEFAULT_STORE_TYPE \
        -ext BasicConstraints=ca:false \
        -ext KeyUsage:critical=digitalSignature,keyAgreement \
        -ext ExtendedkeyUsage=serverAuth,clientAuth \
        -keypass $CLIENT_STORE_PWD -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD
keytool -exportcert -alias client -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD | \
  keytool -importcert -alias client_self_signed -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD -noprompt
echo
echo "${H2}Import root certificate just to be able to sign certificate ...${RESET}"
keytool -importcert -alias rootCA -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD -noprompt -file rootCA.der
echo
echo "${H2}Creating client certificate signed by root CA with expected CN...${RESET}"
keytool -certreq -alias client -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD | \
  keytool -gencert -alias rootCA -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD \
          -validity $VALIDITY \
          -ext BasicConstraints=ca:false \
          -ext KeyUsage:critical=digitalSignature,keyAgreement \
          -ext ExtendedkeyUsage=serverAuth,clientAuth | \
    keytool -importcert -alias client -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD -noprompt
echo
echo "${H2}Creating client certificate signed by root CA with bad/unexpected CN...${RESET}"
keytool -certreq -alias client -dname 'CN=leshan_client_with_bad_cn' -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD | \
  keytool -gencert -alias rootCA -keystore $TRUSTED_CA_STORE -storepass $TRUSTED_CA_STORE_PWD \
          -validity $VALIDITY \
          -ext BasicConstraints=ca:false \
          -ext KeyUsage:critical=digitalSignature,keyAgreement \
          -ext ExtendedkeyUsage=serverAuth,clientAuth | \
    keytool -importcert -alias client_bad_cn -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD -noprompt
echo
echo "${H2}Creating client certificate signed by untrusted root CA with expected CN...${RESET}"
keytool -certreq -alias client -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD | \
  keytool -gencert -alias untrustedRootCA -keystore $UNKNOWN_CA_STORE -storepass $UNKNOWN_CA_STORE_PWD \
          -validity $VALIDITY \
          -ext BasicConstraints=ca:false \
          -ext KeyUsage:critical=digitalSignature,keyAgreement \
          -ext ExtendedkeyUsage=serverAuth,clientAuth | \
    keytool -importcert -alias client_not_trusted -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD -noprompt
echo
echo "${H2}Creating mfg client key and self-signed certificate with expected CN...${RESET}"
keytool -genkeypair -alias mfgClient -keyalg EC -dname 'CN=urn:dev:ops:32473-IoT_Device-K1234567,O=Manufacturer' \
        -validity $VALIDITY \
        -storetype $DEFAULT_STORE_TYPE \
        -ext BasicConstraints=ca:false \
        -ext KeyUsage:critical=digitalSignature,keyAgreement \
        -ext ExtendedkeyUsage=serverAuth,clientAuth \
        -keypass $CLIENT_STORE_PWD -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD
echo
echo "${H2}Import mfg products root CA certificate just to be able to sign certificate ...${RESET}"
keytool -importcert -alias mfgProductsRootCA -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD -noprompt -file mfgProductsRootCA.der
echo
echo "${H2}Import mfg devices CA certificate just to be able to sign certificate ...${RESET}"
keytool -importcert -alias mfgDevicesCA -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD -noprompt -file mfgDevicesCA.der
echo
echo "${H2}Creating mfg client certificate signed by root CA with expected CN...${RESET}"
keytool -certreq -alias mfgClient -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD | \
  keytool -gencert -alias mfgDevicesCA -keystore $MANUFACTURER_CA_STORE -storepass $MANUFACTURER_CA_STORE_PWD \
          -validity $VALIDITY \
          -ext BasicConstraints=ca:false \
          -ext KeyUsage:critical=digitalSignature,keyAgreement \
          -ext ExtendedkeyUsage=serverAuth,clientAuth | \
    keytool -importcert -alias mfgClient -keystore $CLIENT_STORE -storepass $CLIENT_STORE_PWD -noprompt
