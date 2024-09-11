#!/bin/bash

#
# This script generates a self-signed CA, then signs other certs for U2F and PACKED attestation
# It also generates MDS3 metadata files for use with your FIDO server and a JSON FIDO2_CLIENT_CONFIG
# parameter that you can use in the .env file for the clients in the parent directory.
#

#
# Ideas from:
#   https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309
#   https://zonena.me/2016/02/creating-ssl-certificates-in-3-easy-steps/
#

ROOTCACERT=rootCA.pem
ROOTCAKEY=rootCA.key
ROOTCADN="/C=US/O=IBM/CN=FIDOTEST"

U2F_ATTESTATION_DN="/C=US/O=IBM/CN=U2F-SIGNER"
U2F_ATTESTATION_KEY=u2f.key
U2F_ATTESTATION_CSR=u2f.csr
U2F_ATTESTATION_CERT=u2f.pem
U2F_METADATA=fidotest-u2f.json

PACKED_ATTESTATION_DN="/C=US/O=IBM/OU=Authenticator Attestation/CN=PACKED-SIGNER"
PACKED_ATTESTATION_KEY=packed.key
PACKED_ATTESTATION_CSR=packed.csr
PACKED_ATTESTATION_CERT=packed.pem
PACKED_ATTESTATION_CONFIG=packed.config
PACKED_ATTESTATION_AAGUID=packed.aaguid
PACKED_METADATA=fidotest-packed.json

TPM_INTER_DN="/CN=FIDOTEST-TPM-INTERMEDIATE"
TPM_INTER_KEY="tpminter.key"
TPM_INTER_PUB="tpminter.pub"
TPM_INTER_CSR="tpminter.csr"
TPM_INTER_CERT="tpminter.pem"
TPM_INTER_CONFIG="tpminter.config"
TPM_ATTESTATION_DN=""
TPM_ATTESTATION_KEY="tpm.key"
TPM_ATTESTATION_PUB="tpm.pub"
TPM_ATTESTATION_CSR="tpm.csr"
TPM_ATTESTATION_CERT="tpm.pem"
TPM_ATTESTATION_CONFIG="tpm.config"
TPM_ATTESTATION_AAGUID="tpm.aaguid"
TPM_METADATA="fidotest-tpm.json"



SELF_ATTESTATION_AAGUID=self.aaguid
SELF_METADATA=fidotest-self.json

ENCRYPTION_PASSPHRASE_FILE="encpass.txt"

ICONFILE="icon.txt"

#
# Generate AAGUIDS for packed, tpm and self attestation
#
if [ ! -e "$PACKED_ATTESTATION_AAGUID" ]
then
  echo "Creating packed attestation aaguid: $PACKED_ATTESTATION_AAGUID"
  uuidgen  > "$PACKED_ATTESTATION_AAGUID"
fi
if [ ! -e "$TPM_ATTESTATION_AAGUID" ]
then
  echo "Creating tpm attestation aaguid: $TPM_ATTESTATION_AAGUID"
  uuidgen  > "$TPM_ATTESTATION_AAGUID"
fi
if [ ! -e "$SELF_ATTESTATION_AAGUID" ]
then
  echo "Creating self attestation aaguid: $SELF_ATTESTATION_AAGUID"
  uuidgen > "$SELF_ATTESTATION_AAGUID"
fi

#
# Generate a Root CA key and certificate
#
if [ ! -e "$ROOTCAKEY" ]
then
  echo "Creating Root CA key: $ROOTCAKEY"
  openssl ecparam -genkey -name prime256v1 -noout -out "$ROOTCAKEY"
fi

if [ ! -e "$ROOTCACERT" ]
then
  echo "Creating Root CA certificate: $ROOTCACERT"
  openssl req -x509 -new -nodes -key "$ROOTCAKEY" -sha256 -days 9999 -subj "$ROOTCADN" -out "$ROOTCACERT"
fi

#
# Generate a U2F attestation key and certificate, signed by the rootCA
#
if [ ! -e "$U2F_ATTESTATION_KEY" ]
then
  echo "Creating U2F key: $U2F_ATTESTATION_KEY"
  openssl ecparam -out "$U2F_ATTESTATION_KEY" -name prime256v1 -genkey
fi
if [ ! -e "$U2F_ATTESTATION_CSR" ]
then
  echo "Creating U2F CSR: $U2F_ATTESTATION_CSR"
  openssl req -new -sha256 -key "$U2F_ATTESTATION_KEY" -subj "$U2F_ATTESTATION_DN" -out "$U2F_ATTESTATION_CSR"
fi
if [ ! -e "$U2F_ATTESTATION_CERT" ]
then
  echo "Creating U2F certificate: $U2F_ATTESTATION_CERT"
  openssl x509 -req -in "$U2F_ATTESTATION_CSR" -CA "$ROOTCACERT" -CAkey "$ROOTCAKEY" -passin pass:"$PASSPHRASE" -CAcreateserial -out "$U2F_ATTESTATION_CERT" -days 9999 -sha256
fi

#
# Generate a packed attestation key and certificate, signed by the rootCA
#
if [ ! -e "$PACKED_ATTESTATION_KEY" ]
then
  echo "Creating packed key: $PACKED_ATTESTATION_KEY"
  openssl ecparam -out "$PACKED_ATTESTATION_KEY" -name prime256v1 -genkey
fi
# Generate packed CSR config file, AAGUID extension is injected as part of the last line added
PACKED_AAGUID=$(cat "$PACKED_ATTESTATION_AAGUID" | tr '[:upper:]' '[:lower:]')
PACKED_AAGUID_NODASH=$(echo "$PACKED_AAGUID" | tr -d '-' | tr '[:lower:]' '[:upper:]')
cat > "$PACKED_ATTESTATION_CONFIG" << "EOF"
[req]
distinguished_name=dn
[dn]
[ext]
basicConstraints=critical,CA:FALSE
EOF
echo "1.3.6.1.4.1.45724.1.1.4=DER:0410$PACKED_AAGUID_NODASH" >> "$PACKED_ATTESTATION_CONFIG"

if [ ! -e "$PACKED_ATTESTATION_CSR" ]
then
  echo "Creating packed CSR: $PACKED_ATTESTATION_CSR"
  openssl req -config <(cat "$PACKED_ATTESTATION_CONFIG") -reqexts ext -new -sha256 -key "$PACKED_ATTESTATION_KEY" -subj "$PACKED_ATTESTATION_DN" -out "$PACKED_ATTESTATION_CSR"
fi
if [ ! -e "$PACKED_ATTESTATION_CERT" ]
then
  echo "Creating packed certificate: $PACKED_ATTESTATION_CERT"
  openssl x509 -req -in "$PACKED_ATTESTATION_CSR" -extfile "$PACKED_ATTESTATION_CONFIG" -extensions ext -CA "$ROOTCACERT" -CAkey "$ROOTCAKEY" -passin pass:"$PASSPHRASE" -CAcreateserial -out "$PACKED_ATTESTATION_CERT" -days 9999 -sha256
fi

#
# Generate a TPM intermediate key and certificate, signed by the rootCA
#
if [ ! -e "$TPM_INTER_KEY" ]
then
  echo "Creating TPM Intermediate key: $TPM_INTER_KEY"
  openssl genrsa -out "$TPM_INTER_KEY" 2048
  rm -f "$TPM_INTER_PUB"
fi
if [ ! -e "$TPM_INTER_PUB" ]
then
  echo "Storing TPM Intermediate public key: $TPM_INTER_PUB"
  openssl rsa -in "$TPM_INTER_KEY" -inform PEM -pubout -out "$TPM_INTER_PUB"
fi

# Generate TPM Intermediate CSR config file
cat > "$TPM_INTER_CONFIG" << "EOF"
[req]
distinguished_name=dn
[dn]
[ext]
keyUsage=critical,digitalSignature,keyCertSign,cRLSign
extendedKeyUsage=1.3.6.1.4.1.311.21.36,2.23.133.8.3
basicConstraints=critical,CA:TRUE,pathlen:0
EOF

if [ ! -e "$TPM_INTER_CSR" ]
then
  echo "Creating TPM Intermediate CSR: $TPM_INTER_CSR"
  openssl req -config <(cat "$TPM_INTER_CONFIG") -reqexts ext -new -sha256 -key "$TPM_INTER_KEY" -subj "$TPM_INTER_DN" -out "$TPM_INTER_CSR"
fi
if [ ! -e "$TPM_INTER_CERT" ]
then
  echo "Creating TPM Intermediate certificate: $TPM_INTER_CERT"
  openssl x509 -req -in "$TPM_INTER_CSR" -extfile "$TPM_INTER_CONFIG" -extensions ext -CA "$ROOTCACERT" -CAkey "$ROOTCAKEY" -passin pass:"$PASSPHRASE" -CAcreateserial -out "$TPM_INTER_CERT" -days 9999 -sha256
fi

#
# Generate a TPM attestation key and certificate, signed by the TPM Intermediate
#
if [ ! -e "$TPM_ATTESTATION_KEY" ]
then
  echo "Creating TPM key: $TPM_ATTESTATION_KEY"
  openssl genrsa -out "$TPM_ATTESTATION_KEY" 2048
  rm -f "$TPM_ATTESTATION_PUB"
fi
if [ ! -e "$TPM_ATTESTATION_PUB" ]
then
  echo "Storing TPM public key: $TPM_ATTESTATION_PUB"
  openssl rsa -in "$TPM_ATTESTATION_KEY" -inform PEM -pubout -out "$TPM_ATTESTATION_PUB"
fi

#
# Generate TPM CSR config file,
# The subjectAltName extension value is provided as a magic DER encoded string since I couldn't figure out out to specify this in the config file format in plain text
#   DirName:/2.23.133.2.3=id:1+2.23.133.2.2=IBMTPM+2.23.133.2.1=id:FFFFF1D0
#
# AAGUID extension is injected as part of the last line added
#
TPM_AAGUID=$(cat "$TPM_ATTESTATION_AAGUID" | tr '[:upper:]' '[:lower:]')
TPM_AAGUID_NODASH=$(echo "$TPM_AAGUID" | tr -d '-' | tr '[:lower:]' '[:upper:]')
cat > "$TPM_ATTESTATION_CONFIG" << "EOF"
[req]
distinguished_name=dn
[dn]
[dir_sect]
+2.23.133.2.3=id:1
[ext]
keyUsage=critical,digitalSignature
extendedKeyUsage=2.23.133.8.3
basicConstraints=critical,CA:FALSE
subjectAltName=critical,DER:303CA43A30383136300D060567810502030C0469643A31300F060567810502020C0649424D54504D3014060567810502010C0B69643A4646464646314430
EOF
echo "1.3.6.1.4.1.45724.1.1.4=DER:0410$TPM_AAGUID_NODASH" >> "$TPM_ATTESTATION_CONFIG"

if [ ! -e "$TPM_ATTESTATION_CSR" ]
then
  echo "Creating TPM CSR: $TPM_ATTESTATION_CSR"
  if [ "$TPM_ATTESTATION_DN" == "" ]
  then
    # note -subj "/" parameter here when TPM_ATTESTATION_DN is empty
    openssl req -config <(cat "$TPM_ATTESTATION_CONFIG") -reqexts ext -new -sha256 -key "$TPM_ATTESTATION_KEY" -subj "/" -out "$TPM_ATTESTATION_CSR"
  else
    openssl req -config <(cat "$TPM_ATTESTATION_CONFIG") -reqexts ext -new -sha256 -key "$TPM_ATTESTATION_KEY" -subj "$TPM_ATTESTATION_DN" -out "$TPM_ATTESTATION_CSR"
  fi
fi
if [ ! -e "$TPM_ATTESTATION_CERT" ]
then
  echo "Creating TPM certificate: $TPM_ATTESTATION_CERT"
  openssl x509 -req -in "$TPM_ATTESTATION_CSR" -extfile "$TPM_ATTESTATION_CONFIG" -extensions ext -CA "$TPM_INTER_CERT" -CAkey "$TPM_INTER_KEY" -CAcreateserial -out "$TPM_ATTESTATION_CERT" -days 9999 -sha256
fi

#
# Generate the FIDO MDS3 metadata documents
#
ICON_TEXT=$(cat "$ICONFILE")
ROOTCA_TXT=$(cat "$ROOTCACERT" | grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | tr -d '\n')
PACKED_AAGUID=$(cat "$PACKED_ATTESTATION_AAGUID" | tr '[:upper:]' '[:lower:]')
TPM_AAGUID=$(cat "$TPM_ATTESTATION_AAGUID" | tr '[:upper:]' '[:lower:]')
SELF_AAGUID=$(cat "$SELF_ATTESTATION_AAGUID" | tr '[:upper:]' '[:lower:]')


if [ ! -e "$U2F_METADATA" ]
then
  echo "Generating U2F metadata file: $U2F_METADATA"
  # calculate the ski (subject key identifier) of the u2f certificate assuming it is EC256
  # The magic 26 asn1parse offset below leaps straight into the public key bitstring without COUNT of number of padding bits
  # (idea from https://security.stackexchange.com/questions/129490/why-are-there-leading-0x00-bytes-in-the-subjectpublickey-field-of-a-der-x-509-ce)
  SKI=$(openssl x509 -noout -in "$U2F_ATTESTATION_CERT" -pubkey  | openssl asn1parse -offset 26 -noout -out  - | openssl dgst -c -sha1 | sed -e "s/^SHA1(stdin)= //" | tr -d ':')
  # You could also extract it from the ski extension of the certificate
  #SKI2=$(openssl x509 -in "$U2F_ATTESTATION_CERT" -text | grep -A1 "X509v3 Subject Key Identifier" | grep -v "X509v3 Subject Key Identifier" | sed -e 's/^[[:space:]]*//g' | tr '[:upper:]' '[:lower:]' | tr -d ':')

  echo "{\"description\":\"FIDOTEST-U2F\"," \
       "\"attestationCertificateKeyIdentifiers\": [ \"$SKI\" ]," \
       "\"protocolFamily\":\"fido2\"," \
       "\"schema\":3," \
       "\"attestationTypes\": [ \"basic_full\" ]," \
       "\"attestationRootCertificates\": [ \"$ROOTCA_TXT\" ]," \
       "\"icon\": \"$ICON_TEXT\"" \
       "}" | jq '.' > "$U2F_METADATA"
fi

if [ ! -e "$PACKED_METADATA" ]
then
  echo "Generating PACKED metadata file: $PACKED_METADATA"
  echo "{\"description\":\"FIDOTEST-PACKED\"," \
       "\"aaguid\": \"$PACKED_AAGUID\"," \
       "\"protocolFamily\":\"fido2\"," \
       "\"schema\":3," \
       "\"attestationTypes\": [ \"basic_full\" ]," \
       "\"attestationRootCertificates\": [ \"$ROOTCA_TXT\" ]," \
       "\"icon\": \"$ICON_TEXT\"" \
       "}" | jq '.' > "$PACKED_METADATA"
fi

if [ ! -e "$TPM_METADATA" ]
then
  echo "Generating PACKED metadata file: $TPM_METADATA"
  echo "{\"description\":\"FIDOTEST-TPM\"," \
       "\"aaguid\": \"$TPM_AAGUID\"," \
       "\"protocolFamily\":\"fido2\"," \
       "\"schema\":3," \
       "\"attestationTypes\": [ \"attca\" ]," \
       "\"attestationRootCertificates\": [ \"$ROOTCA_TXT\" ]," \
       "\"icon\": \"$ICON_TEXT\"" \
       "}" | jq '.' > "$TPM_METADATA"
fi

if [ ! -e "$SELF_METADATA" ]
then
  echo "Generating SELF metadata file: $SELF_METADATA"
  echo "{\"description\":\"FIDOTEST-SELF\"," \
       "\"aaguid\": \"$SELF_AAGUID\"," \
       "\"protocolFamily\":\"fido2\"," \
       "\"schema\":3," \
       "\"attestationTypes\": [ \"basic_surrogate\" ]," \
       "\"icon\": \"$ICON_TEXT\"" \
       "}" | jq '.' > "$SELF_METADATA"
fi

#
# Generate an encryption passphrase
#
if [ ! -e "$ENCRYPTION_PASSPHRASE_FILE" ]
then
  echo "Generating encryption passphrase file: $ENCRYPTION_PASSPHRASE_FILE"
  openssl rand -hex 20 > "$ENCRYPTION_PASSPHRASE_FILE"
fi
ENCRYPTION_PASSPHRASE=$(cat "$ENCRYPTION_PASSPHRASE_FILE")


#
# Generate the FIDO2_CLIENT_CONFIG variable that should be used in the .env
#
U2F_PRIVATE_KEY_HEX=$(openssl ec -in "$U2F_ATTESTATION_KEY" -text 2>/dev/null | grep -A 3 "priv:" | grep -v "priv:" | sed -e 's/^[[:space:]]*//g' | tr -d '\n' | tr -d ':')
U2F_PUBLIC_KEY_HEX=$(openssl ec -in "$U2F_ATTESTATION_KEY" -text 2>/dev/null | grep -A 5 "pub:" | grep -v "pub:" | sed -e 's/^[[:space:]]*//g' | tr -d '\n' | tr -d ':')
U2F_CERT_TEXT=$(cat "$U2F_ATTESTATION_CERT" | grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | tr -d '\n')

PACKED_PRIVATE_KEY_HEX=$(openssl ec -in "$PACKED_ATTESTATION_KEY" -text 2>/dev/null | grep -A 3 "priv:" | grep -v "priv:" | sed -e 's/^[[:space:]]*//g' | tr -d '\n' | tr -d ':')
PACKED_PUBLIC_KEY_HEX=$(openssl ec -in "$PACKED_ATTESTATION_KEY" -text 2>/dev/null | grep -A 5 "pub:" | grep -v "pub:" | sed -e 's/^[[:space:]]*//g' | tr -d '\n' | tr -d ':')
PACKED_CERT_TEXT=$(cat "$PACKED_ATTESTATION_CERT" | grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | tr -d '\n')

TPM_PRIVATE_KEY_PEM=$(cat "$TPM_ATTESTATION_KEY" | tr -d '\r' | awk '{printf "%s\\r\\n", $0}')
TPM_PUBLIC_KEY_PEM=$(cat "$TPM_ATTESTATION_PUB" | tr -d '\r' | awk '{printf "%s\\r\\n", $0}')
TPM_CERT_TEXT=$(cat "$TPM_ATTESTATION_CERT" | grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | tr -d '\n')
TPM_INTER_CERT_TEXT=$(cat "$TPM_INTER_CERT" | grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | tr -d '\n')

echo "FIDO2_CLIENT_CONFIG={\"encryptionPassphrase\":\"$ENCRYPTION_PASSPHRASE\",\"fido-u2f\":{\"privateKeyHex\":\"$U2F_PRIVATE_KEY_HEX\",\"publicKeyHex\":\"$U2F_PUBLIC_KEY_HEX\",\"cert\":\"$U2F_CERT_TEXT\"},\"packed\":{\"aaguid\":\"$PACKED_AAGUID\",\"privateKeyHex\":\"$PACKED_PRIVATE_KEY_HEX\",\"publicKeyHex\":\"$PACKED_PUBLIC_KEY_HEX\",\"cert\":\"$PACKED_CERT_TEXT\"},\"tpm\":{\"aaguid\":\"$TPM_AAGUID\",\"privateKeyPEM\":\"$TPM_PRIVATE_KEY_PEM\",\"publicKeyPEM\":\"$TPM_PUBLIC_KEY_PEM\",\"cert\":\"$TPM_CERT_TEXT\",\"tpmIntercert\":\"$TPM_INTER_CERT_TEXT\"},\"packed-self\":{\"aaguid\":\"$SELF_AAGUID\"}}"
