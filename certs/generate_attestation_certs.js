//
// generate_attestation_certs.js 
// 

//
// This script generates a self-signed CA, then signs other certs for U2F, PACKED and TPM attestation
// It also generates MDS3 metadata files for use with your FIDO server and a JSON FIDO2_CLIENT_CONFIG
// parameter that you can use in the .env file for the clients in the parent directory.
//

const fs = require('fs');
const jsrsasign = require('jsrsasign'); // https://www.npmjs.com/package/jsrsasign
const crypto = require('node:crypto');
const fidoutils = require('../fidoutils.js');

let ROOTCACERT="rootCA.pem"
let ROOTCAKEY="rootCA.key"
let ROOTCADN="/C=US/O=IBM/CN=FIDOTEST"

let U2F_ATTESTATION_DN="/C=US/O=IBM/CN=U2F-SIGNER"
let U2F_ATTESTATION_KEY="u2f.key"
let U2F_ATTESTATION_CERT="u2f.pem"
let U2F_METADATA="fidotest-u2f.json"

let PACKED_ATTESTATION_DN="/C=US/O=IBM/OU=Authenticator Attestation/CN=PACKED-SIGNER"
let PACKED_ATTESTATION_KEY="packed.key"
let PACKED_ATTESTATION_CERT="packed.pem"
let PACKED_ATTESTATION_AAGUID="packed.aaguid"
let PACKED_METADATA="fidotest-packed.json"

let TPM_INTER_DN="/CN=FIDOTEST-TPM-INTERMEDIATE"
let TPM_INTER_KEY="tpminter.key"
let TPM_INTER_PUB="tpminter.pub"
let TPM_INTER_CERT="tpminter.pem"

let TPM_ATTESTATION_DN=""
let TPM_ATTESTATION_KEY="tpm.key"
let TPM_ATTESTATION_PUB="tpm.pub"
let TPM_ATTESTATION_CERT="tpm.pem"
let TPM_ATTESTATION_AAGUID="tpm.aaguid"
let TPM_METADATA="fidotest-tpm.json"

let SELF_ATTESTATION_AAGUID="self.aaguid"
let SELF_METADATA="fidotest-self.json"

let ENCRYPTION_PASSPHRASE_FILE="encpass.txt"

let ICONFILE="icon.txt"


//
// Utility functions
//

function pad(num, size) {
    num = num.toString();
    while (num.length < size) num = "0" + num;
    return num;
}

// returns asn.1 GeneralizedTime from a Javascript Date
function dateToASN1GeneralizedTime(d) {
    return (pad(d.getUTCFullYear(),2) + pad(d.getUTCMonth()+1,2) + pad(d.getUTCDate(),2) + pad(d.getUTCHours(), 2) + pad(d.getUTCMinutes(),2) + pad(d.getUTCSeconds(),2) + 'Z');
}

function generateRandomSerialNumberHex() {
    // random bytes, but lets at least make sure its not negative by making sure the left-most bit is 0
    let randHex = jsrsasign.KJUR.crypto.Util.getRandomHexOfNbytes(16);
    let randBytes = jsrsasign.b64toBA(jsrsasign.hextob64(randHex));
    randBytes[0] &= 0x7F;
    return jsrsasign.BAtohex(randBytes);
}

//
// The main code entry point is here
//

//
// Generate AAGUIDs for packed, tpm and self attestation
//
let packedAttestationAAGUID = null;
if (!fs.existsSync(PACKED_ATTESTATION_AAGUID)) {
    packedAttestationAAGUID = crypto.randomUUID().toLowerCase();
    fs.writeFileSync(PACKED_ATTESTATION_AAGUID, packedAttestationAAGUID);
} else {
    packedAttestationAAGUID = fs.readFileSync(PACKED_ATTESTATION_AAGUID).toString().replaceAll('\n','').toLowerCase();
}
//console.log("packedAttestationAAGUID: " + packedAttestationAAGUID);

let tpmAttestationAAGUID = null;
if (!fs.existsSync(TPM_ATTESTATION_AAGUID)) {
    tpmAttestationAAGUID = crypto.randomUUID().toLowerCase();
    fs.writeFileSync(TPM_ATTESTATION_AAGUID, tpmAttestationAAGUID);
} else {
    tpmAttestationAAGUID = fs.readFileSync(TPM_ATTESTATION_AAGUID).toString().replaceAll('\n','').toLowerCase();
}
//console.log("tpmAttestationAAGUID: " + tpmAttestationAAGUID);

let selfAttestationAAGUID = null;
if (!fs.existsSync(SELF_ATTESTATION_AAGUID)) {
    selfAttestationAAGUID = crypto.randomUUID().toLowerCase();
    fs.writeFileSync(SELF_ATTESTATION_AAGUID, selfAttestationAAGUID);
} else {
    selfAttestationAAGUID = fs.readFileSync(SELF_ATTESTATION_AAGUID).toString().replaceAll('\n','').toLowerCase();
}
//console.log("selfAttestationAAGUID: " + selfAttestationAAGUID);

//
// Generate (or read from existing files) a Root CA keypair and certificate
//
let rootCAPublicKeyPEM = null;
let rootCAPrivateKeyPEM = null;
if (!fs.existsSync(ROOTCAKEY)) {
    console.log("Creating Root CA key: " + ROOTCAKEY);
    let kp = jsrsasign.KEYUTIL.generateKeypair("EC", "secp256r1");
    rootCAPublicKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.pubKeyObj, "PKCS8PUB");
    rootCAPrivateKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.prvKeyObj, "PKCS8PRV");
    fs.writeFileSync(ROOTCAKEY, rootCAPrivateKeyPEM);
} else {
    // read in existing root CA private key PEM from file and extract public key and convert to PEM
    rootCAPrivateKeyPEM = fs.readFileSync(ROOTCAKEY).toString();
    let prvKey = jsrsasign.KEYUTIL.getKey(rootCAPrivateKeyPEM);
    rootCAPublicKeyPEM = fidoutils.certToPEM(jsrsasign.b64toBA(jsrsasign.hextob64(prvKey.pubKeyHex)));
}
//console.log('rootCAPublicKeyPEM: ' + rootCAPublicKeyPEM);
//console.log('rootCAPrivateKeyPEM: ' + rootCAPrivateKeyPEM);

let rootCAPEM = null;
if (!fs.existsSync(ROOTCACERT)) {
    console.log("Creating Root CA certificate: " + ROOTCACERT);

    let notBeforeDate = new Date();
    let notAfterDate = new Date();
    // same as -days 9999 for openssl
    notAfterDate.setDate(notAfterDate.getDate() + 9999);

    let cert = new jsrsasign.asn1.x509.Certificate({
        version: 3,
        serial: {hex: generateRandomSerialNumberHex()},
        subject: {str: ROOTCADN},
        issuer: {str: ROOTCADN},
        notbefore: { type: 'gen', str: dateToASN1GeneralizedTime(notBeforeDate) },
        notafter: { type: 'gen', str: dateToASN1GeneralizedTime(notAfterDate) },
        sbjpubkey: rootCAPublicKeyPEM,
        ext: [
            {extname: "basicConstraints", cA: true, critical: true},
            {extname: "subjectKeyIdentifier", kid: rootCAPublicKeyPEM},
            {extname: "authorityKeyIdentifier", kid: rootCAPublicKeyPEM}
        ],
        sigalg: "SHA256withECDSA",
        cakey: rootCAPrivateKeyPEM
    });

    rootCAPEM = cert.getPEM();
    fs.writeFileSync(ROOTCACERT, rootCAPEM);
} else {
    rootCAPEM = fs.readFileSync(ROOTCACERT).toString();
}
//console.log('rootCAPEM: ' + rootCAPEM);


//
// Generate (or read from existing files) a U2F attestation key and certificate, signed by the rootCA
//
let u2fPublicKeyPEM = null;
let u2fPrivateKeyPEM = null;
if (!fs.existsSync(U2F_ATTESTATION_KEY)) {
    console.log("Creating U2F key: " + U2F_ATTESTATION_KEY);
    let kp = jsrsasign.KEYUTIL.generateKeypair("EC", "secp256r1");
    u2fPublicKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.pubKeyObj, "PKCS8PUB");
    u2fPrivateKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.prvKeyObj, "PKCS8PRV");
    fs.writeFileSync(U2F_ATTESTATION_KEY, u2fPrivateKeyPEM);
} else {
    // read in existing U2F private key PEM from file and extract public key and convert to PEM
    u2fPrivateKeyPEM = fs.readFileSync(U2F_ATTESTATION_KEY).toString();
    let prvKey = jsrsasign.KEYUTIL.getKey(u2fPrivateKeyPEM);
    u2fPublicKeyPEM = fidoutils.certToPEM(jsrsasign.b64toBA(jsrsasign.hextob64(prvKey.pubKeyHex)));
}
//console.log('u2fPublicKeyPEM: ' + u2fPublicKeyPEM);
//console.log('u2fPrivateKeyPEM: ' + u2fPrivateKeyPEM);

let u2fAttestationCertificatePEM = null;
if (!fs.existsSync(U2F_ATTESTATION_CERT)) {
    console.log("Creating U2F certificate: " + U2F_ATTESTATION_CERT);

    let notBeforeDate = new Date();
    let notAfterDate = new Date();
    // same as -days 9999 for openssl
    notAfterDate.setDate(notAfterDate.getDate() + 9999);

    let cert = new jsrsasign.asn1.x509.Certificate({
        version: 3,
        serial: {hex: generateRandomSerialNumberHex()},
        subject: {str: U2F_ATTESTATION_DN},
        issuer: {str: ROOTCADN},
        notbefore: { type: 'gen', str: dateToASN1GeneralizedTime(notBeforeDate) },
        notafter: { type: 'gen', str: dateToASN1GeneralizedTime(notAfterDate) },
        sbjpubkey: u2fPublicKeyPEM,
        ext: [
            {extname: "subjectKeyIdentifier", kid: u2fPublicKeyPEM},
            {extname: "authorityKeyIdentifier", kid: rootCAPublicKeyPEM}
        ],
        sigalg: "SHA256withECDSA",
        cakey: rootCAPrivateKeyPEM
    });

    u2fAttestationCertificatePEM = cert.getPEM();
    fs.writeFileSync(U2F_ATTESTATION_CERT, u2fAttestationCertificatePEM);
} else {
    u2fAttestationCertificatePEM = fs.readFileSync(U2F_ATTESTATION_CERT).toString();
}
//console.log('u2fAttestationCertificatePEM: ' + u2fAttestationCertificatePEM);


//
// Generate (or read from existing files) a packed attestation key and certificate, signed by the rootCA
//
let packedPublicKeyPEM = null;
let packedPrivateKeyPEM = null;
if (!fs.existsSync(PACKED_ATTESTATION_KEY)) {
    console.log("Creating packed key: " + PACKED_ATTESTATION_KEY);
    let kp = jsrsasign.KEYUTIL.generateKeypair("EC", "secp256r1");
    packedPublicKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.pubKeyObj, "PKCS8PUB");
    packedPrivateKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.prvKeyObj, "PKCS8PRV");
    fs.writeFileSync(PACKED_ATTESTATION_KEY, packedPrivateKeyPEM);
} else {
    // read in existing packed private key PEM from file and extract public key and convert to PEM
    packedPrivateKeyPEM = fs.readFileSync(PACKED_ATTESTATION_KEY).toString();
    let prvKey = jsrsasign.KEYUTIL.getKey(packedPrivateKeyPEM);
    packedPublicKeyPEM = fidoutils.certToPEM(jsrsasign.b64toBA(jsrsasign.hextob64(prvKey.pubKeyHex)));
}
//console.log('packedPublicKeyPEM: ' + packedPublicKeyPEM);
//console.log('packedPrivateKeyPEM: ' + packedPrivateKeyPEM);


let packedAttestationCertificatePEM = null;
if (!fs.existsSync(PACKED_ATTESTATION_CERT)) {
    console.log("Creating packed certificate: " + PACKED_ATTESTATION_CERT);

    let notBeforeDate = new Date();
    let notAfterDate = new Date();
    // same as -days 9999 for openssl
    notAfterDate.setDate(notAfterDate.getDate() + 9999);

    let cert = new jsrsasign.asn1.x509.Certificate({
        version: 3,
        serial: {hex: generateRandomSerialNumberHex()},
        subject: {str: PACKED_ATTESTATION_DN},
        issuer: {str: ROOTCADN},
        notbefore: { type: 'gen', str: dateToASN1GeneralizedTime(notBeforeDate) },
        notafter: { type: 'gen', str: dateToASN1GeneralizedTime(notAfterDate) },
        sbjpubkey: packedPublicKeyPEM,
        ext: [
            {extname: "subjectKeyIdentifier", kid: packedPublicKeyPEM},
            {extname: "authorityKeyIdentifier", kid: rootCAPublicKeyPEM},
            {extname: "basicConstraints", cA: false, critical: true},
            {extname:"1.3.6.1.4.1.45724.1.1.4",extn:("0410"+packedAttestationAAGUID.replaceAll('-','').toUpperCase())}
        ],
        sigalg: "SHA256withECDSA",
        cakey: rootCAPrivateKeyPEM
    });

    packedAttestationCertificatePEM = cert.getPEM();
    fs.writeFileSync(PACKED_ATTESTATION_CERT, packedAttestationCertificatePEM);
} else {
    packedAttestationCertificatePEM = fs.readFileSync(PACKED_ATTESTATION_CERT).toString();
}
//console.log('packedAttestationCertificatePEM: ' + packedAttestationCertificatePEM);





//
// Generate (or read from existing files) a TPM intermediate key and certificate, signed by the rootCA
//
let tpmInterPublicKeyPEM = null;
let tpmInterPrivateKeyPEM = null;
if (!fs.existsSync(TPM_INTER_KEY)) {
    console.log("Creating TPM Intermediate key: " + TPM_INTER_KEY);
    let kp = jsrsasign.KEYUTIL.generateKeypair("RSA", "2048");
    tpmInterPublicKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.pubKeyObj, "PKCS8PUB");
    tpmInterPrivateKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.prvKeyObj, "PKCS8PRV");
    fs.writeFileSync(TPM_INTER_KEY, tpmInterPrivateKeyPEM);
    fs.writeFileSync(TPM_INTER_PUB, tpmInterPublicKeyPEM);
} else {
    // read in existing TPM intermediate private key PEM from file and extract public key and convert to PEM
    tpmInterPrivateKeyPEM = fs.readFileSync(TPM_INTER_KEY).toString();
    tpmInterPublicKeyPEM = fs.readFileSync(TPM_INTER_PUB).toString();
}
//console.log('tpmInterPublicKeyPEM: ' + tpmInterPublicKeyPEM);
//console.log('tpmInterPrivateKeyPEM: ' + tpmInterPrivateKeyPEM);

let tpmInterCertificatePEM = null;
if (!fs.existsSync(TPM_INTER_CERT)) {
    console.log("Creating TPM Intermediate certificate: " + TPM_INTER_CERT);

    let notBeforeDate = new Date();
    let notAfterDate = new Date();
    // same as -days 9999 for openssl
    notAfterDate.setDate(notAfterDate.getDate() + 9999);

    let cert = new jsrsasign.asn1.x509.Certificate({
        version: 3,
        serial: {hex: generateRandomSerialNumberHex()},
        subject: {str: TPM_INTER_DN},
        issuer: {str: ROOTCADN},
        notbefore: { type: 'gen', str: dateToASN1GeneralizedTime(notBeforeDate) },
        notafter: { type: 'gen', str: dateToASN1GeneralizedTime(notAfterDate) },
        sbjpubkey: tpmInterPublicKeyPEM,
        ext: [
            { extname: "keyUsage", critical: true, names: ["digitalSignature", "keyCertSign", "cRLSign"] },
            // this is extendedKeyUsage 1.3.6.1.4.1.311.21.36, 2.23.133.8.3
            { extname: "extKeyUsage", extn: "301206092B060104018237152406056781050803" },
            {extname: "subjectKeyIdentifier", kid: tpmInterPublicKeyPEM},
            {extname: "authorityKeyIdentifier", kid: rootCAPublicKeyPEM},
            {extname: "basicConstraints", cA: true, critical: true, pathLen: 0},
        ],
        sigalg: "SHA256withECDSA",
        cakey: rootCAPrivateKeyPEM
    });

    tpmInterCertificatePEM = cert.getPEM();
    fs.writeFileSync(TPM_INTER_CERT, tpmInterCertificatePEM);
} else {
    tpmInterCertificatePEM = fs.readFileSync(TPM_INTER_CERT).toString();
}
//console.log('tpmInterCertificatePEM: ' + tpmInterCertificatePEM);

//
// Generate (or read from existing files) a TPM attestation key and certificate, signed by the TPM Intermediate key
//
let tpmPublicKeyPEM = null;
let tpmPrivateKeyPEM = null;
if (!fs.existsSync(TPM_ATTESTATION_KEY)) {
    console.log("Creating TPM key: " + TPM_ATTESTATION_KEY);
    let kp = jsrsasign.KEYUTIL.generateKeypair("RSA", "2048");
    tpmPublicKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.pubKeyObj, "PKCS8PUB");
    tpmPrivateKeyPEM  = jsrsasign.KEYUTIL.getPEM(kp.prvKeyObj, "PKCS8PRV");
    fs.writeFileSync(TPM_ATTESTATION_KEY, tpmPrivateKeyPEM);
    fs.writeFileSync(TPM_ATTESTATION_PUB, tpmPublicKeyPEM);
} else {
    // read in existing TPM private key PEM from file and extract public key and convert to PEM
    tpmPrivateKeyPEM = fs.readFileSync(TPM_ATTESTATION_KEY).toString();
    tpmPublicKeyPEM = fs.readFileSync(TPM_ATTESTATION_PUB).toString();
}
//console.log('tpmPublicKeyPEM: ' + tpmPublicKeyPEM);
//console.log('tpmPrivateKeyPEM: ' + tpmPrivateKeyPEM);

let tpmAttestationCertificatePEM = null;
if (!fs.existsSync(TPM_ATTESTATION_CERT)) {
    console.log("Creating TPM certificate: " + TPM_ATTESTATION_CERT);

    let notBeforeDate = new Date();
    let notAfterDate = new Date();
    // same as -days 9999 for openssl
    notAfterDate.setDate(notAfterDate.getDate() + 9999);

    //
    // See table 2 in section 4.1 of the document at https://trustedcomputinggroup.org/resource/vendor-id-registry/
    // uppercase is required when encoding in a SAN dirName
    //
    // FIDO's test value (not in the table yet)
    let TPM_MANUFACTURER_ID = "FFFFF1D0".toUpperCase();

    let certificateParameters = {
        version: 3,
        serial: {hex: generateRandomSerialNumberHex()},
        issuer: {str: TPM_INTER_DN},
        notbefore: { type: 'gen', str: dateToASN1GeneralizedTime(notBeforeDate) },
        notafter: { type: 'gen', str: dateToASN1GeneralizedTime(notAfterDate) },
        sbjpubkey: tpmPublicKeyPEM,
        ext: [
            { extname: "keyUsage", critical: true, names: ["digitalSignature"] },
            { extname: "extKeyUsage", extn: "300706056781050803" },
            {extname: "subjectAltName", 
                critical: true, 
                array: [
                    {dn: "/2.23.133.2.3=id:1+2.23.133.2.2=IBMTPM+2.23.133.2.1=id:"+TPM_MANUFACTURER_ID}
                ]
            },
            {extname: "subjectKeyIdentifier", kid: tpmPublicKeyPEM},
            {extname: "authorityKeyIdentifier", kid: tpmInterPublicKeyPEM},
            {extname: "basicConstraints", cA: false, critical: true},
            {extname:"1.3.6.1.4.1.45724.1.1.4",extn:("0410"+tpmAttestationAAGUID.replaceAll('-','').toUpperCase())}
        ],
        sigalg: "SHA256withRSA",
        cakey: tpmInterPrivateKeyPEM
    };
    // subject DN can be absent for the TPM attestation certificate
    if (TPM_ATTESTATION_DN.length > 0) {
        certificateParameters.subject = {
            str: TPM_ATTESTATION_DN
        };
    }

    let cert = new jsrsasign.asn1.x509.Certificate(certificateParameters);

    tpmAttestationCertificatePEM = cert.getPEM();
    fs.writeFileSync(TPM_ATTESTATION_CERT, tpmAttestationCertificatePEM);
} else {
    tpmAttestationCertificatePEM = fs.readFileSync(TPM_ATTESTATION_CERT).toString();
}
//console.log('tpmAttestationCertificatePEM: ' + tpmAttestationCertificatePEM);


//
// Generate the FIDO MDS3 metadata documents
//
let iconText = fs.readFileSync(ICONFILE).toString();
let rootCAX509 = new jsrsasign.X509();
rootCAX509.readCertPEM(rootCAPEM);
let rootCAText = jsrsasign.hextob64(rootCAX509.hex);
let u2fX509 = new jsrsasign.X509();
u2fX509.readCertPEM(u2fAttestationCertificatePEM);
let packedX509 = new jsrsasign.X509();
packedX509.readCertPEM(packedAttestationCertificatePEM);
let tpmInterX509 = new jsrsasign.X509();
tpmInterX509.readCertPEM(tpmInterCertificatePEM);
let tpmX509 = new jsrsasign.X509();
tpmX509.readCertPEM(tpmAttestationCertificatePEM);

let u2fMetadataJSON = null;
if (!fs.existsSync(U2F_METADATA)) {
    u2fMetadataJSON = {
        description: "FIDOTEST-U2F",
        attestationCertificateKeyIdentifiers: [ u2fX509.getExtSubjectKeyIdentifier().kid.hex ],
        protocolFamily: "fido2",
        schema: 3,
        attestationTypes: [ "basic_full" ],
        attestationRootCertificates: [ rootCAText ],
        icon: iconText
    };
    fs.writeFileSync(U2F_METADATA, JSON.stringify(u2fMetadataJSON));
} else {
    u2fMetadataJSON = JSON.parse(fs.readFileSync(U2F_METADATA).toString());
}
//console.log("u2fMetadataJSON");
//console.log(JSON.stringify(u2fMetadataJSON));

let packedMetadataJSON = null;
if (!fs.existsSync(PACKED_METADATA)) {
    packedMetadataJSON = {
        description: "FIDOTEST-PACKED",
        aaguid: packedAttestationAAGUID,
        protocolFamily: "fido2",
        schema: 3,
        attestationTypes: [ "basic_full" ],
        attestationRootCertificates: [ rootCAText ],
        icon: iconText
    };
    fs.writeFileSync(PACKED_METADATA, JSON.stringify(packedMetadataJSON));
} else {
    packedMetadataJSON = JSON.parse(fs.readFileSync(PACKED_METADATA).toString());
}
//console.log("packedMetadataJSON");
//console.log(JSON.stringify(packedMetadataJSON));

let tpmMetadataJSON = null;
if (!fs.existsSync(TPM_METADATA)) {
    tpmMetadataJSON = {
        description: "FIDOTEST-TPM",
        aaguid: tpmAttestationAAGUID,
        protocolFamily: "fido2",
        schema: 3,
        attestationTypes: [ "attca" ],
        attestationRootCertificates: [ rootCAText ],
        icon: iconText
    };
    fs.writeFileSync(TPM_METADATA, JSON.stringify(tpmMetadataJSON));
} else {
    packedMetadataJSON = JSON.parse(fs.readFileSync(TPM_METADATA).toString());
}
//console.log("packedMetadataJSON");
//console.log(JSON.stringify(packedMetadataJSON));

let selfMetadataJSON = null;
if (!fs.existsSync(SELF_METADATA)) {
    selfMetadataJSON = {
        description: "FIDOTEST-SELF",
        aaguid: selfAttestationAAGUID,
        protocolFamily: "fido2",
        schema: 3,
        attestationTypes: [ "basic_surrogate" ],
        icon: iconText
    };
    fs.writeFileSync(SELF_METADATA, JSON.stringify(selfMetadataJSON));
} else {
    selfMetadataJSON = JSON.parse(fs.readFileSync(SELF_METADATA).toString());
}
//console.log("selfMetadataJSON");
//console.log(JSON.stringify(selfMetadataJSON));


//
// Generate an encryption passphrase
//
let encryptionPassphrase = null;
if (!fs.existsSync(ENCRYPTION_PASSPHRASE_FILE)) {
    console.log("Generating encryption passphrase file: " + ENCRYPTION_PASSPHRASE_FILE);
    encryptionPassphrase = jsrsasign.KJUR.crypto.Util.getRandomHexOfNbytes(20);
    fs.writeFileSync(ENCRYPTION_PASSPHRASE_FILE, encryptionPassphrase);
} else {
    encryptionPassphrase = fs.readFileSync(ENCRYPTION_PASSPHRASE_FILE).toString().replaceAll('\n','').toLowerCase();
}
//console.log("encryptionPassphrase: " + encryptionPassphrase);

//
// Generate the FIDO2_CLIENT_CONFIG variable that should be used in the .env
//
let fido2ClientConfigJSON = {
    "encryptionPassphrase": encryptionPassphrase,
    "fido-u2f": {
        "privateKeyHex": jsrsasign.KEYUTIL.getKey(u2fPrivateKeyPEM).prvKeyHex,
        "publicKeyHex": jsrsasign.KEYUTIL.getKey(u2fPrivateKeyPEM).pubKeyHex,
        "cert": jsrsasign.hextob64(u2fX509.hex)
    },
    "packed": {
        "aaguid": packedAttestationAAGUID,
        "privateKeyHex": jsrsasign.KEYUTIL.getKey(packedPrivateKeyPEM).prvKeyHex,
        "publicKeyHex": jsrsasign.KEYUTIL.getKey(packedPrivateKeyPEM).pubKeyHex,
        "cert": jsrsasign.hextob64(packedX509.hex)
    },
    "tpm": {
        "aaguid": tpmAttestationAAGUID,
        "privateKeyPEM": tpmPrivateKeyPEM,
        "publicKeyPEM": tpmPublicKeyPEM,
        "cert": jsrsasign.hextob64(tpmX509.hex),
        "tpmIntercert": jsrsasign.hextob64(tpmInterX509.hex)
    },
    "packed-self": {
        "aaguid": selfAttestationAAGUID
    }
};
console.log("FIDO2_CLIENT_CONFIG="+JSON.stringify(fido2ClientConfigJSON));