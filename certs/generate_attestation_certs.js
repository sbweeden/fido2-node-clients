//
// generate_attestation_certs.js 
// 

//
// This script generates a self-signed CA, then signs other certs for U2F and PACKED attestation
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
//let U2F_ATTESTATION_CSR="u2f.csr"
let U2F_ATTESTATION_CERT="u2f.pem"
let U2F_METADATA="fidotest-u2f.json"

let PACKED_ATTESTATION_DN="/C=US/O=IBM/OU=Authenticator Attestation/CN=PACKED-SIGNER"
let PACKED_ATTESTATION_KEY="packed.key"
//let PACKED_ATTESTATION_CSR="packed.csr"
let PACKED_ATTESTATION_CERT="packed.pem"
//let PACKED_ATTESTATION_CONFIG="packed.config"
let PACKED_ATTESTATION_AAGUID="packed.aaguid"
let PACKED_METADATA="fidotest-packed.json"

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

/*
// u2fCSRPEM is not required for this implementation
let u2fCSRPEM = null;
if (!fs.existsSync(U2F_ATTESTATION_CSR)) {
    console.log("Creating U2F CSR: " + U2F_ATTESTATION_CSR);
    let pubKey = jsrsasign.KEYUTIL.getKey(u2fPublicKeyPEM);
    let prvKey = jsrsasign.KEYUTIL.getKey(u2fPrivateKeyPEM);

    let u2fCSR = new jsrsasign.KJUR.asn1.csr.CertificationRequest({
        subject: {str: U2F_ATTESTATION_DN},
        sbjpubkey: pubKey,
        sigalg: "SHA256withECDSA",
        sbjprvkey: prvKey
    });
    u2fCSRPEM = u2fCSR.getPEM();
    fs.writeFileSync(U2F_ATTESTATION_CSR, u2fCSRPEM);
} else {
    u2fCSRPEM = fs.readFileSync(U2F_ATTESTATION_CSR).toString();
}
//console.log('u2fCSRPEM: ' + u2fCSRPEM);
*/

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

/*
// packedCSR is not required for this implementation
let packedCSRPEM = null;
if (!fs.existsSync(PACKED_ATTESTATION_CSR)) {
    console.log("Creating packed CSR: " + PACKED_ATTESTATION_CSR);
    let pubKey = jsrsasign.KEYUTIL.getKey(packedPublicKeyPEM);
    let prvKey = jsrsasign.KEYUTIL.getKey(packedPrivateKeyPEM);

    let packedCSR = new jsrsasign.KJUR.asn1.csr.CertificationRequest({
        subject: {str: PACKED_ATTESTATION_DN},
        sbjpubkey: pubKey,
        sigalg: "SHA256withECDSA",
        sbjprvkey: prvKey,
        extreq: [
            {extname: "basicConstraints", cA: false, critical: true}
        ]
    });
    packedCSRPEM = packedCSR.getPEM();
    fs.writeFileSync(PACKED_ATTESTATION_CSR, packedCSRPEM);
} else {
    packedCSRPEM = fs.readFileSync(PACKED_ATTESTATION_CSR).toString();
}
//console.log('packedCSRPEM: ' + packedCSRPEM);
*/

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
            {extname: "basicConstraints", cA: false, critical: true}
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
// Generate AAGUIDs for packed and self attestation
//
let packedAttestationAAGUID = null;
if (!fs.existsSync(PACKED_ATTESTATION_AAGUID)) {
    packedAttestationAAGUID = crypto.randomUUID().toLowerCase();
    fs.writeFileSync(PACKED_ATTESTATION_AAGUID, packedAttestationAAGUID);
} else {
    packedAttestationAAGUID = fs.readFileSync(PACKED_ATTESTATION_AAGUID).toString().replaceAll('\n','').toLowerCase();
}
//console.log("packedAttestationAAGUID: " + packedAttestationAAGUID);

let selfAttestationAAGUID = null;
if (!fs.existsSync(SELF_ATTESTATION_AAGUID)) {
    selfAttestationAAGUID = crypto.randomUUID().toLowerCase();
    fs.writeFileSync(SELF_ATTESTATION_AAGUID, selfAttestationAAGUID);
} else {
    selfAttestationAAGUID = fs.readFileSync(SELF_ATTESTATION_AAGUID).toString().replaceAll('\n','').toLowerCase();
}
//console.log("selfAttestationAAGUID: " + selfAttestationAAGUID);


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
    "packed-self": {
        "aaguid": selfAttestationAAGUID
    }
};
console.log("FIDO2_CLIENT_CONFIG="+JSON.stringify(fido2ClientConfigJSON));