//
// generate_attestation_certs.js 
// 

//
// This script generates a self-signed CA, then signs other certs for U2F, PACKED and TPM attestation
// It also generates MDS3 metadata files for use with your FIDO server and a JSON FIDO2_CLIENT_CONFIG
// parameter that you can use in the .env file for the clients in the parent directory.
//

// It additionally generates the Merkle Tree Certificate (MTC) test artifacts (fmt "mtc", WebAuthn Level 4):
// an ML-DSA-87 root CA, an authenticator batch key, a signed subtree checkpoint over a Merkle tree of log entries,
// an MDS3 metadata statement containing mtcTrustAnchors, and an "mtc" block for FIDO2_CLIENT_CONFIG.
// See MTC_IMPLEMENTATION_PLAN.md. The MTC code does NOT use jsrsasign. Pass --mtc-only to generate only the MTC
// artifacts and write just the "mtc" JSON config block to stdout (this is what generate_attestation_certs.sh does).
//

const fs = require('fs');
const jsrsasign = require('jsrsasign'); // https://www.npmjs.com/package/jsrsasign
const crypto = require('node:crypto');
const cbor = require('cbor'); // https://www.npmjs.com/package/cbor
const fidoutils = require('../fidoutils.js');
const mycertutil = require('../mycertutil.js');
const mykeyutil = require('../mykeyutil.js');

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

// Merkle Tree Certificate (MTC) artifacts - see MTC_IMPLEMENTATION_PLAN.md
let MTC_ROOTCACERT="rootCA-mldsa87.pem"
let MTC_ROOTCAKEY="rootCA-mldsa87.key"
let MTC_ROOTCADN="/C=US/O=IBM/CN=FIDOTEST-MTC-ROOT"
let MTC_ROOTCA_ALG=-50                 // ML-DSA-87
let MTC_ROOTCA_OID="2.16.840.1.101.3.4.3.19"
let MTC_BATCH_KEY="mtc-batch.key"
let MTC_BATCH_ALG=-48                  // ML-DSA-44
let MTC_AAGUID="mtc.aaguid"
let MTC_METADATA="fidotest-mtc.json"
let MTC_CA_ID=Buffer.from("83993f0101", "hex")  // compact 5 byte CA identifier (same as the example in WebAuthn L4 8.10)
let MTC_LOG_NUMBER=1
let MTC_SUBTREE_START=0
let MTC_SUBTREE_END=1024
let MTC_LEAF_INDEX=0                   // index of the batch key we generate within the subtree
let MTC_NOT_AFTER=253402300799         // 9999-12-31T23:59:59Z, "never expires"

const MTC_ONLY = process.argv.includes("--mtc-only");


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
// Merkle Tree Certificate (MTC) generation. Uses only node:crypto, Buffer and the helpers in mycertutil.js and
// mykeyutil.js (no jsrsasign). All progress is logged to stderr so that stdout is only ever the JSON config.
//

// Minimal ASN.1 DER encoding helpers, sufficient to build a self-signed X.509v3 root CA certificate.
// node:crypto cannot create certificates, and the ML-DSA signature algorithm is not supported by jsrsasign.
function derLength(len) {
    if (len < 0x80) {
        return Buffer.from([len]);
    }
    const bytes = [];
    while (len > 0) {
        bytes.unshift(len & 0xff);
        len = Math.floor(len / 256);
    }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, ...contents) {
    const content = Buffer.concat(contents);
    return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function derSequence(...contents) { return tlv(0x30, ...contents); }
function derSet(...contents) { return tlv(0x31, ...contents); }
function derBoolean(v) { return tlv(0x01, Buffer.from([v ? 0xff : 0x00])); }
function derOctetString(buf) { return tlv(0x04, buf); }
function derBitString(buf, unusedBits = 0) { return tlv(0x03, Buffer.from([unusedBits]), buf); }

function derInteger(buf) {
    // positive integer: strip leading zeros, then prepend 0x00 if the top bit is set
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) { i++; }
    buf = buf.subarray(i);
    return tlv(0x02, (buf[0] & 0x80) ? Buffer.concat([Buffer.from([0]), buf]) : buf);
}

function derOID(oid) {
    const parts = oid.split(".").map((p) => parseInt(p, 10));
    const bytes = [parts[0] * 40 + parts[1]];
    for (const p of parts.slice(2)) {
        const enc = [p & 0x7f];
        for (let v = Math.floor(p / 128); v > 0; v = Math.floor(v / 128)) {
            enc.unshift((v & 0x7f) | 0x80);
        }
        bytes.push(...enc);
    }
    return tlv(0x06, Buffer.from(bytes));
}

function derTime(d) {
    // RFC 5280: UTCTime up to and including 2049, GeneralizedTime from 2050
    const p = (n) => String(n).padStart(2, "0");
    const rest = p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + "Z";
    const year = d.getUTCFullYear();
    return (year < 2050)
        ? tlv(0x17, Buffer.from(p(year % 100) + rest, "ascii"))
        : tlv(0x18, Buffer.from(String(year) + rest, "ascii"));
}

const DN_ATTRIBUTE_OIDS = { C: "2.5.4.6", O: "2.5.4.10", OU: "2.5.4.11", CN: "2.5.4.3" };

// converts an openssl style subject string like "/C=US/O=IBM/CN=Example" to a DER encoded Name
function derName(dn) {
    const rdns = dn.split("/").filter((s) => s.length > 0).map((pair) => {
        const idx = pair.indexOf("=");
        const type = pair.substring(0, idx);
        const value = Buffer.from(pair.substring(idx + 1), "utf8");
        // countryName must be a PrintableString, everything else is a UTF8String
        return derSet(derSequence(derOID(DN_ATTRIBUTE_OIDS[type]), tlv(type === "C" ? 0x13 : 0x0c, value)));
    });
    return derSequence(...rdns);
}

function pemEncode(label, der) {
    return "-----BEGIN " + label + "-----\n" + der.toString("base64").match(/.{1,64}/g).join("\n") + "\n-----END " + label + "-----\n";
}

// Creates a self-signed ML-DSA X.509v3 root CA certificate (BasicConstraints CA:TRUE) and returns its DER bytes
function createSelfSignedMLDSARootCert(privateKey, publicKey, dn, oid, days) {
    const spki = publicKey.export({ type: "spki", format: "der" });
    const rawPublicKey = Buffer.from(publicKey.export({ format: "jwk" }).pub, "base64url");
    // RFC 5280 4.2.1.2 method 1: SHA-1 of the subjectPublicKey bit string value
    const keyId = crypto.createHash("sha1").update(rawPublicKey).digest();

    const serial = crypto.randomBytes(20);
    serial[0] &= 0x7f;

    const notBefore = new Date();
    const notAfter = new Date();
    notAfter.setUTCDate(notAfter.getUTCDate() + days);

    const sigAlg = derSequence(derOID(oid)); // RFC 9881: parameters MUST be absent
    const extension = (extOid, critical, value) =>
        derSequence(derOID(extOid), ...(critical ? [derBoolean(true)] : []), derOctetString(value));

    const extensions = tlv(0xa3, derSequence(
        extension("2.5.29.14", false, derOctetString(keyId)),         // subjectKeyIdentifier
        extension("2.5.29.35", false, derSequence(tlv(0x80, keyId))), // authorityKeyIdentifier
        extension("2.5.29.19", true, derSequence(derBoolean(true))),  // basicConstraints CA:TRUE
        extension("2.5.29.15", true, derBitString(Buffer.from([0x06]), 1)) // keyUsage keyCertSign, cRLSign
    ));

    const tbsCertificate = derSequence(
        tlv(0xa0, derInteger(Buffer.from([2]))), // version v3
        derInteger(serial),
        sigAlg,
        derName(dn), // issuer
        derSequence(derTime(notBefore), derTime(notAfter)),
        derName(dn), // subject
        spki,
        extensions
    );
    const signature = crypto.sign(null, tbsCertificate, privateKey);
    return derSequence(tbsCertificate, sigAlg, derBitString(signature));
}

// returns a KeyObject private key from a PKCS8 PEM file, generating (and saving) it if the file does not exist
function readOrCreateKey(file, keyType) {
    if (!fs.existsSync(file)) {
        console.error("Creating key: " + file);
        const kp = crypto.generateKeyPairSync(keyType);
        fs.writeFileSync(file, kp.privateKey.export({ type: "pkcs8", format: "pem" }));
    }
    return crypto.createPrivateKey(fs.readFileSync(file));
}

function readOrCreateAAGUID(file) {
    if (!fs.existsSync(file)) {
        console.error("Creating aaguid: " + file);
        fs.writeFileSync(file, crypto.randomUUID().toLowerCase());
    }
    return fs.readFileSync(file).toString().replaceAll("\n", "").toLowerCase();
}

// Canonical (deterministic) CBOR encoding of the COSE_Key { 1: 7 (AKP), 3: alg, -1: pub }
function encodeCoseKeyBytes(alg, publicKey) {
    const pub = Buffer.from(publicKey.export({ format: "jwk" }).pub, "base64url");
    return cbor.encodeCanonical(new Map([[1, 7], [3, alg], [-1, pub]]));
}

/**
 * Generates (or reuses existing) MTC artifacts:
 *  - rootCA-mldsa87.key/.pem : ML-DSA-87 vendor root CA (alg -50)
 *  - mtc-batch.key           : authenticator batch attestation key (ML-DSA-44, alg -48)
 *  - mtc.aaguid              : AAGUID of the test authenticator
 *  - fidotest-mtc.json       : MDS3 metadata statement with mtcTrustAnchors (subtree checkpoint + batchKeys)
 * Binary values in the metadata statement are standard base64 encoded, like attestationRootCertificates.
 *
 * @returns the "mtc" block for FIDO2_CLIENT_CONFIG (binary values are hex encoded)
 */
function generateMTC() {
    const aaguid = readOrCreateAAGUID(MTC_AAGUID);
    const rootPrivateKey = readOrCreateKey(MTC_ROOTCAKEY, "ml-dsa-87");
    const rootPublicKey = crypto.createPublicKey(rootPrivateKey);
    const batchPrivateKey = readOrCreateKey(MTC_BATCH_KEY, "ml-dsa-44");
    const batchPublicKey = crypto.createPublicKey(batchPrivateKey);

    let rootCertDER = null;
    if (!fs.existsSync(MTC_ROOTCACERT)) {
        console.error("Creating MTC Root CA certificate: " + MTC_ROOTCACERT);
        // same as -days 9999 for openssl
        rootCertDER = createSelfSignedMLDSARootCert(rootPrivateKey, rootPublicKey, MTC_ROOTCADN, MTC_ROOTCA_OID, 9999);
        fs.writeFileSync(MTC_ROOTCACERT, pemEncode("CERTIFICATE", rootCertDER));
    } else {
        rootCertDER = new crypto.X509Certificate(fs.readFileSync(MTC_ROOTCACERT)).raw;
    }

    let metadata = null;
    if (!fs.existsSync(MTC_METADATA)) {
        console.error("Generating MTC metadata file: " + MTC_METADATA);
        const serial = (BigInt(MTC_LOG_NUMBER) << 48n) | BigInt(MTC_LEAF_INDEX);
        const notBefore = Math.floor(Date.now() / 1000);
        const coseKeyBytes = encodeCoseKeyBytes(MTC_BATCH_ALG, batchPublicKey);

        // Build the leaf hashes of the whole subtree. The batch key is at MTC_LEAF_INDEX and every other leaf is a
        // deterministic placeholder standing in for the batch keys of other authenticators in the log.
        const leafHashes = [];
        for (let i = MTC_SUBTREE_START; i < MTC_SUBTREE_END; i++) {
            if (i === MTC_LEAF_INDEX) {
                const logEntry = mycertutil.buildFidoMtcLogEntry({
                    caId: MTC_CA_ID,
                    serial: serial,
                    notBefore: notBefore,
                    notAfter: MTC_NOT_AFTER,
                    aaguid: mykeyutil.fromHex(aaguid.replaceAll("-", "")),
                    firmwareVersion: null,
                    coseKeyBytes: coseKeyBytes,
                    extensions: null
                });
                leafHashes.push(mycertutil.computeFidoMtcLeafHash(logEntry));
            } else {
                leafHashes.push(mycertutil.computeFidoMtcLeafHash(Buffer.from("FIDOTEST-MTC-PLACEHOLDER-LEAF-" + i, "ascii")));
            }
        }
        const tree = mycertutil.buildRFC9162MerkleTree(leafHashes);
        const relIndex = MTC_LEAF_INDEX - MTC_SUBTREE_START;
        const proof = tree.getProof(relIndex);
        if (!mycertutil.verifyRFC9162MerkleProof({
            leafHash: leafHashes[relIndex], proof: proof, leafIndex: MTC_LEAF_INDEX,
            start: MTC_SUBTREE_START, end: MTC_SUBTREE_END, rootHash: tree.rootHash })) {
            throw new Error("Generated Merkle inclusion proof failed verification");
        }

        // sign the subtree checkpoint with the root CA key
        const checkpoint = mycertutil.buildFidoMtcSubtreeCheckpoint({
            caId: MTC_CA_ID,
            logNumber: MTC_LOG_NUMBER,
            start: MTC_SUBTREE_START,
            end: MTC_SUBTREE_END,
            rootHash: tree.rootHash
        });
        const checkpointSignature = crypto.sign(null, checkpoint, rootPrivateKey);
        if (!crypto.verify(null, checkpoint, rootPublicKey, checkpointSignature)) {
            throw new Error("Generated subtree checkpoint signature failed verification");
        }

        metadata = {
            description: "FIDOTEST-MTC",
            aaguid: aaguid,
            protocolFamily: "fido2",
            schema: 3,
            attestationTypes: [ "basic_full" ],
            attestationRootCertificates: [ mykeyutil.toBase64(rootCertDER) ],
            icon: fs.readFileSync(ICONFILE).toString(),
            mtcTrustAnchors: [
                {
                    caId: mykeyutil.toBase64(MTC_CA_ID),
                    subtrees: [
                        {
                            logNumber: MTC_LOG_NUMBER,
                            start: MTC_SUBTREE_START,
                            end: MTC_SUBTREE_END,
                            rootHash: mykeyutil.toBase64(tree.rootHash),
                            alg: MTC_ROOTCA_ALG,
                            signature: mykeyutil.toBase64(checkpointSignature)
                        }
                    ],
                    batchKeys: [
                        {
                            serial: Number(serial), // (logNumber << 48) | index, still an exact JSON number (< 2^53)
                            coseKey: mykeyutil.toBase64(coseKeyBytes),
                            notBefore: notBefore,
                            notAfter: MTC_NOT_AFTER,
                            // concatenation of the 32 byte RFC 9162 sibling hashes, ordered from the leaf upwards
                            mtcProof: mykeyutil.toBase64(Buffer.concat(proof))
                        }
                    ]
                }
            ]
        };
        fs.writeFileSync(MTC_METADATA, JSON.stringify(metadata));
    } else {
        metadata = JSON.parse(fs.readFileSync(MTC_METADATA).toString());
    }

    const anchor = metadata.mtcTrustAnchors[0];
    const batchKey = anchor.batchKeys[0];
    const subtree = anchor.subtrees[0];
    return {
        aaguid: metadata.aaguid,
        caId: mykeyutil.toHex(mykeyutil.fromBase64(anchor.caId)),
        serial: batchKey.serial,
        alg: MTC_BATCH_ALG,
        privateKeyHex: mykeyutil.toHex(batchPrivateKey.export({ type: "pkcs8", format: "der" })),
        coseKey: mykeyutil.toHex(mykeyutil.fromBase64(batchKey.coseKey)),
        notBefore: batchKey.notBefore,
        notAfter: batchKey.notAfter,
        mtcProof: mykeyutil.toHex(mykeyutil.fromBase64(batchKey.mtcProof)),
        rootHash: mykeyutil.toHex(mykeyutil.fromBase64(subtree.rootHash))
    };
}

if (MTC_ONLY) {
    console.log(JSON.stringify(generateMTC()));
    process.exit(0);
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
        protocolFamily: "u2f",
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
    },
    "mtc": generateMTC()
};
console.log("FIDO2_CLIENT_CONFIG="+JSON.stringify(fido2ClientConfigJSON));
