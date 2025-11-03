// mykeyutil.js

// this crypto library is used in order to support EC, RSA, ED25519, and the PQC ML algs
// see docs: https://nodejs.org/docs/latest-v24.x/api/webcrypto.html#class-subtlecrypto
const crypto = require('node:crypto');

// values from IANA COSE Algorithms registry
// if you want to force the client to only support one or a subset of credential algorithms
// change this to the appropriate value
const keyTypes = [ -7, -8, -257,-48, -49, -50 ];

/**
 * Extracts the bytes from an array beginning at index start, and continuing until
 * index end-1 or the end of the array is reached. Pass -1 for end if you want to
 * parse till the end of the array.
 */
function bytesFromArray(o, start, end) {
	// o may be a normal array of bytes, or it could be a JSON encoded Uint8Array
	let len = o.length;
	if (len == null) {
		len = Object.keys(o).length;
	}

	let result = [];
	for (let i = start; (end == -1 || i < end) && i < len; i++) {
		result.push(o[i]);
	}
	return result;
}
const SUPPORTED_ALGS = [ 
    // RS256, -257
    {
        name: 'RS256',
        algId: -257,
        createParams: {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1,0,1])
        },
        signParams: 'RSASSA-PKCS1-v1_5',
        verifyParams: 'RSASSA-PKCS1-v1_5',
        getPublicKeyCOSE: async function(kp) {
            let jwkPK = await crypto.subtle.exportKey('jwk', kp.publicKey);
            return {
                    "1": 3, // kty
                    "3": -257, // alg
                    "-1": bytesFromArray(new Uint8Array(Buffer.from(jwkPK.n, "base64url")), 0, -1), // n
                    "-2": [1,0,1], // exponent 65537
            };
        }
    }, 
    // ES256, -7
    {
        name: 'ES256',
        algId: -7,
        createParams: {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        signParams: {
            name: 'ECDSA',
            hash: 'SHA-256'
        },
        verifyParams: {
            name: 'ECDSA',
            hash: 'SHA-256'
        },
        getPublicKeyCOSE: async function(kp) {
            let jwkPK = await crypto.subtle.exportKey('jwk', kp.publicKey);
            return {
                    "1": 2, // kty
                    "3": -7, // alg
                    "-1": 1, // crv
                    "-2": bytesFromArray(new Uint8Array(Buffer.from(jwkPK.x, "base64url")), 0, -1), // xCoordinate
                    "-3": bytesFromArray(new Uint8Array(Buffer.from(jwkPK.y, "base64url")), 0, -1), // yCoordinate
            };
        }
    }, 
    // Ed25519, -8
    {
        name: 'Ed25519',
        algId: -8,
        createParams: 'Ed25519',
        signParams: 'Ed25519',
        verifyParams: 'Ed25519',
        getPublicKeyCOSE: async function(kp) {
            let jwkPK = await crypto.subtle.exportKey('jwk', kp.publicKey);
            return {
                    "1": 1, // kty
                    "3": -8, // alg
                    "-1": 6, // crv
                    "-2": bytesFromArray(new Uint8Array(Buffer.from(jwkPK.x, "base64url")), 0, -1)// xCoordinate
            };
        }
    },     // ML-DSA-44, -48
    {
        name: 'ML-DSA-44',
        algId: -48,
        createParams: 'ML-DSA-44',
        signParams: 'ML-DSA-44',
        verifyParams: 'ML-DSA-44',
        getPublicKeyCOSE: async function(kp) {
            let jwkPK = await crypto.subtle.exportKey('jwk', kp.publicKey);
            return {
                    "1": 7, // kty
                    "3": -48, // alg
                    "-1": bytesFromArray(new Uint8Array(Buffer.from(jwkPK.pub, "base64url")), 0, -1) // pub
            };
        }
    },
    // ML-DSA-65, -49
    {
        name: 'ML-DSA-65',
        algId: -49,
        createParams: 'ML-DSA-65',
        signParams: 'ML-DSA-65',
        verifyParams: 'ML-DSA-65',
        getPublicKeyCOSE: async function(kp) {
            let jwkPK = await crypto.subtle.exportKey('jwk', kp.publicKey);
            return {
                    "1": 7, // kty
                    "3": -49, // alg
                    "-1": bytesFromArray(new Uint8Array(Buffer.from(jwkPK.pub, "base64url")), 0, -1) // pub
            };
        }
    },
    // ML-DSA-87, -50
    {
        name: 'ML-DSA-87',
        algId: -50,
        createParams: 'ML-DSA-87',
        signParams: 'ML-DSA-87',
        verifyParams: 'ML-DSA-87',
        getPublicKeyCOSE: async function(kp) {
            let jwkPK = await crypto.subtle.exportKey('jwk', kp.publicKey);
            return {
                    "1": 7, // kty
                    "3": -50, // alg
                    "-1": bytesFromArray(new Uint8Array(Buffer.from(jwkPK.pub, "base64url")), 0, -1) // pub
            };
        }
    }
];

function supportsPubKeyCredParam(algId) {
    return keyTypes.indexOf(algId) >= 0;
}

async function generateKeypair(algId) {
    let result = null;
    let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === algId);
    if (supportedAlgInfo) {
        const { publicKey, privateKey } = await crypto.subtle.generateKey(supportedAlgInfo.createParams, true, ['sign', 'verify']);
        result = {
            algId: algId,
            publicKey: publicKey,
            privateKey: privateKey
        };
    }
    return result;
}

// extract the private key as hex bytes from a keypair previously generated with generateKeypair
async function getPrivateKeyHex(kp) {
    let privKeyAB = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
    return Buffer.from(privKeyAB).toString("hex");
}

// extract the public key as hex bytes from a keypair previously generated with generateKeypair
async function getPublicKeyHex(kp) {
    let pubKeyAB = await crypto.subtle.exportKey('spki', kp.publicKey);
    return Buffer.from(pubKeyAB).toString("hex");
}

function subtleKeyToPEM(k) {
    const kObj = crypto.KeyObject.from(k);
    return kObj.export({ type: (k.type == "private" ? 'pkcs8' : 'spki'), format: 'pem'});
}

// extract the public key as PEM from a keypair previously generated with generateKeypair
function getPublicKeyPEM(kp) {
    return subtleKeyToPEM(kp.publicKey);
}

// extract the private key as PEM from a keypair previously generated with generateKeypair
function getPrivateKeyPEM(kp) {
    result = subtleKeyToPEM(kp.privateKey);
    return result;
}

// given a particular algorithm ID and the private key hex butes, return the private key as a CryptoKey
async function getPrivateKeyFromHex(algId, hex) {
    let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === algId);
    return await crypto.subtle.importKey(
        "pkcs8", 
        Buffer.from(hex, "hex"),
        supportedAlgInfo.createParams,
        true,
        ["sign"]
    );
}

// return the COSE format of the public key from a keypair previously generated with generateKeypair
async function getPublicKeyCOSE(kp) {
    let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === kp.algId);
    return supportedAlgInfo.getPublicKeyCOSE(kp);
}

// given an algorithm ID and the private key as a CryptoKey, return the base64url format of a signature over the data
// in a format suitable for WebAuthn signatures
async function signBytesWithPrivateKey(algId, privateKey, data) {
    let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === algId);
    let sigArrayBuffer = await crypto.subtle.sign(supportedAlgInfo.signParams, privateKey, new Uint8Array(data).buffer);

    // ECDSA signatures need to be ASN.1 encoded per https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
    // inspiration from: https://stackoverflow.com/questions/39554165/ecdsa-signatures-between-node-js-and-webcrypto-appear-to-be-incompatible
    let result = null;
    if (algId === -7) {
        // Extract r and s and format in ASN1
        let signatureHex = Buffer.from(sigArrayBuffer).toString("hex");
        let r = signatureHex.substring(0, signatureHex.length/2);
        let s = signatureHex.substring(signatureHex.length/2);
        let rPre = true;
        let sPre = true;

        // remove any zero-byte prefixes of r
        while(r.indexOf('00') === 0) {
            r = r.substring(2);
            rPre = false;
        }

        // pad r with leading zeros if necessary to make it unsigned
        if (rPre && parseInt(r.substring(0, 2), 16) > 127) {
            r = '00' + r;
        }

        // remove any zero-byte prefixes of s
        while(s.indexOf('00') === 0) {
            s = s.substring(2);
            sPre = false;
        }

        // pad s with leading zeros if necessary to make it unsigned
        if(sPre && parseInt(s.substring(0, 2), 16) > 127) {
            s = '00' + s;
        }

        // encode the two hex bytes of r and s in ASN1 format
        let payloadHex = '02' + (r.length/2).toString(16) + r + '02' + (s.length/2).toString(16) + s;
        // encode into a sequence
        let der = '30' + (payloadHex.length/2).toString(16) + payloadHex;

        // convert hex asn1 to base64url
        result = Buffer.from(der, 'hex').toString("base64url");
    } else {
        // for all other signature types, just supply raw signature output in base64url format
        result = Buffer.from(sigArrayBuffer).toString("base64url");
    }

    return result;
}

module.exports = {
    supportsPubKeyCredParam: supportsPubKeyCredParam,
    generateKeypair: generateKeypair,
    getPrivateKeyHex: getPrivateKeyHex,
    getPublicKeyHex: getPublicKeyHex,
    getPublicKeyPEM: getPublicKeyPEM,
    getPrivateKeyPEM: getPrivateKeyPEM,
    getPrivateKeyFromHex: getPrivateKeyFromHex,
    getPublicKeyCOSE: getPublicKeyCOSE,
    signBytesWithPrivateKey: signBytesWithPrivateKey
}
