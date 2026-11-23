// fidoutils.js

const cbor = require('cbor'); // https://www.npmjs.com/package/cbor
const jsrsasign = require('jsrsasign'); // https://www.npmjs.com/package/jsrsasign
const CryptoJS = require('crypto-js'); // https://www.npmjs.com/package/crypto-js
const mycertutil = require('./mycertutil.js');
const mykeyutil = require('./mykeyutil.js');

// if true this hashes the private key bytes to produce a credential ID (non-reversable)
// if false this encrypts the private key bytes to produce a credential ID (reversable), however produces results for RSA keys that are very long
let USE_HASHED_CREDENTIAL_ID=true

// This environment variable needs to be set.
let fidoutilsConfig = null;
if (process.env.FIDO2_CLIENT_CONFIG != null) {
	fidoutilsConfig = JSON.parse(process.env.FIDO2_CLIENT_CONFIG);
	fidoutilsConfig.origin = process.env.ORIGIN;
}
// It should contain a JSON document like this:
let exampleConfig = {
	"encryptionPassphrase": "MySecret",

	"origin": "https://example.ibm.com:9443",

	"fido-u2f": {
		"privateKeyHex":
			"00b8464b082d2a77bae48d8ec84694cd4cca7b41948635622a8db1bc87a8894f17",
		"publicKeyHex":
			"04ffd1d9a70f7c1c83fa8660925dfbfcbb4d1c232e5443f5d9ee4ad72480fec9d20068c05b5d7777cc25fd27d93015c0ea2d72f51d8eae1970729b98609a5013db",
		"cert": "MIIDFjCB/wIJAKiWRVc805iDMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAlVTMQ0wCwYDVQQKDAROSVNUMRMwEQYDVQQDDApVSUNDUm9vdENBMB4XDTE5MDgwNzIwMjgwM1oXDTQ2MTIyMjIwMjgwM1owNTELMAkGA1UEBhMCVVMxDTALBgNVBAoMBE5JU1QxFzAVBgNVBAMMDlVJQ0NVMkYtU0lHTkVSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/9HZpw98HIP6hmCSXfv8u00cIy5UQ/XZ7krXJID+ydIAaMBbXXd3zCX9J9kwFcDqLXL1HY6uGXBym5hgmlAT2zANBgkqhkiG9w0BAQsFAAOCAgEAKP/Ck24JM+8J7Ns4g5a8XczXPPnYe+FFs7bUQoam2sEEPBzapdIssl9rYkFKvxIW8zgPHJVIQJ3hMmq9tGkhKXT+WzIew+BJRzBYscytaaqMURHuqM1usBFQZSBUYIlDCQqezxG9bZ4cx8gzmL4ldYPGwSAex3K9XOVdyNn+ut8/axcfhDYfr0zW498KOg1L72kjthiNTrJWGaCwkfCsNNtBHWy2HmGzAgMLi7Wn3eNzTyrbzj7GBBsFm6Nv5LKLxCwX8YEd6UWzYLuP/AhAG1+w1rfPmbdi0/hXGUr8h51dlTF2DUrxQfZvECA5Du4TZHHKpTu7opI2BSVabXYp+F25RbkcE1oAqjrZeMdeWXFu5bcD5MvQ6Q3D/M1H1ngahFLzyzPprZ1OO5codyiRwhPtSyeR+FIi7yj9Lirxhv+t1pzm9N6z8DEW3Iman5+x+hGPP01n0RFP1H+Fu0jUCZfcZmx0ecrrd2r3B0YpyUR5n45dweBw+dyQZaPm0eenyMYFNuXWNx+aT7wcYFYhoYEqi0n7bGmvR3ZmFws3rBi2uLOamM1cOSnabOQ7Tvirq39TAbJ3dNZAwoD7pFn4YZHeywPGlENnij1bMnTYyVXRr/coi84bD4S147Ydm6lWpMcolpVlplbXJ3S3BDu/AqJGBqQwKtBUDuL0BbnbE+0="
	},

	"packed": {
		"aaguid": "37c4c2cf41544c5791039c9bdcca5b2b",
		"privateKeyHex":
			"03e158d202854c3bc0cb233a726f4445b41b4ca80b370a2c30d8fe039f820d42",
		"publicKeyHex":
			"045c6c82d6b47e2971a78ebbe8dd910ebbdcecb902019e6b37f743374c5740d9f0533068c562ebd7c11e55258b235efc48aba0d77f6d0ebe6f991321976ea1e072",
		"cert": "MIIDVTCCAT2gAwIBAgIJAKiWRVc805iEMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAlVTMQ0wCwYDVQQKDAROSVNUMRMwEQYDVQQDDApVSUNDUm9vdENBMB4XDTE5MDgwNzIwMjgwM1oXDTQ2MTIyMjIwMjgwM1owXDELMAkGA1UEBhMCVVMxDTALBgNVBAoMBE5JU1QxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEVVJQ0NQQUNLRUQtU0lHTkVSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXGyC1rR+KXGnjrvo3ZEOu9zsuQIBnms390M3TFdA2fBTMGjFYuvXwR5VJYsjXvxIq6DXf20Ovm+ZEyGXbqHgcqMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAtsJl2cVtuRJqwm0SXhP2vGU3An79GxT1appa9JKLWz7iv5zOVWowKvbEnB6sqjNPZ1p65yEi5UmRNnkE6m6IFSRijz5eeWOHQ0ceQN4BhH9veE4Xe3WiOaahTTJX+hqj+5ByMhgw0dZ6+1iEu20BE0zKAA+VSrpA5O+LPOBDNjCfVzLI566ykNqe2mShm+UGNDYkTxVJmFXY9qyy/zLazynroE6qnIt03UutzifAnNNnBKqk9gK9C6cosDHeyvRGy9um1P21EC85yEZvN8wngzNmc8TJwnkXYHP4METHbjR9bmQP60e19a7so9sz7P5MhkFJ/JOURkbWh6qmzIGQhoNpGw6OQnAxHvkPiw9HuDEfjzIFX1LQi74uMIEG7juCIt2u56dXG7T0NM8MfVlupDJzi4AnwI+NuONrKtC5iK6HHSrRxCQ8QiPTemlymPhC/XMJW70PqDiH7cEmCbsDKg9cTN8mWCNNyb1/WkcfrP2zq+jm1Lp8Viam5kHsd66X9VP/44Aj5G6TGJU7ZitBB/hHqz0jznuZU+fRuGf2taQdCP/DXps/VngXrcvs4sRS3aid0KO5eLkUP8e11r909DMTvV/CsqghqXpS13oUbTs8cD12y93EftSbw6OKR30xcV1PScCOY/CSnCuSQFlgrXW1OotzmWQUKKKUB9Egzb8="
	},

	"packed-self": {
		"aaguid": "1811ec8b8a91459299f217f35d53242e"
	},

	"mtc": {
		"aaguid": "00000000-0000-0000-0000-000000000000",
		"caId": "83993f0101",
		"serial": 281474976710656,
		"alg": -48
	}
};

/*
 * Collection of functions useful to emulate a FIDO2 client and authenticator
 */

// CBOR encodes an object, returning results as a byte array
function myCBOREncode(o) {
	result = bytesFromArray((new Uint8Array(cbor.encode(o))), 0, -1);
	return result;
}

// Some data structures in FIDO authenticators that are arrays of bytes
// need to be encoded as a CBOR byte string rather than a CBOR array of unsigned integers.
// Our CBOR encoder will encode Buffer to byte string, so this utility function
// is called when what we have is a byte array and what we need CBOR encoded is a byte string.
function prepareBAForCBOR(ba) {
	return (new Uint8Array(ba)).buffer;
}

//
// CBOR encoding a COSE key is a bit tricky because not only are co-ordinate values
// required to be byte strings, its also required that the key values are integers.
// You can't express integer keys in a JSON object, so we first convert to a Map
// with integer keys so that the CBOR encoder correctly encodes those keys as integers.
//
function coseKeyToMap(coseKey) {
	// create a Map, treating object keys as integers (notice call to parseInt below) and converting byte array values to 
	// a Buffer so that CBOR encoding of a COSE key results in integer keys and coordinates as byte strings
	let coseKeyMap = new Map();
	for (const [k,v] of Object.entries(coseKey)) {
		let mapKey = (Number.isNaN(parseInt(k)) ? k : parseInt(k));
		let mapValue = ((v instanceof Array) ? prepareBAForCBOR(v) : v);
		coseKeyMap.set(mapKey,mapValue);
	}
	return coseKeyMap;
}

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


/**
 * Returns the bytes of a sha256 message digest of either a string or byte array
 * This is used when building the signature base string to verify registration
 * data.
 */
function sha256(data) {
	let md = new jsrsasign.KJUR.crypto.MessageDigest({
		alg: "sha256",
		prov: "jsrsasign.CryptoJS"
	});
	if (Array.isArray(data)) {
		md.updateHex(jsrsasign.BAtohex(data));
	} else {
		md.updateString(data);
	}
	return jsrsasign.b64toBA(jsrsasign.hex2b64(md.digest()));
}

/**
 * Converts the bytes of an asn1-encoded X509 ceritificate or raw public key
 * into a PEM-encoded cert string
 */
function certToPEM(cert) {
	let keyType = "CERTIFICATE";
	asn1key = cert;

	if (cert != null && cert.length == 65 && cert[0] == 0x04) {
		// this is a raw public key - prefix with ASN1 metadata
		// SEQUENCE {
		// SEQUENCE {
		// OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
		// OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
		// }
		// BITSTRING <raw public key>
		// }
		// We just need to prefix it with constant 26 bytes of metadata
		asn1key = jsrsasign.b64toBA(
			jsrsasign.hextob64("3059301306072a8648ce3d020106082a8648ce3d030107034200")
		);
		Array.prototype.push.apply(asn1key, cert);
		keyType = "PUBLIC KEY";
	}
	let result = "-----BEGIN " + keyType + "-----\n";
	let b64cert = jsrsasign.hextob64(jsrsasign.BAtohex(asn1key));
	for (; b64cert.length > 64; b64cert = b64cert.slice(64)) {
		result += b64cert.slice(0, 64) + "\n";
	}
	if (b64cert.length > 0) {
		result += b64cert + "\n";
	}
	result += "-----END " + keyType + "-----\n";
	return result;
}

function resolveCredentialIdBytesFromPrivateKeyHex(algId, privKeyHEX) {
	if (fidoutilsConfig.encryptionPassphrase == null) {
		throw new Error(
			"Please set the fidoutilsConfig.encryptionPassphrase environment variable"
		);
	}

	let pObj = {
		a: algId,
		k: jsrsasign.hextob64u(privKeyHEX)
	}
	let plainText = JSON.stringify(pObj);

	let result = jsrsasign.b64toBA(
		CryptoJS.AES.encrypt(
			plainText,
			fidoutilsConfig.encryptionPassphrase
		).toString()
	);

	console.log("resolveCredentialIdBytesFromPrivateKeyHex credId length: " + result.length)

	return result;
}

function resolvePrivateKeyFromCredentialIdBytes(credIdBytes) {
	let result = null;
	if (fidoutilsConfig.encryptionPassphrase == null) {
		throw new Error(
			"Please set the fidoutilsConfig.encryptionPassphrase environment variable"
		);
	}
	let plainText = CryptoJS.AES.decrypt(
		jsrsasign.hextob64(jsrsasign.BAtohex(credIdBytes)),
		fidoutilsConfig.encryptionPassphrase
	).toString(CryptoJS.enc.Utf8);

	if (plainText != null && plainText.length > 0) {
		let pObj = JSON.parse(plainText);
		if (pObj != null) {
			result = {
				algId: pObj.a,
				privateKeyHex: jsrsasign.b64utohex(pObj.k)
			};
		}
	}

	return result;
}

/**
 * Given an attestation options response (o), return a new JSON object
 * which is a CredentialCreationOptions as defined in https://w3c.github.io/webauthn/#credentialcreationoptions-extension
 * @param o
 * @returns
 */
function attestationOptionsResponeToCredentialCreationOptions(o) {
	// the final output is a CredentialCreationOptions
	let cco = {};

	// https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
	let pkcco = {};

	/*
	 * required: rp, copy that
	 */
	pkcco.rp = o.rp;
	// console.log("publickeycredentials relying party is", pkcco.rp);

	/*
	 * required: user, map that to the pkcco data types
	 */
	pkcco.user = {};
	// required: id in o is base64url, but in pkcco is BufferSource
	pkcco.user.id = new Uint8Array(
		jsrsasign.b64toBA(jsrsasign.b64utob64(o.user.id))
	);
	// required: displayName is DOMString - copy across
	pkcco.user.displayName = o.user.displayName;
	// required: name is DOMString - copy across
	pkcco.user.name = o.user.name;
	// optional: icon - copy across if present
	if (o.user["icon"] != null) {
		pkcco.user.icon = o.user.icon;
	}

	/*
	 * required: challenge, map to pkcco data type
	 */
	pkcco.challenge = new Uint8Array(
		jsrsasign.b64toBA(jsrsasign.b64utob64(o.challenge))
	);

	/*
	 * required: pubKeyCredParams, copy that
	 */
	pkcco.pubKeyCredParams = o.pubKeyCredParams;

	/*
	 * optional: timeout, copy if present
	 */
	if (o["timeout"] != null) {
		pkcco.timeout = o.timeout;
	}

	/*
	 * optional: excludeCredentials, map to pkcco data types if present
	 */
	if (o["excludeCredentials"] != null) {
		pkcco.excludeCredentials = [];
		for (let i = 0; i < o.excludeCredentials.length; i++) {
			let c = {};
			// required: type - copy across
			c.type = o.excludeCredentials[i].type;
			// required: id in o is base64url, but in pkcco is BufferSource
			c.id = new Uint8Array(
				jsrsasign.b64toBA(jsrsasign.b64utob64(o.excludeCredentials[i].id))
			);
			// optional: transports - copy across if present
			if (o.excludeCredentials[i]["transports"] != null) {
				c.transports = o.excludeCredentials[i].transports;
			}
			pkcco.excludeCredentials.push(c);
		}
	}

	/*
	 * optional: authenticatorSelection, copy if present
	 */
	if (o["authenticatorSelection"] != null) {
		pkcco.authenticatorSelection = o.authenticatorSelection;
	}

	/*
	 * optional: attestation, copy if present
	 */
	if (o["attestation"] != null) {
		pkcco.attestation = o.attestation;
	}

	/*
	 * optional: extensions, copy if present
	 */
	if (o["extensions"] != null) {
		pkcco.extensions = o.extensions;
	}

	// build final result object
	cco.publicKey = pkcco;

	return cco;
}

// base 64 encode functions to be exported and included in bundled file
function base64toBA(base64Str) {
	return jsrsasign.b64toBA(base64Str);
}
function base64utobase64(base64Str) {
	return jsrsasign.b64utob64(base64Str);
}

function canAuthenticateWithCredId(options) {
	// try and use resolvePrivateKeyFromCredentialIdBytes and check the return 
	// if candiateprivkeyhex is not null and candiateprivkeyhex length greather than zero
	// return true, else return false
	let privateKeyFromCandidateCredIdBytes;
	let canAuthenticate = false;
	if (options.publicKey.allowCredentials !== null && options.publicKey.allowCredentials.length > 0) {
		for (let i = 0; i < options.publicKey.allowCredentials.length; i++) {
			let candidateCredId = options.publicKey.allowCredentials[i].id;
			privateKeyFromCandidateCredIdBytes = resolvePrivateKeFromCredentialIdBytes(candidateCredId);
			if (privateKeyFromCandidateCredIdBytes !== null) {
				canAuthenticate = true;
				break;
			}
		}
	}
	//console.log("canAuthenticate", canAuthenticate);
	return canAuthenticate;
}

function getFidoUtilsConfig() {
	return fidoutilsConfig;
}

function setFidoUtilsConfig(newObj) {
	fidoutilsConfig = newObj;
	return newObj;
}

/*
 * Acting as the client+authenticator, prepare a FIDO2 server ServerPublicKeyCredential from a CredentialCreationOptions
 * See example at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#example-authenticator-attestation-response
 * Schema at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredential
 */
async function processCredentialCreationOptions(
	cco,
	attestationFormat = "none",
	up = true,
	uv = true,
	includeJSONResponseElements = false
) {
	let result = {
		authenticatorRecord: {
			rpId: cco.publicKey.rp.id,
			privateKeyHex: null,
			algId: null,
			credentialID: null,
			userHandle: null
		},
		spkc: {}
	};
	let spkc = {};

	// the ServerAuthenticatorAttestationResponse
	let saar = {};

	// build the clientDataJSON
	let clientDataJSON = {
		"origin": fidoutilsConfig.origin,
		"challenge": jsrsasign.hextob64u(
			jsrsasign.BAtohex(bytesFromArray(cco.publicKey.challenge, 0, -1))
		),
		"type": "webauthn.create"
	};

	// add the base64url of this stringified JSON to the response
	saar.clientDataJSON = jsrsasign.utf8tob64u(JSON.stringify(clientDataJSON));

	// also compute the hash - most attestation types need it as part of data to sign
	let clientDataHash = sha256(
		jsrsasign.b64toBA(jsrsasign.utf8tob64(JSON.stringify(clientDataJSON)))
	);

	// attestation object see: https://w3c.github.io/webauthn/#sctn-attestation

	// Build the authenticatorData
	let authData = [];

	// first rpIdHashBytes
	authData.push(...sha256(cco.publicKey.rp.id));

	// mtc-debug extension (WebAuthn L4 §10.2.1): only honoured when the format is "mtc"
	let mtcDebug = null;
	if (
		attestationFormat == "mtc" &&
		cco.publicKey.extensions != null &&
		cco.publicKey.extensions.mtcDebug === true
	) {
		mtcDebug = buildMTCDebugExtension(cco.publicKey.attestation === "enterprise");
	}

	/*
	 * flags
	 *  - conditionally set UV, UP and indicate attested credential data is present
	 *  - Note we never set UV for fido-u2f
	 *  - set ED (0x80) when authenticator extension outputs follow the attested credential data
	 */
	let flags =
		(up ? 0x01 : 0x00) |
		(uv && attestationFormat != "fido-u2f" ? 0x04 : 0x00) |
		0x40 |
		(mtcDebug != null ? 0x80 : 0x00);
	authData.push(flags);

	// add 4 bytes of signature counter - we use 0, to suggest we don't support the counter.
	// This makes it easier to do asynchronous load testing with the same registration since
	// we don't have to serialize each authentication attempt for a given authenticator.
	// An alternative is to use the current time in epoch seconds as a monotonic counter.
	let now = 0; // new Date().getTime() / 1000;
	authData.push(
		((now & 0xff000000) >> 24) & 0xff,
		((now & 0x00ff0000) >> 16) & 0xff,
		((now & 0x0000ff00) >> 8) & 0xff,
		now & 0x000000ff
	);

	// attestedCredentialData
	let attestedCredentialData = [];

	// aaguid - 16 bytes, if we have one defined use it, otherwise all zeros

	let aaguid = null;
	if (
		fidoutilsConfig[attestationFormat] != null &&
		fidoutilsConfig[attestationFormat].aaguid != null
	) {
		let aaguidHex = fidoutilsConfig[attestationFormat].aaguid.replace(/-/g, "");
		aaguid = Array.from(mykeyutil.fromHex(aaguidHex));
	}
	if (aaguid == null) {
		aaguid = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	}
	attestedCredentialData.push(...aaguid);

	// based on the attestationFormat, we use some different attestation keys

	// we use the ECDSA key for the registered keypair - generate a new keypair now
	let selectedAlg = null;
	for (let i = 0; i < cco.publicKey.pubKeyCredParams.length && selectedAlg == null; i++) {
		if (mykeyutil.supportsPubKeyCredParam(cco.publicKey.pubKeyCredParams[i].alg)) {
			selectedAlg = cco.publicKey.pubKeyCredParams[i].alg;
		}
	}
	if (selectedAlg == null) {
		console.log("no algorithm supported");
	}

	let keypair = await mykeyutil.generateKeypair(selectedAlg);

	//
	// map the private key to a credential id - this is just one way to do it with key wrapping
	// you could also locally store the private key and index with any credentialId handle you like
	//
	let privateKeyHex = await mykeyutil.getPrivateKeyHex(keypair);
	let credIdBytes = null;
	if (USE_HASHED_CREDENTIAL_ID) {
		credIdBytes = sha256(jsrsasign.b64toBA(jsrsasign.hextob64(privateKeyHex)));
	} else {
		credIdBytes = resolveCredentialIdBytesFromPrivateKeyHex(selectedAlg, privateKeyHex);
	}

	// store the private/public  key, credentialID and userHandle
	result.authenticatorRecord.privateKeyHex = privateKeyHex;
	result.authenticatorRecord.algId = selectedAlg;
	result.authenticatorRecord.credentialID = jsrsasign.hextob64u(
		jsrsasign.BAtohex(credIdBytes)
	);
	result.authenticatorRecord.userHandle = jsrsasign.hextob64u(
		jsrsasign.BAtohex(bytesFromArray(cco.publicKey.user.id, 0, -1))
	);

	// COSE format of the EC256 key
	let credPublicKeyCOSE = await mykeyutil.getPublicKeyCOSE(selectedAlg, keypair);

	// credentialIdLength (2 bytes) and credential Id
	let lenArray = [
		(credIdBytes.length - (credIdBytes.length & 0xff)) / 256,
		credIdBytes.length & 0xff
	];
	attestedCredentialData.push(...lenArray);
	attestedCredentialData.push(...credIdBytes);

	// credential public key - take bytes from CBOR encoded COSE key
	let credPublicKeyBytes = myCBOREncode(coseKeyToMap(credPublicKeyCOSE));
	attestedCredentialData.push(...credPublicKeyBytes);

	// add attestedCredentialData to authData
	authData.push(...attestedCredentialData);

	// authenticator extension outputs follow the attested credential data and must be
	// present before the attestation statement is built, since attStmt.sig covers authData
	if (mtcDebug != null) {
		authData.push(...myCBOREncode({ "mtc-debug": mtcDebug.authenticatorOutput }));
	}

	// build attestation statement depending on requested format
	let attStmt = null;
	if (attestationFormat == "none") {
		// for none, just return an empty attStmt
		attStmt = {};
	} else if (attestationFormat == "fido-u2f") {
		attStmt = buildFidoU2FAttestationStatement(
			keypair,
			clientDataHash,
			authData,
			credIdBytes
		);
	} else if (attestationFormat == "packed") {
		attStmt = buildPackedAttestationStatement(
			keypair,
			clientDataHash,
			authData,
			credIdBytes,
			false
		);
	} else if (attestationFormat == "packed-self") {
		attStmt = buildPackedAttestationStatement(
			keypair,
			clientDataHash,
			authData,
			credIdBytes,
			true
		);
		// this is really packed, we only used packed-self internally to toggle the flag above
		attestationFormat = "packed";
	} else if (attestationFormat == "tpm") {
		attStmt = buildTPMAttestationStatement(
			keypair,
			clientDataHash,
			authData,
			credIdBytes
		);
	} else if (attestationFormat == "mtc") {
		attStmt = await buildMTCAttestationStatement(
			clientDataHash,
			authData
		);
	} else {
		throw ("Unsupported attestationFormat: " + attestationFormat);
	}

	// build the attestationObject
	let attestationObject = {
		"fmt": attestationFormat,
		"attStmt": attStmt,
		"authData": prepareBAForCBOR(authData)
	};

	// add the base64url of the CBOR encoding of the attestationObject to the response
	saar.attestationObject = jsrsasign.hextob64u(jsrsasign.BAtohex(myCBOREncode(attestationObject)));

	// if the JSON API elements are asked for, populate those
	if (includeJSONResponseElements) {
		saar.publicKeyAlgorithm = selectedAlg;
		// this is b64u of bytes from PEM encoding format
		let publicKeyPEM = await mykeyutil.getPublicKeyPEM(keypair);
		saar.publicKey = jsrsasign.b64tob64u(publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----","").replaceAll("\n",""));
		saar.authenticatorData = jsrsasign.hextob64u(jsrsasign.BAtohex(authData));
	}

	// construct ServerPublicKeyCredential fields

	// id is base64url encoding of the credId
	result.spkc.id = jsrsasign.hextob64u(jsrsasign.BAtohex(credIdBytes));

	// rawId is the same as id
	result.spkc.rawId = result.spkc.id;

	// response - this is the meat of the data structure, contain the clientDataJSON and attestation
	result.spkc.response = saar;

	// type (from Credential defined here: https://w3c.github.io/webappsec-credential-management/#credential)
	result.spkc.type = "public-key";

	// extension results - empty unless an extension produced client output
	result.spkc.getClientExtensionResults = {};
	if (mtcDebug != null) {
		result.spkc.getClientExtensionResults.mtcDebug = mtcDebug.clientOutput;
	}

	return result;
}

/**
 * Given an assertion options response (o), return a new JSON object
 * which is a CredentialRequestOptions as defined in https://w3c.github.io/webauthn/#credentialrequestoptions-extension
 * @param o
 * @returns
 */
function assertionOptionsResponeToCredentialRequestOptions(o) {
	// the final output is a CredentialRequestOptions
	let cro = {};

	// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions
	let pkcro = {};

	/*
	 * required: challenge, map to pkcro data type
	 */
	pkcro.challenge = new Uint8Array(
		jsrsasign.b64toBA(jsrsasign.b64utob64(o.challenge))
	);

	/*
	 * optional: timeout, copy if present
	 */
	if (o["timeout"] != null) {
		pkcro.timeout = o.timeout;
	}

	/*
	 * optional rpId: If not present, needs to be defaulted to origin's effective domain.
	 * We should always have it, because we supply as part of our server implementation.
	 */
	if (o["rpId"] != null) {
		pkcro.rpId = o.rpId;
	}

	/*
	 * optional allowCredentials, map to pkcco data types if present
	 */
	if (o["allowCredentials"] != null) {
		pkcro.allowCredentials = [];
		for (let i = 0; i < o.allowCredentials.length; i++) {
			let c = {};
			// required: type - copy across
			c.type = o.allowCredentials[i].type;
			// required: id in o is base64url, but in pkcco is BufferSource
			c.id = new Uint8Array(
				jsrsasign.b64toBA(jsrsasign.b64utob64(o.allowCredentials[i].id))
			);
			// optional: transports - copy across if present
			if (o.allowCredentials[i]["transports"] != null) {
				c.transports = o.allowCredentials[i].transports;
			}
			pkcro.allowCredentials.push(c);
		}
	}

	/*
	 * optional: userVerification, copy if present
	 */
	if (o["userVerification"] != null) {
		pkcro.userVerification = o.userVerification;
	}

	/*
	 * optional: extensions, copy if present
	 */
	if (o["extensions"] != null) {
		pkcro.extensions = o.extensions;
	}

	// build final result object
	cro.publicKey = pkcro;
	return cro;
}

/*
 * Acting as the client+authenticator, prepare a FIDO2 server ServerAuthenticatorAssertionResponse from a CredentialRequestOptions
 * See example at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#authentication-examples
 * Schema at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverauthenticatorassertionresponse
 *
 * cro is required.
 * The payloadHash is an extension that we added for an IoT demo, and outside that context can be passed as null.
 */
async function processCredentialRequestOptions(
	cro,
	authenticatorRecords,
	up = true,
	uv = true,
	payloadHash = null
) {
	// ServerPublicKeyCredential
	let spkc = {};

	// the ServerAuthenticatorAssertionResponse
	let saar = {};

	// build the clientDataJSON
	let clientDataJSON = {
		"origin": fidoutilsConfig.origin,
		"challenge": jsrsasign.hextob64u(
			jsrsasign.BAtohex(bytesFromArray(cro.publicKey.challenge, 0, -1))
		),
		"type": "webauthn.get"
	};

	if (payloadHash != null) {
		clientDataJSON.payloadHash = payloadHash;
	}

	// attestation object see: https://w3c.github.io/webauthn/#sctn-attestation

	// add the base64url of this stringified JSON to the response
	saar.clientDataJSON = jsrsasign.utf8tob64u(JSON.stringify(clientDataJSON));

	// Build the authenticatorData
	let authData = [];

	// first rpIdHashBytes
	authData.push(...sha256(cro.publicKey.rpId));

	// flags - UP, UV
	let flags = (up ? 0x01 : 0x00) | (uv ? 0x04 : 0x00);
	authData.push(flags);

	// add 4 bytes of signature counter - we use 0, to suggest we don't support the counter.
	// This makes it easier to do asynchronous load testing with the same registration since
	// we don't have to serialize each authentication attempt for a given authenticator.
	// An alternative is to use the current time in epoch seconds as a monotonic counter.
	let now = 0;  // new Date().getTime() / 1000;
	authData.push(
		((now & 0xff000000) >> 24) & 0xff,
		((now & 0x00ff0000) >> 16) & 0xff,
		((now & 0x0000ff00) >> 8) & 0xff,
		now & 0x000000ff
	);

	// add authData to ServerAuthenticatorAssertionResponse
	saar.authenticatorData = jsrsasign.hextob64u(jsrsasign.BAtohex(authData));

	// use the credential id to resolve the private key
	let privKeyHex = null;
	let algId = null;
	let usedCredentialId = null;
	let userHandle = null;
	let usernameLessFlow = false;
	if (
		cro.publicKey["allowCredentials"] != null &&
		cro.publicKey["allowCredentials"].length > 0
	) {
		for (
			let i = 0;
			i < cro.publicKey["allowCredentials"].length && privKeyHex == null;
			i++
		) {
			//
			// if authenticatorRecords is supplied, see if this entry of allowCredentials
			// is in the authenticatorRecords and just use it if its there
			//
			if (authenticatorRecords != null) {
				// authenticatorRecords is an object with keys that are b64u of the credId bytes
				let lookupCredId = jsrsasign.hextob64u(jsrsasign.BAtohex(
					bytesFromArray(cro.publicKey["allowCredentials"][i].id, 0, -1)));
				if (authenticatorRecords[lookupCredId] != null) {
					algId = authenticatorRecords[lookupCredId].algId;
					usedCredentialId = authenticatorRecords[lookupCredId].credentialID;
					privKeyHex = authenticatorRecords[lookupCredId].privateKeyHex;
				}
			}

			//
			// if we did not locate this credentialID in authenticatorRecords,
			// see if we can decrypt it (since it might be a wrapped key)
			//
			if (privKeyHex == null) {
				let candidateCredIdBytes = bytesFromArray(
					cro.publicKey["allowCredentials"][i].id,
					0,
					-1
				);
				let candidateCredIdStr = jsrsasign.hextob64u(
					jsrsasign.BAtohex(candidateCredIdBytes)
				);
				try {
					let candidatePrivKey =
						resolvePrivateKeyFromCredentialIdBytes(candidateCredIdBytes);
					if (candidatePrivKey != null) {
						algId = candidatePrivKey.algId;
						usedCredentialId = candidateCredIdStr;
						privKeyHex = candidatePrivKey.privateKeyHex;
					}
				} catch (e) {
					// probably not our cred id
					//console.log("Unable to decrypt: " + candidateCredIdStr + " e: " + e);
					//console.log("Ignoring allowCredentials cred id as we could not decrypt it: " + candidateCredIdStr);
				}
			}
		}
	} else {
		//
		// This is the usernameless flow - search for a matching credential in the authenticatorRecords
		//
		usernameLessFlow = true;

		let allCredentialIDs = Object.keys(authenticatorRecords);
		for (
			let i = 0;
			(i < allCredentialIDs.length) & (usedCredentialId == null);
			i++
		) {
			// can we use this one? - we will if the rpId matches where we are going
			let candidateRecord = authenticatorRecords[allCredentialIDs[i]];
			if (candidateRecord.rpId == cro.publicKey.rpId) {
				algId = candidateRecord.algId;
				usedCredentialId = candidateRecord.credentialID;
				privKeyHex = candidateRecord.privateKeyHex;
				userHandle = candidateRecord.userHandle;
			}
		}
	}

	if (algId != null && privKeyHex != null) {

		// re-create private key
		let privateKey = await mykeyutil.getPrivateKeyFromHex(algId, privKeyHex);

		// compute the signature
		let cHash = sha256(
			jsrsasign.b64toBA(jsrsasign.b64utob64(saar.clientDataJSON))
		);
		let sigBase = [];
		sigBase.push(...authData);
		sigBase.push(...cHash);

		let sigBytes = await mykeyutil.signBytesWithPrivateKey(algId, privateKey, sigBase); 

		let sigB64U = jsrsasign.hextob64u(jsrsasign.BAtohex(sigBytes));
		saar.signature = sigB64U;

		// add the user handle for username-less flows
		if (usernameLessFlow) {
			// the user handle should have been remembered above
			saar.userHandle = userHandle;
		} else {
			saar.userHandle = "";
		}

		// construct ServerPublicKeyCredential fields

		// id of credential we used
		spkc.id = usedCredentialId;

		// rawId is the same as id
		spkc.rawId = spkc.id;

		// response - this is the meat of the data structure, contain the clientDataJSON, authenticatorData, signature and userHandle
		spkc.response = saar;

		// type (from Credential defined here: https://w3c.github.io/webappsec-credential-management/#credential)
		spkc.type = "public-key";

		// extension results - for now we populate as empty map
		spkc.getClientExtensionResults = {};
	} else {
		// error
		throw new Error(
			"Authenticator does not have any credentials for this login"
		);
		spkc = null;
	}

	return spkc;
}

function buildFidoU2FAttestationStatement(
	keypair,
	clientDataHash,
	authData,
	credIdBytes
) {
	let attStmt = {};

	let ecdsa = new jsrsasign.KJUR.crypto.ECDSA({ "curve": "prime256v1" });
	ecdsa.setPrivateKeyHex(
		fidoutilsConfig["fido-u2f"].privateKeyHex.replace(/:/g, "")
	);
	ecdsa.setPublicKeyHex(
		fidoutilsConfig["fido-u2f"].publicKeyHex.replace(/:/g, "")
	);

	let attestationCert = new jsrsasign.X509();
	attestationCert.readCertPEM(
		certToPEM(jsrsasign.b64toBA(fidoutilsConfig["fido-u2f"].cert))
	);

	// populate x5c of attStmt with one entry - the bytes of the self-signed attestation cert
	attStmt.x5c = [prepareBAForCBOR(jsrsasign.b64toBA(jsrsasign.hextob64(attestationCert.hex)))];

	// build sigBase
	let rpidhashBytes = bytesFromArray(authData, 0, 32);
	let sigBase = [0x00].concat(
		rpidhashBytes,
		clientDataHash,
		credIdBytes,
		jsrsasign.b64toBA(jsrsasign.hextob64(keypair.pubKeyObj.pubKeyHex))
	);

	// generate and populate signature (the sigBase is signed with the attestation cert)
	let sig = new jsrsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
	sig.init(ecdsa);
	sig.updateHex(jsrsasign.BAtohex(sigBase));
	let sigValueHex = sig.sign();

	attStmt.sig = prepareBAForCBOR(jsrsasign.b64toBA(jsrsasign.hextob64(sigValueHex)));
	return attStmt;
}

function buildPackedAttestationStatement(
	keypair,
	clientDataHash,
	authData,
	credIdBytes,
	useSelfAttestation
) {
	/*
	 * we only support ECDSA256 at the moment
	 */
	let attStmt = { alg: -7 };

	let ecdsa = new jsrsasign.KJUR.crypto.ECDSA({ "curve": "prime256v1" });

	// toggle to decide whether to sign with credential private key or attestation private key
	if (useSelfAttestation) {
		ecdsa.setPrivateKeyHex(keypair.prvKeyObj.prvKeyHex);
		ecdsa.setPublicKeyHex(keypair.pubKeyObj.pubKeyHex);
	} else {
		ecdsa.setPrivateKeyHex(
			fidoutilsConfig.packed.privateKeyHex.replace(/:/g, "")
		);
		ecdsa.setPublicKeyHex(
			fidoutilsConfig.packed.publicKeyHex.replace(/:/g, "")
		);

		// if not using self attestation, include the attestation cert as x5c
		let attestationCert = new jsrsasign.X509();
		attestationCert.readCertPEM(
			certToPEM(jsrsasign.b64toBA(fidoutilsConfig.packed.cert))
		);
		attStmt.x5c = [ prepareBAForCBOR(jsrsasign.b64toBA(jsrsasign.hextob64(attestationCert.hex))) ];
	}

	// build sigBase
	let sigBase = authData.concat(clientDataHash);

	// generate and populate signature (the sigBase is signed with the attestation cert)
	let sig = new jsrsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
	sig.init(ecdsa);
	sig.updateHex(jsrsasign.BAtohex(sigBase));
	let sigValueHex = sig.sign();

	attStmt.sig = prepareBAForCBOR(jsrsasign.b64toBA(jsrsasign.hextob64(sigValueHex)));
	return attStmt;
}

// writes size then bytes, returns nextIndex + number of bytes written
function writeSizedBytes(view, index, bytes) {
	let result = index;

	let len = (bytes != null ? bytes.length : 0);

	// first two bytes are the size
	view.setUint16(result, len);
	result += 2;

	// I'm sure there's more efficient ways, but this is easy to understand
	if (len > 0) {
		for (let i = 0; i < len; i++) {
			view.setUint8(result, bytes[i]);
			result += 1;
		}
	}

	return result;
}

// writes digest (as Uint16 if >= 0) and handle bytes (if provided), returns nextIndex + number of bytes written
function writeTPM2BName(view, index, digestUint16, handleBytes) {
	let result = index;
	let len = 0;

	if (digestUint16 >= 0 && handleBytes != null && handleBytes.length > 0) {
		len = 2 + handleBytes.length;
	}
	view.setUint16(result, len);
	result += 2;
	if (len > 0) {
		view.setUint16(result, digestUint16);
		result += 2;
		// I'm sure there's more efficient ways, but this is easy to understand
		for (let i = 0; i < handleBytes.length; i++) {
			view.setUint8(result, handleBytes[i]);
			result += 1;
		}	
	}

	return result;
}

function buildTPMAttestationStatement(
	keypair,
	clientDataHash,
	authData,
	credIdBytes
) {
	/*
	 * we only support RS256 at the moment
	 */
	let attStmt = { alg: -257, ver: "2.0" };

	// sign with tpm attestation private key
	let rsaKey = new jsrsasign.KEYUTIL.getKey(fidoutilsConfig.tpm.privateKeyPEM);

	// include the attestation cert and intermediate cert as x5c
	let attestationCert = new jsrsasign.X509();
	attestationCert.readCertPEM(
		certToPEM(jsrsasign.b64toBA(fidoutilsConfig.tpm.cert))
	);

	let tpmInterCert = new jsrsasign.X509();
	tpmInterCert.readCertPEM(
		certToPEM(jsrsasign.b64toBA(fidoutilsConfig.tpm.tpmIntercert))
	);
	attStmt.x5c = [ 
		prepareBAForCBOR(jsrsasign.b64toBA(jsrsasign.hextob64(attestationCert.hex))),
		prepareBAForCBOR(jsrsasign.b64toBA(jsrsasign.hextob64(tpmInterCert.hex)))
	];

	//
	// build pubArea
	// See https://github.com/w3c/webauthn/issues/984
	//
	let paBuffer = new ArrayBuffer(2048); // should be plenty big enough
	let paView = new DataView(paBuffer);
	let nextIndex = 0;

	// TPMI_ALG_PUBLIC type (2 bytes)
	paView.setUint16(nextIndex, 0x0023); // TPM_ALG_ECC
	nextIndex += 2;

	// TPMI_ALG_HASH nameAlg (2 bytes)
	paView.setUint16(nextIndex, 0x000B); // TPM_ALG_SHA256
	nextIndex += 2;

	// TPMA_OBJECT objectAttributes (4 bytes)
	paView.setUint32(nextIndex, 0x60472); // copied verbatim as seen from a Windows TPM
	nextIndex += 4;

	// TPM2B_DIGEST authPolicy - not going to provide one
	nextIndex = writeSizedBytes(paView, nextIndex, []);
	
	// TPMU_PUBLIC_PARMS parameters
	// TPM_ALG_ECC so using TPMS_ECC_PARAMS (symmetric=16, scheme=16, curveID=3, kdf=16), as seen from a Windows Hello TPM with EC credential public key
	paView.setUint16(nextIndex, 16);
	nextIndex += 2;
	paView.setUint16(nextIndex, 16);
	nextIndex += 2;
	paView.setUint16(nextIndex, 3);
	nextIndex += 2;
	paView.setUint16(nextIndex, 16);
	nextIndex += 2;

	// TPMU_PUBLIC_ID unique
	// TPM_ALG_ECC so using TPMS_ECC_POINT (x and y coordinates of EC public key)
	let xBytes = jsrsasign.b64toBA(jsrsasign.hextob64(keypair.pubKeyObj.getPublicKeyXYHex()["x"]));
	let yBytes = jsrsasign.b64toBA(jsrsasign.hextob64(keypair.pubKeyObj.getPublicKeyXYHex()["y"]));
	nextIndex = writeSizedBytes(paView, nextIndex, xBytes);
	nextIndex = writeSizedBytes(paView, nextIndex, yBytes);

	// extract those bytes and put into the attStmt
	let pubAreaBytes = bytesFromArray(new Uint8Array(paBuffer), 0, nextIndex); 
	attStmt.pubArea = prepareBAForCBOR(pubAreaBytes);

	//
	// build certInfo
	// again see https://github.com/w3c/webauthn/issues/984
	//
	let ciBuffer = new ArrayBuffer(2048); // should be plenty big enough
	let ciView = new DataView(ciBuffer);
	nextIndex = 0;

	// TPM_GENERATED magic
	ciView.setUint32(nextIndex, 0xff544347);
	nextIndex += 4;
	
	// TPMI_ST_ATTEST type must be TPM_ST_ATTEST_CERTIFY
	ciView.setUint16(nextIndex, 0x8017);
	nextIndex += 2;

	// TPM2B_NAME qualifiedSigner
	// choosing not to provide one
	nextIndex = writeTPM2BName(ciView, nextIndex, -1, null);

	// TPM2B_DATA extraData
	// must be hash of concatenation of authenticatorData and clientDataHash
	// we use sha256, as will be later identified in the certInfoAttestedNameDigest
	let certInfoBase = authData.concat(clientDataHash);
	let extraDataBytes = sha256(certInfoBase);
	nextIndex = writeSizedBytes(ciView, nextIndex, extraDataBytes);

	// TPMS_CLOCK_INFO clockInfo - we're going to set to zeros
	ciView.setBigUint64(nextIndex, 0n); // clock UINT64
	nextIndex += 8;
	ciView.setUint32(nextIndex, 0x00); // resetCount UINT32
	nextIndex += 4;
	ciView.setUint32(nextIndex, 0x00); // restartCount UINT32
	nextIndex += 4;
	ciView.setUint8(nextIndex, 0x00); // safe TPMI_YES_NO (boolean)
	nextIndex += 1;

	// UINT64 firmwareVersion - we're going to set to zero
	ciView.setBigUint64(nextIndex, 0n);
	nextIndex += 8;

	// TPMU_ATTEST attested (will be TPMS_CERTIFY_INFO)
	// TPM2B_NAME name - handle is hash of pubArea bytes ; digest says we use sha256 (0x0B)
	nextIndex = writeTPM2BName(ciView, nextIndex, 0x0B, sha256(pubAreaBytes));

	// TPM2B_NAME qualifiedName - choosing not to provide one
	nextIndex = writeTPM2BName(ciView, nextIndex, -1, null);

	// extract those bytes and put into the attStmt
	let certInfoBytes = bytesFromArray(new Uint8Array(ciBuffer), 0, nextIndex);
	attStmt.certInfo = prepareBAForCBOR(certInfoBytes);

	//console.log("certInfoBytes(hex) : " + jsrsasign.BAtohex(certInfoBytes));

	// generate and populate signature (the sigBase is signed with the attestation cert)
	let sig = new jsrsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
	sig.init(rsaKey);
	sig.updateHex(jsrsasign.BAtohex(certInfoBytes));
	let sigValueHex = sig.sign();
	attStmt.sig = prepareBAForCBOR(jsrsasign.b64toBA(jsrsasign.hextob64(sigValueHex)));

	return attStmt;
}

/**
 * Builds the mtc-debug extension outputs (WebAuthn Level 4 §10.2.1) from fidoutilsConfig.mtc.
 * Only call when fmt is "mtc". Returns both representations:
 *  - authenticatorOutput: CBOR-encodable map for authenticatorData.extensions["mtc-debug"] (byte strings)
 *  - clientOutput: clientExtensionResults.mtcDebug in its toJSON() form (ArrayBuffer members base64url encoded)
 * Config fields (binary values hex): coseKey (required), notBefore, notAfter, firmwareVersion,
 * mtcProof, rootHash, deviceSerial. deviceSerial is only emitted when enterprise attestation is granted.
 *
 * @param {boolean} enterpriseAttestation - true if enterprise attestation was requested and granted
 * @param {object} [mtcOverrideConfig] - Optional override for fidoutilsConfig.mtc
 */
function buildMTCDebugExtension(enterpriseAttestation, mtcOverrideConfig) {
	let mtcConfig = mtcOverrideConfig || (fidoutilsConfig && fidoutilsConfig.mtc);
	if (!mtcConfig) {
		throw new Error("MTC configuration not found in fidoutilsConfig.mtc");
	}
	if (!mtcConfig.coseKey) {
		throw new Error("MTC configuration missing 'coseKey' required by the mtc-debug extension");
	}

	let toBytes = function(v) {
		return Buffer.isBuffer(v) || v instanceof Uint8Array
			? Buffer.from(v)
			: Buffer.from(mykeyutil.fromHex(String(v).replace(/:/g, "")));
	};

	let authenticatorOutput = { pubKey: toBytes(mtcConfig.coseKey) };
	let clientOutput = { pubKey: mykeyutil.toBase64Url(authenticatorOutput.pubKey) };

	if (enterpriseAttestation && mtcConfig.deviceSerial != null) {
		authenticatorOutput.deviceSerial = String(mtcConfig.deviceSerial);
		clientOutput.deviceSerial = authenticatorOutput.deviceSerial;
	}
	for (const name of ["notBefore", "notAfter", "firmwareVersion"]) {
		if (mtcConfig[name] != null) {
			authenticatorOutput[name] = Number(mtcConfig[name]);
			clientOutput[name] = authenticatorOutput[name];
		}
	}
	for (const name of ["mtcProof", "rootHash"]) {
		if (mtcConfig[name] != null) {
			authenticatorOutput[name] = toBytes(mtcConfig[name]);
			clientOutput[name] = mykeyutil.toBase64Url(authenticatorOutput[name]);
		}
	}

	return { authenticatorOutput: authenticatorOutput, clientOutput: clientOutput };
}


/**
 * Builds a Merkle Tree Certificate (MTC) Attestation Statement (fmt: "mtc")
 * per WebAuthn Level 4 §8.10.
 *
 * @param {Array<number>|Uint8Array|Buffer} clientDataHash - SHA-256 hash of clientDataJSON
 * @param {Array<number>|Uint8Array|Buffer} authData - Authenticator data bytes
 * @param {object} [mtcOverrideConfig] - Optional override for fidoutilsConfig.mtc
 * @returns {Promise<object>} attStmt object formatted for CBOR encoding
 */
async function buildMTCAttestationStatement(
	clientDataHash,
	authData,
	mtcOverrideConfig
) {
	let mtcConfig = mtcOverrideConfig || (fidoutilsConfig && fidoutilsConfig.mtc);
	if (!mtcConfig) {
		throw new Error("MTC configuration not found in fidoutilsConfig.mtc");
	}

	let caId = mtcConfig.caId;
	if (!caId) {
		throw new Error("MTC configuration missing 'caId'");
	}
	let caIdBytes;
	if (typeof caId === "string") {
		caIdBytes = mykeyutil.fromHex(caId.replace(/:/g, ""));
	} else if (Buffer.isBuffer(caId) || caId instanceof Uint8Array || Array.isArray(caId)) {
		caIdBytes = Buffer.from(caId);
	} else {
		throw new TypeError("Invalid caId in MTC configuration");
	}

	let serial = mtcConfig.serial;
	if (serial === undefined || serial === null) {
		throw new Error("MTC configuration missing 'serial'");
	}
	if (typeof serial === "string") {
		serial = Number(serial);
	} else if (typeof serial === "bigint") {
		if (serial <= BigInt(Number.MAX_SAFE_INTEGER)) {
			serial = Number(serial);
		}
	}

	let alg = mtcConfig.alg;
	if (alg === undefined || alg === null) {
		throw new Error("MTC configuration missing 'alg'");
	}

	let privateKey = mtcConfig.privateKey;
	if (!privateKey) {
		if (mtcConfig.privateKeyHex) {
			privateKey = await mykeyutil.getPrivateKeyFromHex(
				alg,
				mtcConfig.privateKeyHex.replace(/:/g, "")
			);
		} else {
			throw new Error("MTC configuration missing 'privateKey' or 'privateKeyHex'");
		}
	}

	// verificationData = authenticatorData || clientDataHash (raw bytes, no outer pre-hash)
	let authDataBuf = Buffer.isBuffer(authData) ? authData : Buffer.from(authData);
	let clientDataHashBuf = Buffer.isBuffer(clientDataHash) ? clientDataHash : Buffer.from(clientDataHash);
	let verificationData = Buffer.concat([authDataBuf, clientDataHashBuf]);

	// Generate signature using authenticator batch private key
	let sigBytes = await mykeyutil.signBytesWithPrivateKey(alg, privateKey, verificationData);

	let attStmt = {
		alg: alg,
		sig: prepareBAForCBOR(sigBytes),
		mtcCert: {
			caId: prepareBAForCBOR(caIdBytes),
			serial: serial
		}
	};

	return attStmt;
}

/*
 * Relying Party verification of Merkle Tree Certificate (MTC) attestation (WebAuthn Level 4 §8.10).
 * Nothing below uses jsrsasign.
 */

// COSE algorithms an RP accepts for attStmt.alg by default (ML-DSA-44/65/87 and ES256)
const MTC_DEFAULT_ACCEPTABLE_ALGS = [-48, -49, -50, -7];
const MTC_LEAF_INDEX_MASK = 0xFFFFFFFFFFFFn; // serial & mask = leaf index, serial >> 48 = logNumber

function mtcFail(reason) {
	throw new Error("MTC attestation verification failed: " + reason);
}

function mtcAsObject(o, name) {
	if (o instanceof Map) {
		o = Object.fromEntries(o);
	}
	if (o == null || typeof o !== "object" || Array.isArray(o) || ArrayBuffer.isView(o) || o instanceof ArrayBuffer) {
		mtcFail(name + " is not a map");
	}
	return o;
}

// byte string (Buffer/Uint8Array/ArrayBuffer/array of bytes) to Buffer
function mtcToBuffer(v, name) {
	if (Buffer.isBuffer(v)) {
		return v;
	} else if (v instanceof Uint8Array) {
		return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
	} else if (v instanceof ArrayBuffer) {
		return Buffer.from(v);
	} else if (Array.isArray(v) && v.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) {
		return Buffer.from(v);
	}
	return mtcFail(name + " is not a byte string");
}

// like mtcToBuffer, but metadata (MDS3 style JSON) carries binary values as standard base64 strings
function mtcMetaBytes(v, name) {
	if (typeof v === "string") {
		try {
			return mykeyutil.fromBase64(v);
		} catch (e) {
			mtcFail(name + " is not valid base64");
		}
	}
	return mtcToBuffer(v, name);
}

// unsigned 64-bit integer (number, bigint or decimal string) to BigInt
function mtcToUint64(v, name) {
	let result = null;
	try {
		if ((typeof v === "number" && Number.isSafeInteger(v)) || typeof v === "bigint" || (typeof v === "string" && /^[0-9]+$/.test(v))) {
			result = BigInt(v);
		}
	} catch (e) {
		result = null;
	}
	if (result === null || result < 0n || result >= (1n << 64n)) {
		mtcFail(name + " is not an unsigned 64-bit integer");
	}
	return result;
}

function mtcDecodeAttestationObject(attestationObject) {
	let ao = attestationObject;
	try {
		if (typeof ao === "string") {
			ao = mykeyutil.fromBase64Url(ao);
		}
		if (ao instanceof Uint8Array || ao instanceof ArrayBuffer) {
			ao = cbor.decodeFirstSync(mtcToBuffer(ao, "attestationObject"));
		}
	} catch (e) {
		mtcFail("attestationObject cannot be decoded: " + e.message);
	}
	return mtcAsObject(ao, "attestationObject");
}

/**
 * Verifies the Level 3 Merkle inclusion proof and (when a signature is supplied) the Level 1/2 checkpoint signature.
 * Returns null on success, or a reason string.
 */
async function mtcCheckSubtree(subtree, caId, logNumber, leafIndex, leafHash, proofChunks, rootCertsDER, mustVerifyCheckpoint) {
	let rootHash = mtcMetaBytes(subtree.rootHash, "subtrees[].rootHash");
	if (!mycertutil.verifyRFC9162MerkleProof({
		leafHash: leafHash,
		proof: proofChunks,
		leafIndex: leafIndex,
		start: subtree.start,
		end: subtree.end,
		rootHash: rootHash
	})) {
		return "Merkle inclusion proof does not climb to the subtree root hash";
	}
	if (!mustVerifyCheckpoint) {
		return null;
	}

	let checkpoint = mycertutil.buildFidoMtcSubtreeCheckpoint({
		caId: caId,
		logNumber: logNumber,
		start: subtree.start,
		end: subtree.end,
		rootHash: rootHash
	});
	let signature = mtcMetaBytes(subtree.signature, "subtrees[].signature");
	for (const der of rootCertsDER) {
		try {
			let rootKey = await mykeyutil.getPublicKeyFromCertBytes(Array.from(der), subtree.alg);
			if (await mykeyutil.validateSignature(subtree.alg, rootKey, checkpoint, signature)) {
				return null;
			}
		} catch (e) {
			// root certificate with a different key type: try the next one
		}
	}
	return "subtree checkpoint signature is not valid for any attestation root certificate";
}

/**
 * Relying Party verification of a Merkle Tree Certificate attestation (fmt: "mtc"), WebAuthn Level 4 §8.10.
 *
 * Levels verified (see MTC_IMPLEMENTATION_PLAN.md): 5 attStmt.sig over authenticatorData || clientDataHash with the batch key;
 * 4 the batch key (COSE_Key) is the one committed in the leaf; 3 the RFC 9162 inclusion proof climbs to the subtree root hash;
 * 2/1 the subtree checkpoint signature verifies with the vendor root CA certificate (MDS mode only).
 * Level 0 (the MDS3 BLOB JWS) is NOT checked here: mdsMetadata must already be an authenticated MetadataStatement.
 *
 * Two ways to resolve the attestation key entry for (attStmt.mtcCert.caId, serial):
 *  - MDS mode: mdsMetadata.mtcTrustAnchors[].batchKeys[] (the shape produced by certs/generate_attestation_certs.js);
 *    the checkpoint signature is verified with mdsMetadata.attestationRootCertificates.
 *  - In-band (offline conformance) mode, only if options.allowInBand is true and the entry is not in mdsMetadata:
 *    authenticatorData.extensions["mtc-debug"]. There is no trust anchor, so only Levels 3-5 are checked and the result
 *    has trusted: false. The subtree is assumed to be an aligned perfect tree of 2^len(mtcProof)/32 leaves.
 *
 * Not covered: enterprise mode (manufacturer manifest / device serial inventory check, spec step 9).
 *
 * @param {object|Buffer|string} attestationObject - decoded { fmt, attStmt, authData }, CBOR bytes, or base64url string
 * @param {Array<number>|Uint8Array|Buffer} clientDataHash - SHA-256 of clientDataJSON
 * @param {object} [mdsMetadata] - MDS3 MetadataStatement containing mtcTrustAnchors and attestationRootCertificates (base64)
 *   An anchor may carry revokedSerialRanges: [{ start, end }] (inclusive serials) which are rejected.
 * @param {object} [options] - { allowInBand: false, acceptableAlgs: [-48,-49,-50,-7], now: <unix seconds> }
 * @returns {Promise<object>} resolves with details of the verified attestation; rejects with an Error if verification fails
 */
async function verifyMTCAttestation(attestationObject, clientDataHash, mdsMetadata, options) {
	options = options || {};
	let acceptableAlgs = options.acceptableAlgs || MTC_DEFAULT_ACCEPTABLE_ALGS;

	// Step 1: CDDL syntax of fmt and mtcStmtFormat { alg, sig, mtcCert: { caId, serial } }
	let att = mtcDecodeAttestationObject(attestationObject);
	if (att.fmt !== "mtc") {
		mtcFail('fmt is not "mtc"');
	}
	let attStmt = mtcAsObject(att.attStmt, "attStmt");
	if (Object.keys(attStmt).sort().join() !== "alg,mtcCert,sig") {
		mtcFail("attStmt must contain exactly alg, sig and mtcCert");
	}
	let alg = attStmt.alg;
	if (!Number.isInteger(alg)) {
		mtcFail("attStmt.alg is not an integer");
	}
	let sig = mtcToBuffer(attStmt.sig, "attStmt.sig");
	if (sig.length === 0) {
		mtcFail("attStmt.sig is empty");
	}
	let mtcCert = mtcAsObject(attStmt.mtcCert, "attStmt.mtcCert");
	if (Object.keys(mtcCert).sort().join() !== "caId,serial") {
		mtcFail("attStmt.mtcCert must contain exactly caId and serial");
	}
	let caId = mtcToBuffer(mtcCert.caId, "attStmt.mtcCert.caId");
	if (caId.length === 0 || caId.length > 0xffff) {
		mtcFail("attStmt.mtcCert.caId has an invalid length");
	}
	let serial = mtcToUint64(mtcCert.serial, "attStmt.mtcCert.serial");

	// Step 2: alg acceptable to the RP
	if (acceptableAlgs.indexOf(alg) < 0) {
		mtcFail("alg " + alg + " is not acceptable");
	}

	// Step 3: verificationData = authenticatorData || clientDataHash (raw bytes, no outer pre-hash)
	let authData = mtcToBuffer(att.authData, "authData");
	let clientDataHashBuf = mtcToBuffer(clientDataHash, "clientDataHash");
	if (clientDataHashBuf.length !== 32) {
		mtcFail("clientDataHash must be 32 bytes");
	}
	let verificationData = Buffer.concat([authData, clientDataHashBuf]);

	let unpacked = unpackAuthData(authData);
	if (!unpacked.status || unpacked.attestedCredData == null || unpacked.attestedCredData.aaguid == null) {
		mtcFail("authenticatorData is malformed or has no attested credential data");
	}
	let aaguid = Buffer.from(unpacked.attestedCredData.aaguid);
	let debugExt = (unpacked.extensions != null && unpacked.extensions["mtc-debug"] != null)
		? mtcAsObject(unpacked.extensions["mtc-debug"], "authenticatorData.extensions[mtc-debug]")
		: null;

	// Step 4: resolve the attestation key entry
	let entry = null;
	let anchor = null;
	if (mdsMetadata != null) {
		anchor = (mdsMetadata.mtcTrustAnchors || []).find((a) => mtcMetaBytes(a.caId, "mtcTrustAnchors[].caId").equals(caId)) || null;
		let batchKey = anchor == null ? null : (anchor.batchKeys || []).find((k) => mtcToUint64(k.serial, "batchKeys[].serial") === serial);
		if (batchKey != null) {
			if (mdsMetadata.aaguid != null && !mykeyutil.fromHex(String(mdsMetadata.aaguid).replace(/-/g, "")).equals(aaguid)) {
				mtcFail("authenticatorData aaguid does not match the metadata statement aaguid");
			}
			entry = {
				mode: "mds",
				coseKeyBytes: mtcMetaBytes(batchKey.coseKey, "batchKeys[].coseKey"),
				notBefore: mtcToUint64(batchKey.notBefore, "batchKeys[].notBefore"),
				notAfter: mtcToUint64(batchKey.notAfter, "batchKeys[].notAfter"),
				firmwareVersion: batchKey.firmwareVersion == null ? null : mtcToUint64(batchKey.firmwareVersion, "batchKeys[].firmwareVersion"),
				extensions: batchKey.extensions == null ? null : mtcMetaBytes(batchKey.extensions, "batchKeys[].extensions"),
				proof: batchKey.mtcProof == null ? null : mtcMetaBytes(batchKey.mtcProof, "batchKeys[].mtcProof")
			};
		}
	}
	if (entry == null) {
		if (!options.allowInBand || debugExt == null) {
			mtcFail("no batch key found for (caId, serial) in the metadata" + (debugExt == null ? "" : " and in-band verification is not allowed"));
		}
		if (debugExt.pubKey == null || debugExt.notBefore == null || debugExt.notAfter == null || debugExt.mtcProof == null || debugExt.rootHash == null) {
			mtcFail("mtc-debug extension must contain pubKey, notBefore, notAfter, mtcProof and rootHash");
		}
		entry = {
			mode: "in-band",
			coseKeyBytes: mtcToBuffer(debugExt.pubKey, "mtc-debug.pubKey"),
			notBefore: mtcToUint64(debugExt.notBefore, "mtc-debug.notBefore"),
			notAfter: mtcToUint64(debugExt.notAfter, "mtc-debug.notAfter"),
			firmwareVersion: debugExt.firmwareVersion == null ? null : mtcToUint64(debugExt.firmwareVersion, "mtc-debug.firmwareVersion"),
			extensions: null,
			proof: mtcToBuffer(debugExt.mtcProof, "mtc-debug.mtcProof"),
			rootHash: mtcToBuffer(debugExt.rootHash, "mtc-debug.rootHash")
		};
	} else if (debugExt != null && debugExt.pubKey != null && !mtcToBuffer(debugExt.pubKey, "mtc-debug.pubKey").equals(entry.coseKeyBytes)) {
		mtcFail("mtc-debug pubKey differs from the key resolved from the metadata");
	}

	// Step 5: COSE_Key must be canonical, its alg (3) must match attStmt.alg, and sig must verify over verificationData
	let coseMap;
	try {
		coseMap = cbor.decodeFirstSync(entry.coseKeyBytes);
		if (!(coseMap instanceof Map) || !cbor.encodeCanonical(coseMap).equals(entry.coseKeyBytes)) {
			throw new Error("not a canonical CBOR map");
		}
	} catch (e) {
		mtcFail("batch key is not a canonical CBOR COSE_Key: " + e.message);
	}
	if (coseMap.get(3) !== alg) {
		mtcFail("COSE_Key alg does not match attStmt.alg");
	}
	let coseObj = {};
	for (const [k, v] of coseMap) {
		coseObj[String(k)] = Buffer.isBuffer(v) ? Array.from(v) : v;
	}
	let sigValid = false;
	try {
		let batchPublicKey = await mykeyutil.getPublicKeyFromCOSE(coseObj);
		sigValid = await mykeyutil.validateSignature(alg, batchPublicKey, verificationData, sig);
	} catch (e) {
		sigValid = false;
	}
	if (!sigValid) {
		mtcFail("attStmt.sig is not a valid signature over authenticatorData || clientDataHash");
	}

	// Step 6: notBefore <= now <= notAfter
	let now = BigInt(Math.floor(options.now != null ? options.now : Date.now() / 1000));
	if (now < entry.notBefore || now > entry.notAfter) {
		mtcFail("the batch key is outside its validity period");
	}

	// Step 7: revocation (optional anchor.revokedSerialRanges, inclusive serial ranges)
	if (anchor != null && Array.isArray(anchor.revokedSerialRanges)) {
		for (const r of anchor.revokedSerialRanges) {
			if (serial >= mtcToUint64(r.start, "revokedSerialRanges[].start") && serial <= mtcToUint64(r.end, "revokedSerialRanges[].end")) {
				mtcFail("serial is revoked");
			}
		}
	}

	// Step 8: Merkle commitment (Levels 3/4, plus the Level 2/1 checkpoint signature in MDS mode)
	if (entry.proof == null) {
		mtcFail("mtcProof is required: the Merkle commitment of the batch key cannot be checked");
	}
	if (entry.proof.length % 32 !== 0) {
		mtcFail("mtcProof is not a multiple of 32 bytes");
	}
	let proofChunks = [];
	for (let i = 0; i < entry.proof.length; i += 32) {
		proofChunks.push(entry.proof.subarray(i, i + 32));
	}

	let leafIndex = serial & MTC_LEAF_INDEX_MASK;
	let logNumber = serial >> 48n;
	let leafHash = mycertutil.computeFidoMtcLeafHash(mycertutil.buildFidoMtcLogEntry({
		caId: caId,
		serial: serial,
		notBefore: entry.notBefore,
		notAfter: entry.notAfter,
		aaguid: aaguid,
		firmwareVersion: entry.firmwareVersion,
		coseKeyBytes: entry.coseKeyBytes,
		extensions: entry.extensions
	}));

	let subtree = null;
	if (entry.mode === "mds") {
		let rootCertsDER = (mdsMetadata.attestationRootCertificates || []).map((c) => mtcMetaBytes(c, "attestationRootCertificates[]"));
		let candidates = (anchor.subtrees || []).filter((s) =>
			BigInt(s.logNumber) === logNumber && BigInt(s.start) <= leafIndex && leafIndex < BigInt(s.end));
		if (candidates.length === 0) {
			mtcFail("no subtree in the metadata covers this serial");
		}
		let lastReason = null;
		for (const candidate of candidates) {
			lastReason = await mtcCheckSubtree(candidate, caId, logNumber, leafIndex, leafHash, proofChunks, rootCertsDER, true);
			if (lastReason == null) {
				subtree = candidate;
				break;
			}
		}
		if (subtree == null) {
			mtcFail(lastReason);
		}
	} else {
		if (proofChunks.length > 48) {
			mtcFail("mtcProof is too long");
		}
		let size = 1n << BigInt(proofChunks.length);
		let start = leafIndex - (leafIndex % size);
		subtree = { start: start, end: start + size, rootHash: entry.rootHash };
		let reason = await mtcCheckSubtree(subtree, caId, logNumber, leafIndex, leafHash, proofChunks, [], false);
		if (reason != null) {
			mtcFail(reason);
		}
	}

	return {
		verified: true,
		mode: entry.mode,
		// false when the batch key was only checked against a root hash supplied by the authenticator itself
		trusted: entry.mode === "mds",
		attestationType: "basic",
		alg: alg,
		caId: caId,
		serial: serial,
		logNumber: Number(logNumber),
		leafIndex: leafIndex,
		aaguid: aaguid,
		notBefore: entry.notBefore,
		notAfter: entry.notAfter,
		batchPublicKeyCose: entry.coseKeyBytes,
		subtree: { start: BigInt(subtree.start), end: BigInt(subtree.end) },
		rootHash: mtcMetaBytes(subtree.rootHash, "rootHash"),
		deviceSerial: debugExt != null && debugExt.deviceSerial != null ? String(debugExt.deviceSerial) : null
	};
}

/**
 * RP rule from WebAuthn Level 4 §10.2.1: the registration ceremony MUST fail if authenticatorData.extensions contains
 * "mtc-debug", or clientExtensionResults.mtcDebug is present, when fmt is not "mtc".
 *
 * @returns {boolean} true when the rule is satisfied; throws an Error when it is violated
 */
function assertNoMTCDebugUnlessMTC(attestationObject, clientExtensionResults) {
	let att = mtcDecodeAttestationObject(attestationObject);
	let unpacked = unpackAuthData(mtcToBuffer(att.authData, "authData"));
	let present = (unpacked.extensions != null && unpacked.extensions["mtc-debug"] !== undefined) ||
		(clientExtensionResults != null && clientExtensionResults.mtcDebug !== undefined);
	if (present && att.fmt !== "mtc") {
		throw new Error("mtc-debug extension output is only allowed with fmt \"mtc\"");
	}
	return true;
}




/*
* Override the CBOR decode method with a slightly modified version that handles remaining bytes in a
* way that allows implementation of cbor.decodeVariable
*/
cbor.decode = function(data, tagger, simpleValue) {
	var POW_2_24 = Math.pow(2, -24);
	var POW_2_32 = Math.pow(2, 32);
	var POW_2_53 = Math.pow(2, 53);
	var dataView = new DataView(data);
	var offset = 0;
  
	if (typeof tagger !== "function")
	  tagger = function(value) { return value; };
	if (typeof simpleValue !== "function")
	  simpleValue = function() { return undefined; };
  
	function commitRead(length, value) {
	  offset += length;
	  return value;
	}
	function readArrayBuffer(length) {
	  return commitRead(length, new Uint8Array(data, offset, length));
	}
	function readFloat16() {
	  var tempArrayBuffer = new ArrayBuffer(4);
	  var tempDataView = new DataView(tempArrayBuffer);
	  var value = readUint16();
  
	  var sign = value & 0x8000;
	  var exponent = value & 0x7c00;
	  var fraction = value & 0x03ff;
  
	  if (exponent === 0x7c00)
		exponent = 0xff << 10;
	  else if (exponent !== 0)
		exponent += (127 - 15) << 10;
	  else if (fraction !== 0)
		return (sign ? -1 : 1) * fraction * POW_2_24;
  
	  tempDataView.setUint32(0, sign << 16 | exponent << 13 | fraction << 13);
	  return tempDataView.getFloat32(0);
	}
	function readFloat32() {
	  return commitRead(4, dataView.getFloat32(offset));
	}
	function readFloat64() {
	  return commitRead(8, dataView.getFloat64(offset));
	}
	function readUint8() {
	  return commitRead(1, dataView.getUint8(offset));
	}
	function readUint16() {
	  return commitRead(2, dataView.getUint16(offset));
	}
	function readUint32() {
	  return commitRead(4, dataView.getUint32(offset));
	}
	function readUint64() {
	  return readUint32() * POW_2_32 + readUint32();
	}
	function readBreak() {
	  if (dataView.getUint8(offset) !== 0xff)
		return false;
	  offset += 1;
	  return true;
	}
	function readLength(additionalInformation) {
	  if (additionalInformation < 24)
		return additionalInformation;
	  if (additionalInformation === 24)
		return readUint8();
	  if (additionalInformation === 25)
		return readUint16();
	  if (additionalInformation === 26)
		return readUint32();
	  if (additionalInformation === 27)
		return readUint64();
	  if (additionalInformation === 31)
		return -1;
	  throw "Invalid length encoding";
	}
	function readIndefiniteStringLength(majorType) {
	  var initialByte = readUint8();
	  if (initialByte === 0xff)
		return -1;
	  var length = readLength(initialByte & 0x1f);
	  if (length < 0 || (initialByte >> 5) !== majorType)
		throw "Invalid indefinite length element";
	  return length;
	}
  
	function appendUtf16Data(utf16data, length) {
	  for (var i = 0; i < length; ++i) {
		var value = readUint8();
		if (value & 0x80) {
		  if (value < 0xe0) {
			value = (value & 0x1f) <<  6
				  | (readUint8() & 0x3f);
			length -= 1;
		  } else if (value < 0xf0) {
			value = (value & 0x0f) << 12
				  | (readUint8() & 0x3f) << 6
				  | (readUint8() & 0x3f);
			length -= 2;
		  } else {
			value = (value & 0x0f) << 18
				  | (readUint8() & 0x3f) << 12
				  | (readUint8() & 0x3f) << 6
				  | (readUint8() & 0x3f);
			length -= 3;
		  }
		}
  
		if (value < 0x10000) {
		  utf16data.push(value);
		} else {
		  value -= 0x10000;
		  utf16data.push(0xd800 | (value >> 10));
		  utf16data.push(0xdc00 | (value & 0x3ff));
		}
	  }
	}
  
	function decodeItem() {
	  var initialByte = readUint8();
	  var majorType = initialByte >> 5;
	  var additionalInformation = initialByte & 0x1f;
	  var i;
	  var length;
  
	  if (majorType === 7) {
		switch (additionalInformation) {
		  case 25:
			return readFloat16();
		  case 26:
			return readFloat32();
		  case 27:
			return readFloat64();
		}
	  }
  
	  length = readLength(additionalInformation);
	  if (length < 0 && (majorType < 2 || 6 < majorType))
		throw "Invalid length";
  
	  switch (majorType) {
		case 0:
		  return length;
		case 1:
		  return -1 - length;
		case 2:
		  if (length < 0) {
			var elements = [];
			var fullArrayLength = 0;
			while ((length = readIndefiniteStringLength(majorType)) >= 0) {
			  fullArrayLength += length;
			  elements.push(readArrayBuffer(length));
			}
			var fullArray = new Uint8Array(fullArrayLength);
			var fullArrayOffset = 0;
			for (i = 0; i < elements.length; ++i) {
			  fullArray.set(elements[i], fullArrayOffset);
			  fullArrayOffset += elements[i].length;
			}
			return fullArray;
		  }
		  return readArrayBuffer(length);
		case 3:
		  var utf16data = [];
		  if (length < 0) {
			while ((length = readIndefiniteStringLength(majorType)) >= 0)
			  appendUtf16Data(utf16data, length);
		  } else
			appendUtf16Data(utf16data, length);
		  return String.fromCharCode.apply(null, utf16data);
		case 4:
		  var retArray;
		  if (length < 0) {
			retArray = [];
			while (!readBreak())
			  retArray.push(decodeItem());
		  } else {
			retArray = new Array(length);
			for (i = 0; i < length; ++i)
			  retArray[i] = decodeItem();
		  }
		  return retArray;
		case 5:
		  var retObject = {};
		  for (i = 0; i < length || length < 0 && !readBreak(); ++i) {
			var key = decodeItem();
			retObject[key] = decodeItem();
		  }
		  return retObject;
		case 6:
		  return tagger(decodeItem(), length);
		case 7:
		  switch (length) {
			case 20:
			  return false;
			case 21:
			  return true;
			case 22:
			  return null;
			case 23:
			  return undefined;
			default:
			  return simpleValue(length);
		  }
	  }
	}
  
	var ret = decodeItem();
  
	/*
	 * Here is the modification: deal with remaining bytes a different way so we can implement decodeVariable
	 */
	//if (offset !== datalen) {
	//  throw "Remaining bytes";
	//}
	if (offset !== data.byteLength) {
		var result = {};
		result["decodedObj"] = ret;
		result["datalen"] = data.byteLength;
		result["offset"] = offset;
		throw result;
	  }
  
	return ret;
  }
  
  /*
  * Added this extra CBOR function to allow extraction of CBOR from a larger byte array
  */
  cbor.decodeVariable = function(data, tagger, simpleValue) {
	  try {
		  var result = { "decodedObj": cbor.decode(data, tagger, simpleValue), "offset": -1 };
		  return result;
	  } catch (e) {
		  if (e["decodedObj"] != null && e["offset"] != null) {
			  // this is a partial decode with remaining bytes
			  return e;
		  } else {
			  throw e;
		  }
	  }
  }   
/**
 * Convert a 4-byte array to a uint assuming big-endian encoding
 * 
 * @param buf
 */
function bytesToUInt32BE(buf) {
	var result = 0;
	if (buf != null && buf.length == 4) {
		result = ((buf[0] & 0xFF) << 24) | ((buf[1] & 0xFF) << 16) | ((buf[2] & 0xFF) << 8) | (buf[3] & 0xFF);
		return result;
	}
	return result;
}

/**
* Used to introspect a result for debug/printing purposes. Not actually used in construction of
* an object used by the client.
*/
function unpackAuthData(authDataBytes) {
	var result = { 
		"status": false, 
		"rawBytes": null,
		"rpIdHashBytes": null, 
		"flags": 0, 
		"counter": 0, 
		"attestedCredData": null,
		"extensions": null
	};
	
	result["rawBytes"] = authDataBytes;
	
	if (authDataBytes != null && authDataBytes.length >= 37) {
		result["rpIdHashBytes"] = bytesFromArray(authDataBytes, 0, 32);
		result["flags"] = authDataBytes[32];
		result["counter"] = bytesToUInt32BE(bytesFromArray(authDataBytes, 33, 37));
				
		var nextByteIndex = 37;
		
		// check flags to see if there is attested cred data and/or extensions
		
		// bit 6 of flags - Indicates whether the authenticator added attested credential data.
		if (result["flags"] & 0x40) {
			result["attestedCredData"] = {};
			
			// are there enough bytes to read aaguid?
			if (authDataBytes.length >= (nextByteIndex + 16)) {
				result["attestedCredData"]["aaguid"] = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+16));
				nextByteIndex += 16;
				
				// are there enough bytes for credentialIdLength?
				if (authDataBytes.length >= (nextByteIndex + 2)) {
					var credentialIdLengthBytes = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+2));
					nextByteIndex += 2;
					var credentialIdLength = credentialIdLengthBytes[0] * 256 + credentialIdLengthBytes[1] 
					result["attestedCredData"]["credentialIdLength"] = credentialIdLength;
					
					// are there enough bytes for the credentialId?
					if (authDataBytes.length >= (nextByteIndex + credentialIdLength)) {
						result["attestedCredData"]["credentialId"] = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+credentialIdLength));
						nextByteIndex += credentialIdLength;
						
						var remainingBytes = bytesFromArray(authDataBytes, nextByteIndex, -1);
						
						//
						// try CBOR decoding the remaining bytes. 
						// NOTE: There could be both credentialPublicKey and extensions objects
						// so we use this special decodeVariable that Shane wrote to deal with
						// remaining bytes.
						//
						try {
							var decodeResult = cbor.decodeVariable((new Uint8Array(remainingBytes)).buffer);
							result["attestedCredData"]["credentialPublicKey"] = decodeResult["decodedObj"];
							nextByteIndex += (decodeResult["offset"] == -1 ? remainingBytes.length : decodeResult["offset"]);
						} catch (e) {
							console.log("Error CBOR decoding credentialPublicKey: " + e);
							nextByteIndex = -1; // to force error checking
						}
					} else {
						console.log("unPackAuthData encountered authDataBytes not containing enough bytes for credentialId in attested credential data");
					}					
				} else {
					console.log("unPackAuthData encountered authDataBytes not containing enough bytes for credentialIdLength in attested credential data");
				}				
			} else {
				console.log("unPackAuthData encountered authDataBytes not containing enough bytes for aaguid in attested credential data");
			}
		}
		
		// bit 7 of flags - Indicates whether the authenticator has extensions.
		if (nextByteIndex > 0 && result["flags"] & 0x80) {
			try {
				result["extensions"] = cbor.decode((new Uint8Array(bytesFromArray(authDataBytes, nextByteIndex, -1))).buffer);
				// must have worked
				nextByteIndex = authDataBytes.length;
			} catch (e) {
				console.log("Error CBOR decoding extensions");
			}
		}
		
		// we should be done - make sure we processed all the bytes
		if (nextByteIndex == authDataBytes.length) {
			result["status"] = true;
		} else {
			console.log("Remaining bytes in unPackAuthData. nextByteIndex: " + nextByteIndex + " authDataBytes.length: " + authDataBytes.length);
		}
	} else {
		console.log("unPackAuthData encountered authDataBytes not at least 37 bytes long. Actual length: " + authDataBytes.length);
	}

	return result;
}

function init() {
	return mykeyutil.init();
}

module.exports = {
	init: init,
	attestationOptionsResponeToCredentialCreationOptions: attestationOptionsResponeToCredentialCreationOptions,
	processCredentialCreationOptions: processCredentialCreationOptions,
	assertionOptionsResponeToCredentialRequestOptions: assertionOptionsResponeToCredentialRequestOptions,
	processCredentialRequestOptions: processCredentialRequestOptions,
	bytesFromArray: bytesFromArray,
	base64toBA: base64toBA,
	base64utobase64: base64utobase64,
	certToPEM: certToPEM,
	canAuthenticateWithCredId: canAuthenticateWithCredId,
	getFidoUtilsConfig: getFidoUtilsConfig,
	setFidoUtilsConfig: setFidoUtilsConfig,
	unpackAuthData: unpackAuthData,
	verifyMTCAttestation: verifyMTCAttestation,
	assertNoMTCDebugUnlessMTC: assertNoMTCDebugUnlessMTC
};
