// fidoutils.js

const cbor = require('cbor'); // https://www.npmjs.com/package/cbor
const jsrsasign = require('jsrsasign'); // https://www.npmjs.com/package/jsrsasign
const CryptoJS = require('crypto-js'); // https://www.npmjs.com/package/crypto-js

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
		"cert": "MIIDFjCB/wIJAKiWRVc805iDMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAlVTMQ0wCwYDVQQKDAROSVNUMRMwEQYDVQQDDApVSUNDUm9vdENBMB4XDTE5MDgwNzIwMjgwM1oXDTQ2MTIyMjIwMjgwM1owNTELMAkGA1UEBhMCVVMxDTALBgNVBAoMBE5JU1QxFzAVBgNVBAMMDlVJQ0NVMkYtU0lHTkVSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/9HZpw98HIP6hmCSXfv8u00cIy5UQ/XZ7krXJID+ydIAaMBbXXd3zCX9J9kwFcDqLXL1HY6uGXBym5hgmlAT2zANBgkqhkiG9w0BAQsFAAOCAgEAKP/Ck24JM+8J7Ns4g5a8XczXPPnYe+FFs7bUQoam2sEEPBzapdIssl9rYkFKvxIW8zgPHJVIQJ3hMmq9tGkhKXT+WzIew+BJRzBYscytaaqMURHuqM1usBFQZSBUYIlDCQqezxG9bZ4cx8gzmL4ldYPGwSAex3K9XOVdyNn+ut8/axcfhDYfr0zW498KOg1L72kjthiNTrJWGaCwkfCsNNtBHWy2HmGzAgMLi7Wn3eNzTyrbzj7GBBsFm6Nv5LKLxCwX8YEd6UWzYLuP/AhAG1+w1rfPmbdi0/hXGUr8h51dlTF2DUrxQfZvECA5Du4TZHHKpTu7opI2BSVabXYp+F25RbkcE1oAqjrZeMdeWXFu5bcD5MvQ6Q3D/M1H1ngahFLzyzPprZ1OO5codyiRwhPtSyeR+FIi7yj9Lirxhv+t1pzm9N6z8DEW3Iman5+x+hGPP01n0RFP1H+Fu0jUCZfcZmx0ecrrd2r3B0YpyUR5n45dweBw+dyQZaPm0eenyMYFNuXWNx+aT7wcYFYhoYEqi0n7bGmvR3ZmFws3rBi2uLOamM1cOSnabOQ7Tvirq39TAbJ3dNZAwoD7pFn4YZHeywPGlENnij1bMnTYyVXRr/coi84bD4S147Ydm6lWpMcolpVlplbXJ3S3BDu/AqJGBqQwKtBUDuL0BbnbE+0=",
	},

	"packed": {
		"aaguid": "37c4c2cf41544c5791039c9bdcca5b2b",
		"privateKeyHex":
			"03e158d202854c3bc0cb233a726f4445b41b4ca80b370a2c30d8fe039f820d42",
		"publicKeyHex":
			"045c6c82d6b47e2971a78ebbe8dd910ebbdcecb902019e6b37f743374c5740d9f0533068c562ebd7c11e55258b235efc48aba0d77f6d0ebe6f991321976ea1e072",
		"cert": "MIIDVTCCAT2gAwIBAgIJAKiWRVc805iEMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAlVTMQ0wCwYDVQQKDAROSVNUMRMwEQYDVQQDDApVSUNDUm9vdENBMB4XDTE5MDgwNzIwMjgwM1oXDTQ2MTIyMjIwMjgwM1owXDELMAkGA1UEBhMCVVMxDTALBgNVBAoMBE5JU1QxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEVVJQ0NQQUNLRUQtU0lHTkVSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXGyC1rR+KXGnjrvo3ZEOu9zsuQIBnms390M3TFdA2fBTMGjFYuvXwR5VJYsjXvxIq6DXf20Ovm+ZEyGXbqHgcqMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAtsJl2cVtuRJqwm0SXhP2vGU3An79GxT1appa9JKLWz7iv5zOVWowKvbEnB6sqjNPZ1p65yEi5UmRNnkE6m6IFSRijz5eeWOHQ0ceQN4BhH9veE4Xe3WiOaahTTJX+hqj+5ByMhgw0dZ6+1iEu20BE0zKAA+VSrpA5O+LPOBDNjCfVzLI566ykNqe2mShm+UGNDYkTxVJmFXY9qyy/zLazynroE6qnIt03UutzifAnNNnBKqk9gK9C6cosDHeyvRGy9um1P21EC85yEZvN8wngzNmc8TJwnkXYHP4METHbjR9bmQP60e19a7so9sz7P5MhkFJ/JOURkbWh6qmzIGQhoNpGw6OQnAxHvkPiw9HuDEfjzIFX1LQi74uMIEG7juCIt2u56dXG7T0NM8MfVlupDJzi4AnwI+NuONrKtC5iK6HHSrRxCQ8QiPTemlymPhC/XMJW70PqDiH7cEmCbsDKg9cTN8mWCNNyb1/WkcfrP2zq+jm1Lp8Viam5kHsd66X9VP/44Aj5G6TGJU7ZitBB/hHqz0jznuZU+fRuGf2taQdCP/DXps/VngXrcvs4sRS3aid0KO5eLkUP8e11r909DMTvV/CsqghqXpS13oUbTs8cD12y93EftSbw6OKR30xcV1PScCOY/CSnCuSQFlgrXW1OotzmWQUKKKUB9Egzb8=",
	},

	"packed-self": {
		"aaguid": "1811ec8b8a91459299f217f35d53242e",
	},
};

/*
 * Collection of functions useful to emulate a FIDO2 client and authenticator
 */

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
		prov: "jsrsasign.CryptoJS",
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

function resolveCredentialIdBytesFromPrivateKeyHex(privKeyHEX) {
	if (fidoutilsConfig.encryptionPassphrase == null) {
		throw new Error(
			"Please set the fidoutilsConfig.encryptionPassphrase environment variable"
		);
	}

	return jsrsasign.b64toBA(
		CryptoJS.AES.encrypt(
			privKeyHEX,
			fidoutilsConfig.encryptionPassphrase
		).toString()
	);
}

function resolvePrivateKeyHexFromCredentialIdBytes(credIdBytes) {
	if (fidoutilsConfig.encryptionPassphrase == null) {
		throw new Error(
			"Please set the fidoutilsConfig.encryptionPassphrase environment variable"
		);
	}
	return CryptoJS.AES.decrypt(
		jsrsasign.hextob64(jsrsasign.BAtohex(credIdBytes)),
		fidoutilsConfig.encryptionPassphrase
	).toString(CryptoJS.enc.Utf8);
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

/*
 * Acting as the client+authenticator, prepare a FIDO2 server ServerPublicKeyCredential from a CredentialCreationOptions
 * See example at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#example-authenticator-attestation-response
 * Schema at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredential
 */
function processCredentialCreationOptions(
	cco,
	attestationFormat = "none",
	up = true,
	uv = true
) {
	let result = {
		authenticatorRecord: {
			rpId: cco.publicKey.rp.id,
			privateKeyHex: null,
			credentialID: null,
			userHandle: null,
		},
		spkc: {},
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
		"type": "webauthn.create",
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

	/*
	 * flags
	 *  - conditionally set UV, UP and indicate attested credential data is present
	 *  - Note we never set UV for fido-u2f
	 */
	let flags =
		(up ? 0x01 : 0x00) |
		(uv && attestationFormat != "fido-u2f" ? 0x04 : 0x00) |
		0x40;
	authData.push(flags);

	// add 4 bytes of counter - we use time in epoch seconds as monotonic counter
	let now = new Date().getTime() / 1000;
	authData.push(
		((now & 0xff000000) >> 24) & 0xff,
		((now & 0x00ff0000) >> 16) & 0xff,
		((now & 0x0000ff00) >> 8) & 0xff,
		now & 0x000000ff
	);

	// attestedCredentialData
	let attestedCredentialData = [];

	// aaguid - 16 bytes, if we have one defined use it, otherwise all zeros

	let aaguid =
		fidoutilsConfig[attestationFormat] == null ||
			fidoutilsConfig[attestationFormat].aaguid == null
			? null
			: jsrsasign.b64toBA(
				jsrsasign.hextob64(
					fidoutilsConfig[attestationFormat].aaguid.replace(/-/g, "")
				)
			);
	if (aaguid == null) {
		aaguid = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	}
	attestedCredentialData.push(...aaguid);

	// based on the attestationFormat, we use some different attestation keys

	// we use the ECDSA key for the registered keypair - generate a new keypair now
	let keypair = jsrsasign.KEYUTIL.generateKeypair("EC", "prime256v1");

	//
	// map the private key to a credential id - this is just one way to do it with key wrapping
	// you could also locally store the private key and index with any credentialId handle you like
	//
	let credIdBytes = resolveCredentialIdBytesFromPrivateKeyHex(
		keypair.prvKeyObj.prvKeyHex
	);

	// store the private/public  key, credentialID and userHandle
	result.authenticatorRecord.privateKeyHex = keypair.prvKeyObj.prvKeyHex;
	result.authenticatorRecord.credentialID = jsrsasign.hextob64u(
		jsrsasign.BAtohex(credIdBytes)
	);
	result.authenticatorRecord.userHandle = jsrsasign.hextob64u(
		jsrsasign.BAtohex(bytesFromArray(cco.publicKey.user.id, 0, -1))
	);

	// COSE format of the EC256 key
	let credPublicKeyCOSE = {
		"1": 2, // kty
		"3": -7, // alg
		"-1": 1, // crv
		"-2": jsrsasign.b64toBA(
			jsrsasign.hextob64(keypair.pubKeyObj.getPublicKeyXYHex()["x"])
		), // xCoordinate
		"-3": jsrsasign.b64toBA(
			jsrsasign.hextob64(keypair.pubKeyObj.getPublicKeyXYHex()["y"])
		), // yCoordinate
	};

	// credentialIdLength (2 bytes) and credential Id
	let lenArray = [
		(credIdBytes.length - (credIdBytes.length & 0xff)) / 256,
		credIdBytes.length & 0xff,
	];
	attestedCredentialData.push(...lenArray);
	attestedCredentialData.push(...credIdBytes);

	// credential public key - take bytes from CBOR encoded COSE key
	let credPublicKeyBytes = bytesFromArray(
		new Uint8Array(cbor.encode(credPublicKeyCOSE)),
		0,
		-1
	);
	attestedCredentialData.push(...credPublicKeyBytes);

	// add attestedCredentialData to authData
	authData.push(...attestedCredentialData);

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
	} else {
		throw ("Unsupported attestationFormat: " + attestationFormat);
	}

	// build the attestationObject
	let attestationObject = {
		"fmt": attestationFormat,
		"attStmt": attStmt,
		"authData": authData,
	};

	// add the base64url of the CBOR encoding of the attestationObject to the response
	saar.attestationObject = jsrsasign.hextob64u(
		jsrsasign.BAtohex(
			bytesFromArray(new Uint8Array(cbor.encode(attestationObject)), 0, -1)
		)
	);

	// construct ServerPublicKeyCredential fields

	// id is base64url encoding of the credId
	result.spkc.id = jsrsasign.hextob64u(jsrsasign.BAtohex(credIdBytes));

	// rawId is the same as id
	result.spkc.rawId = result.spkc.id;

	// response - this is the meat of the data structure, contain the clientDataJSON and attestation
	result.spkc.response = saar;

	// type (from Credential defined here: https://w3c.github.io/webappsec-credential-management/#credential)
	result.spkc.type = "public-key";

	// extension results - for now we populate as empty map
	result.spkc.getClientExtensionResults = {};

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
function processCredentialRequestOptions(
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
		"type": "webauthn.get",
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

	// add 4 bytes of signature counter - we use the current time in epoch seconds as the monotonic counter
	let now = new Date().getTime() / 1000;
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
			let candidateCredIdBytes = bytesFromArray(
				cro.publicKey["allowCredentials"][i].id,
				0,
				-1
			);
			let candidateCredIdStr = jsrsasign.hextob64u(
				jsrsasign.BAtohex(candidateCredIdBytes)
			);
			try {
				let candidatePrivKeyHex =
					resolvePrivateKeyHexFromCredentialIdBytes(candidateCredIdBytes);
				if (candidatePrivKeyHex != null && candidatePrivKeyHex.length > 0) {
					usedCredentialId = candidateCredIdStr;
					privKeyHex = candidatePrivKeyHex;
				}
			} catch (e) {
				// probably not our cred id
				//console.log("Unable to decrypt: " + candidateCredIdStr + " e: " + e);
				//console.log("Ignoring allowCredentials cred id as we could not decrypt it: " + candidateCredIdStr);
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
				usedCredentialId = candidateRecord.credentialID;
				privKeyHex = candidateRecord.privateKeyHex;
				userHandle = candidateRecord.userHandle;
			}
		}
	}

	if (privKeyHex != null) {
		// credential information
		let ecdsa = new jsrsasign.KJUR.crypto.ECDSA({ "curve": "prime256v1" });
		ecdsa.setPrivateKeyHex(privKeyHex);

		// compute the signature
		let cHash = sha256(
			jsrsasign.b64toBA(jsrsasign.b64utob64(saar.clientDataJSON))
		);
		let sigBase = [];
		sigBase.push(...authData);
		sigBase.push(...cHash);

		let sig = new jsrsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
		sig.init(ecdsa);
		sig.updateHex(jsrsasign.BAtohex(sigBase));
		let sigValueHex = sig.sign();

		saar.signature = jsrsasign.hextob64u(sigValueHex);

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
	attStmt.x5c = [jsrsasign.b64toBA(jsrsasign.hextob64(attestationCert.hex))];

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

	attStmt.sig = jsrsasign.b64toBA(jsrsasign.hextob64(sigValueHex));
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
		attStmt.x5c = [jsrsasign.b64toBA(jsrsasign.hextob64(attestationCert.hex))];
	}

	// build sigBase
	let sigBase = authData.concat(clientDataHash);

	// generate and populate signature (the sigBase is signed with the attestation cert)
	let sig = new jsrsasign.KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
	sig.init(ecdsa);
	sig.updateHex(jsrsasign.BAtohex(sigBase));
	let sigValueHex = sig.sign();

	attStmt.sig = jsrsasign.b64toBA(jsrsasign.hextob64(sigValueHex));
	return attStmt;
}

function generateRandom(len) {
	// generates a random string of alpha-numerics
	let chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	let result = "";
	for (let i = 0; i < len; i++) {
		result = result + chars.charAt(Math.floor(Math.random() * chars.length));
	}
	return result;
}

module.exports = {
	attestationOptionsResponeToCredentialCreationOptions:
		attestationOptionsResponeToCredentialCreationOptions,
	processCredentialCreationOptions: processCredentialCreationOptions,
	assertionOptionsResponeToCredentialRequestOptions:
		assertionOptionsResponeToCredentialRequestOptions,
	processCredentialRequestOptions: processCredentialRequestOptions,
	bytesFromArray: bytesFromArray,
	base64toBA: base64toBA,
	base64utobase64: base64utobase64,
};
