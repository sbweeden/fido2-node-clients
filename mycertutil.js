// mycertutil.js

// inspiration from https://blog.engelke.com/2014/10/21/web-crypto-and-x-509-certificates/

const nodeCrypto = require('node:crypto');
const { MerkleTree } = require('merkletreejs'); // https://www.npmjs.com/package/merkletreejs

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

const EXTENSION_ID_PROCESSORS = {
    "2.5.29.17": parseSubjectAltName
}

const SPK_ALG_PROCESSORS = {
    "1.3.101.112" : parsePublicKeyED25519,
    "1.2.840.10045.2.1": parseECPublicKey,
    "1.2.840.113549.1.1.1": parseRSAKey,
    "2.16.840.1.101.3.4.3.17": parseMLDSA44,
    "2.16.840.1.101.3.4.3.18": parseMLDSA65,
    "2.16.840.1.101.3.4.3.19": parseMLDSA87
}

const OID_TO_COSE_PARAMS = {
    "1.2.840.10045.3.1.7": {
        kty: 2,
        alg: -7,
        crv: 1
    },
    "1.3.132.0.34": {
        kty: 2,
        alg: -35,
        crv: 2
    },
    "1.3.132.0.35": {
        kty: 2,
        alg: -36,
        crv: 3
    }
}


function berToJavaScript(byteArray) {
    "use strict";
    var result = {};
    var position = 0;

    result.cls              = getClass();
    result.structured       = getStructured();
    result.tag              = getTag();
    var length              = getLength(); // As encoded, which may be special value 0

    if (length === 0x80) {
        length = 0;
        while (byteArray[position + length] !== 0 || byteArray[position + length + 1] !== 0) {
            length += 1;
        }
        result.byteLength   = position + length + 2;
        result.contents     = bytesFromArray(byteArray, position, position + length);
    } else {
        result.byteLength   = position + length;
        result.contents     = bytesFromArray(byteArray, position, result.byteLength);
    }

    result.raw              = bytesFromArray(byteArray,0, result.byteLength); // May not be the whole input array
    return result;

    function getClass() {
        var cls = (byteArray[position] & 0xc0) / 64;
        // Consumes no bytes
        return cls;
    }

    function getStructured() {
        var structured = ((byteArray[0] & 0x20) === 0x20);
        // Consumes no bytes
        return structured;
    }

    function getTag() {
        var tag = byteArray[0] & 0x1f;
        position += 1;
        if (tag === 0x1f) {
            tag = 0;
            while (byteArray[position] >= 0x80) {
                tag = tag * 128 + byteArray[position] - 0x80;
                position += 1;
            }
            tag = tag * 128 + byteArray[position] - 0x80;
            position += 1;
        }
        return tag;
    }

    function getLength() {
        var length = 0;

        if (byteArray[position] < 0x80) {
            length = byteArray[position];
            position += 1;
        } else {
            var numberOfDigits = byteArray[position] & 0x7f;
            position += 1;
            length = 0;
            for (var i=0; i<numberOfDigits; i++) {
                length = length * 256 + byteArray[position];
                position += 1;
            }
        }
        return length;
    }
}

function parseCertificate(byteArray) {
    var asn1 = berToJavaScript(byteArray);
    if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
        throw new Error("This can't be an X.509 certificate. Wrong data type.");
    }

    var cert = {asn1: asn1};  // Include the raw parser result for debugging
    var pieces = berListToJavaScript(asn1.contents);
    if (pieces.length !== 3) {
        throw new Error("Certificate contains more than the three specified children.");
    }

    cert.tbsCertificate     = parseTBSCertificate(pieces[0]);
    cert.signatureAlgorithm = parseAlgorithmIdentifier(pieces[1]);
    cert.signatureValue     = parseSignatureValue(pieces[2]);

    return cert;
}

function berListToJavaScript(byteArray) {
    var result = new Array();
    var nextPosition = 0;
    while (nextPosition < byteArray.length) {
        var nextPiece = berToJavaScript(bytesFromArray(byteArray,nextPosition, -1));
        result.push(nextPiece);
        nextPosition += nextPiece.byteLength;
    }
    return result;
}

function parseSignatureValue(asn1) {
    if (asn1.cls !== 0 || asn1.tag !== 3 || asn1.structured) {
        throw new Error("Bad signature value. Not a BIT STRING.");
    }
    var sig = {asn1: asn1};   // Useful for debugging
    sig.bits = berBitStringValue(asn1.contents);
    return sig;
}

function berBitStringValue(byteArray) {
    return {
        unusedBits: byteArray[0],
        bytes: bytesFromArray(byteArray, 1, -1)
    };
}

function parseAlgorithmIdentifier(asn1) {
    if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
        throw new Error("Bad algorithm identifier. Not a SEQUENCE.");
    }
    var alg = {asn1: asn1};
    var pieces = berListToJavaScript(asn1.contents);
    if (pieces.length > 2) {
        throw new Error("Bad algorithm identifier. Contains too many child objects.");
    }
    var encodedAlgorithm = pieces[0];
    if (encodedAlgorithm.cls !== 0 || encodedAlgorithm.tag !== 6 || encodedAlgorithm.structured) {
        throw new Error("Bad algorithm identifier. Does not begin with an OBJECT IDENTIFIER.");
    }
    alg.algorithm = berObjectIdentifierValue(encodedAlgorithm.contents);
    if (pieces.length === 2) {
        alg.parameters = {asn1: pieces[1]}; // Don't need this now, so not parsing it
    } else {
        alg.parameters = null;  // It is optional
    }
    return alg;
}

function berObjectIdentifierValue(byteArray) {
    var oid = Math.floor(byteArray[0] / 40) + "." + byteArray[0] % 40;
    var position = 1;
    while(position < byteArray.length) {
        var nextInteger = 0;
        while (byteArray[position] >= 0x80) {
            nextInteger = nextInteger * 0x80 + (byteArray[position] & 0x7f);
            position += 1;
        }
        nextInteger = nextInteger * 0x80 + byteArray[position];
        position += 1;
        oid += "." + nextInteger;
    }
    return oid;
}

function parseTBSCertificate(asn1) {
    if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
        throw new Error("This can't be a TBSCertificate. Wrong data type.");
    }
    var tbs = {asn1: asn1};  // Include the raw parser result for debugging
    var pieces = berListToJavaScript(asn1.contents);
    if (pieces.length < 7) {
        throw new Error("Bad TBS Certificate. There are fewer than the seven required children.");
    }
    tbs.version = pieces[0];
    tbs.serialNumber = pieces[1];
    tbs.signature = parseAlgorithmIdentifier(pieces[2]);
    tbs.issuer = pieces[3];
    tbs.validity = pieces[4];
    tbs.subject = pieces[5];
    tbs.subjectPublicKeyInfo = parseSubjectPublicKeyInfo(pieces[6]);

    if (pieces.length > 7) {
        let extensions = parseExtensions(pieces[7]);
        if (extensions != null && extensions.length > 0) {
            tbs.extensions = extensions;
        }
    }

    return tbs;  // Ignore optional fields for now
}

function parseSubjectPublicKeyInfo(asn1) {
    if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
        throw new Error("Bad SPKI. Not a SEQUENCE.");
    }
    var spki = {asn1: asn1};
    var pieces = berListToJavaScript(asn1.contents);
    if (pieces.length !== 2) {
        throw new Error("Bad SubjectPublicKeyInfo. Wrong number of child objects.");
    }
    spki.algorithm = parseAlgorithmIdentifier(pieces[0]);
    spki.bits = berBitStringValue(pieces[1].contents);
    return spki;
}

function parseExtensions(asn1) {
    let result = null;
    // only a subset of known extensions are implemented
    if (asn1.cls !== 2 || asn1.tag !== 3 || !asn1.structured) {
        throw new Error("Bad Extensions - not a BIT STRING.");
    }

    if (asn1.contents != null && asn1.contents.length > 0) {
        result = parseExtensionsSequence(asn1.contents);
    }

    return result;
}

function parseExtensionsSequence(asn1) {
    let result = [];
    let extSequence = berToJavaScript(asn1);
    if (extSequence.cls !== 0 || extSequence.tag !== 16 || !extSequence.structured) {
        throw new Error("Bad Extensions Sequence - not a SEQUENCE.");
    }

    let extArray = berListToJavaScript(extSequence.contents);
    if (extArray != null && extArray.length > 0) {
        extArray.forEach(ext => {
            let parsedExtension = parseExtension(ext);
            if (parsedExtension != null) {
                result.push(parsedExtension);
            }
        });
    }
    return result;
}

function parseExtension(asn1) {
    let result = null;
    let critical = null;
    if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
        throw new Error("Bad Extension - not a SEQUENCE.");
    }

    let extSequenceElements = berListToJavaScript(asn1.contents);
    if (extSequenceElements == null || (extSequenceElements.length != 2 && extSequenceElements.length != 3)) {
        throw new Error("Bad Extension - not a SEQUENCE of two or three elements.");
    }


    let extnID = berObjectIdentifierValue(extSequenceElements[0].contents);
    let nextIndex = 1;
    if (extSequenceElements.length > 2) {
        critical = parseBoolean(extSequenceElements[nextIndex]);
        if (critical == null) {
            throw new Error("Bad Extension - critical value not a boolean.");
        }
        nextIndex++;
    }
    let extensionOctetString = parseOctetString(extSequenceElements[nextIndex]);

    // what we do next depends entirely on the extension ID
    // this can develop over time, but for now we are only interested in 
    // coding up a solution to a subset of extensions
    let extensionProcessor = EXTENSION_ID_PROCESSORS[extnID];
    if (extensionProcessor != null) {
        let parsedExtensionContent = extensionProcessor(berToJavaScript(extensionOctetString));

        if (parsedExtensionContent != null) {
            result = {
                id: extnID,
                value: parsedExtensionContent
            };
            if (critical != null) {
                result["critical"] = critical;
            }
        }
    } else {
        //console.log("No extension processor defined for extension ID: " + extnID)
    }

    return result;
}

function parseBoolean(asn1) {
    if (asn1.cls !== 0 || asn1.tag !== 1) {
        throw new Error("Bad Boolean - not a BOOLEAN.");
    }
    return asn1.contents[0] === 0xFF;
}

function parseOID(asn1) {
    let result = null;
    if (asn1.cls !== 0 || asn1.tag !== 6) {
        throw new Error("Bad Extensions ID - not an OBJECT IDENTIFIER.");
    }

    if (asn1.contents.length > 0) {
        let resultStr = "";
        let i = 0;
        if (asn1.contents.length >= 1) {
            let firstByteVal = asn1.contents[i];
            resultStr = resultStr + Math.floor(firstByteVal/40) + "." + (firstByteVal % 40);
            i = i + 1;
            while (i < asn1.contents.length) {
                let n = 0;
                let byteVal = 0;
                do {
                    byteVal = asn1.contents[i];
                    n = n * 128 + (0x7F & byteVal)
                    i = i + 1
                } while (byteVal > 127 && i < asn1.contents.length);
                resultStr = resultStr + "." + n
            }
        }
        if (resultStr.length > 0) {
            result = resultStr;
        }
    }

    return result;
}

function parseOctetString(asn1) {
    let result = null;
    if (asn1.cls !== 0 || asn1.tag !== 4) {
        throw new Error("Bad Extensions value - not an OCTECT STRING.");
    }

    result = asn1.contents;

    return result;
}

function parseSubjectAltName(asn1) {
    let result = null;

    /* 
    * there can be several types of subjectAltName extensions.
    * Only the URI type has been implemented at present.
    */
    if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
        throw new Error("Bad subjectAltName - not a SEQUENCE.");
    }

    result = [];

    let subjectAltNames = berListToJavaScript(asn1.contents);
    
    if (subjectAltNames != null && subjectAltNames.length > 0) {
        subjectAltNames.forEach(san => {
            // san.tag is the type of the name, 6 is URI
            if (san.tag === 6) {
                result.push({
                    type: "uri",
                    uri: bytesToString(san.contents)
                });
            } else {
                console.log("Not processing subjectAltName type: " + san.tag);
            }
        });
    }

    return result;
}

function bytesToString(byteArray) {
    return String.fromCharCode.apply(String, byteArray);
}

function removeLeadingZeroBytes(byteArray) {
    let result = byteArray;
    let i = 0;
    while (i < byteArray.length && byteArray[i] === 0) {
        i++;
    }
    if (i > 0) {
        result = byteArray.slice(i);
    }
    return result;
}

function parsePublicKeyED25519(pkSeq) {
    result = null;
    if (pkSeq.length === 2 && pkSeq[1].cls == 0 && pkSeq[1].tag === 3 && !pkSeq[1].structured) {
        result = {
            coseKey: {
                "1": 1, // kty
                "3": -8, // alg
                "-1": 6, // crv
                "-2": removeLeadingZeroBytes(pkSeq[1].contents)
            }
        }
    } else {
        console.log("parsePublicKeyED25519: unexpected pkSeq: " + JSON.stringify(pkSeq));
    }
    return result;
}

function parseECPublicKey(pkSeq) {
    result = null;

    // get the parameters from the algorithm sequence to determine the curve name
    let algIdSeq = berListToJavaScript(pkSeq[0].contents);
    if (algIdSeq.length === 2 && algIdSeq[1].cls === 0 && algIdSeq[1].tag === 6 && !algIdSeq[1].structured) {
        let curveOID = berObjectIdentifierValue(algIdSeq[1].contents);
        let coseParams = OID_TO_COSE_PARAMS[curveOID];
        if (coseParams != null) {
            if (pkSeq.length === 2 && pkSeq[1].cls == 0 && pkSeq[1].tag === 3 && !pkSeq[1].structured) {

                let pkBytesToInspect = removeLeadingZeroBytes(pkSeq[1].contents);
                if (pkBytesToInspect.length >= 1 && pkBytesToInspect[0] === 0x04) {
                    let xBytes = pkBytesToInspect.slice(1, (pkBytesToInspect.length-1) / 2 + 1);
                    let yBytes = pkBytesToInspect.slice((pkBytesToInspect.length-1) / 2 + 1);

                    result = {
                        coseKey: {
                            "1": coseParams.kty,
                            "3": coseParams.alg,
                            "-1": coseParams.crv,
                            "-2": xBytes,
                            "-3": yBytes
                        }
                    };
                } else {
                    console.log("parseECPublicKey: unexpected public key format: " + JSON.stringify(pkBytesToInspect));
                }
            } else {
                console.log("parseECPublicKey: unexpected pkSeq: " + JSON.stringify(pkSeq));
            }
        } else {
            console.log("parseECPublicKey: urecognized curveOID: " + curveOID);
        }
    } else {
        console.log("parseECPublicKey: unexpected algIdSeq: " + JSON.stringify(algIdSeq));
    }

    return result;
}

function parseRSAKey(pkSeq) {
    result = null;

    // get the n and exponent from the subjectPublicKey
    if (pkSeq.length === 2 && pkSeq[1].cls == 0 && pkSeq[1].tag === 3 && !pkSeq[1].structured) {
        let rsaPK = berToJavaScript(removeLeadingZeroBytes(pkSeq[1].contents));
        if (rsaPK.cls === 0 && rsaPK.tag === 16 && rsaPK.structured) {
            let rsaPKSeq = berListToJavaScript(rsaPK.contents);
            if (rsaPKSeq.length === 2 && rsaPKSeq[0].cls == 0 && rsaPKSeq[0].tag === 2 && !rsaPKSeq[0].structured
                && rsaPKSeq[1].cls == 0 && rsaPKSeq[1].tag === 2 && !rsaPKSeq[1].structured) {
                result = {
                    coseKey: {
                        "1": 3, // kty
                        //"3": -257, // alg - there is actually no way to know this with information avaialable in this function
                        "-1": removeLeadingZeroBytes(rsaPKSeq[0].contents), // n
                        "-2": removeLeadingZeroBytes(rsaPKSeq[1].contents), // exponent 65537
                    }
                };
            } else {
                console.log("parseRSAKey: unexpected rsaPKSeq: " + JSON.stringify(rsaPKSeq));    
            }
        } else {
            console.log("parseRSAKey: unexpected rsaPK: " + JSON.stringify(rsaPK));
        }
    } else {
        console.log("parseRSAKey: unexpected pkSeq: " + JSON.stringify(pkSeq));
    }

    return result;
}

function parseMLDSA44(pkSeq) {
    result = null;
    if (pkSeq.length === 2 && pkSeq[1].cls == 0 && pkSeq[1].tag === 3 && !pkSeq[1].structured) {
        result = {
            coseKey: {
                "1": 7, // kty
                "3": -48, // alg
                "-1": removeLeadingZeroBytes(pkSeq[1].contents), // pub
            }
        };
    } else {
        console.log("parseMLDSA44: unexpected pkSeq: " + JSON.stringify(pkSeq));
    }
    return result;
}

function parseMLDSA65(pkSeq) {
    result = null;
    if (pkSeq.length === 2 && pkSeq[1].cls == 0 && pkSeq[1].tag === 3 && !pkSeq[1].structured) {
        result = {
            coseKey: {
                "1": 7, // kty
                "3": -49, // alg
                "-1": removeLeadingZeroBytes(pkSeq[1].contents), // pub
            }
        };
    } else {
        console.log("parseMLDSA65: unexpected pkSeq: " + JSON.stringify(pkSeq));
    }
    return result;
}

function parseMLDSA87(pkSeq) {
    result = null;
    if (pkSeq.length === 2 && pkSeq[1].cls == 0 && pkSeq[1].tag === 3 && !pkSeq[1].structured) {
        result = {
            coseKey: {
                "1": 7, // kty
                "3": -50, // alg
                "-1": removeLeadingZeroBytes(pkSeq[1].contents), // pub
            }
        };
    } else {
        console.log("parseMLDSA87: unexpected pkSeq: " + JSON.stringify(pkSeq));
    }
    return result;
}

function parsePublicKeyBytes(byteArray) {
    let result = {};
    let pk = berToJavaScript(byteArray);
    if (pk.cls == 0 && pk.tag === 16 && pk.structured) {
        let pkSeq = berListToJavaScript(pk.contents);
        if (pkSeq.length === 2 && pkSeq[0].cls == 0 && pkSeq[0].tag === 16 && pkSeq[0].structured) {
            // parse algorithm identifier sequence
            let algIdSeq = berListToJavaScript(pkSeq[0].contents);
            if (algIdSeq.length >= 1 && algIdSeq[0].cls === 0 && algIdSeq[0].tag === 6 && !algIdSeq[0].structured) {
                // parse algorithm identifier
                let algorithmIdOID = berObjectIdentifierValue(algIdSeq[0].contents);
                result.algorithm = algorithmIdOID;

                let algProcessor = SPK_ALG_PROCESSORS[algorithmIdOID];
                if (algProcessor != null) {
                    let spk = algProcessor(pkSeq);
                    if (spk != null) {
                        result.subjectPublicKey = algProcessor(pkSeq);
                    }
                } else {
                    console.log("parsePublicKeyBytes: No subject public key algorithm processor written for algorithm: " + algorithmIdOID);
                }
            } else {
                console.log("parsePublicKeyBytes: Invalid algIdSeq for public key bytes: " + JSON.stringify(byteArray));
            }
        } else {
            console.log("parsePublicKeyBytes: Invalid pkSeq for public key bytes: " + JSON.stringify(byteArray));
        }
    } else {
        console.log("parsePublicKeyBytes: Invalid public key bytes: " + JSON.stringify(byteArray));
    }
    return result;
}

/*
 * ===========================================================================
 * Merkle Tree Certificate (MTC) primitives - WebAuthn Level 4 fmt "mtc"
 * (see MTC_IMPLEMENTATION_PLAN.md, sections 3.1 and 3.2)
 * ===========================================================================
 */

// 9999-12-31T23:59:59Z - the "never expires" notAfter sentinel
const MTC_NOT_AFTER_NEVER = 253402300799n;

// ASCII "FIDO-MTC-SUBTREE-CHECKPOINT-V1" followed by two 0x00 bytes (32 bytes)
const MTC_CHECKPOINT_DOMAIN_SEPARATOR = Buffer.concat([
    Buffer.from("FIDO-MTC-SUBTREE-CHECKPOINT-V1", "ascii"),
    Buffer.alloc(2)
]);

function sha256(buf) {
    return nodeCrypto.createHash('sha256').update(buf).digest();
}

/**
 * Converts a Buffer, Uint8Array, ArrayBuffer, or array of byte values to a Buffer.
 * Throws a TypeError for anything else.
 */
function toBuffer(value, name) {
    if (Buffer.isBuffer(value)) {
        return value;
    } else if (value instanceof Uint8Array) {
        return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    } else if (value instanceof ArrayBuffer) {
        return Buffer.from(value);
    } else if (Array.isArray(value) && value.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) {
        return Buffer.from(value);
    }
    throw new TypeError(name + " must be a Buffer, Uint8Array, ArrayBuffer or array of bytes");
}

/**
 * Converts a non-negative integer (number or bigint) to a big-endian Buffer of exactly size bytes.
 */
function uintToBE(value, size, name) {
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value)) {
            throw new RangeError(name + " must be a safe integer (use a bigint for larger values)");
        }
        value = BigInt(value);
    } else if (typeof value !== "bigint") {
        throw new TypeError(name + " must be a number or bigint");
    }
    if (value < 0n || value >= (1n << BigInt(size * 8))) {
        throw new RangeError(name + " is out of range for uint" + (size * 8));
    }
    const result = Buffer.alloc(size);
    for (let i = size - 1; i >= 0; i--) {
        result[i] = Number(value & 0xffn);
        value >>= 8n;
    }
    return result;
}

function checkedCaId(caId) {
    const caIdBuf = toBuffer(caId, "caId");
    if (caIdBuf.length > 0xffff) {
        throw new RangeError("caId is too long");
    }
    return caIdBuf;
}

/**
 * Builds the FidoMtcSubtreeCheckpoint binary preimage (80 + len(caId) bytes) which is signed by the vendor root CA:
 *   "FIDO-MTC-SUBTREE-CHECKPOINT-V1\0\0" (32) || uint16(len(caId)) || caId || uint16(logNumber)
 *   || uint48(start) || uint48(end) || rootHash (32)
 *
 * @returns {Buffer}
 */
function buildFidoMtcSubtreeCheckpoint({ caId, logNumber, start, end, rootHash }) {
    const caIdBuf = checkedCaId(caId);
    const rootHashBuf = toBuffer(rootHash, "rootHash");
    if (rootHashBuf.length !== 32) {
        throw new RangeError("rootHash must be 32 bytes");
    }
    const startBuf = uintToBE(start, 6, "start");
    const endBuf = uintToBE(end, 6, "end");
    if (BigInt("0x" + endBuf.toString("hex")) <= BigInt("0x" + startBuf.toString("hex"))) {
        throw new RangeError("end must be greater than start");
    }
    return Buffer.concat([
        MTC_CHECKPOINT_DOMAIN_SEPARATOR,
        uintToBE(caIdBuf.length, 2, "caId length"),
        caIdBuf,
        uintToBE(logNumber, 2, "logNumber"),
        startBuf,
        endBuf,
        rootHashBuf
    ]);
}

/**
 * Builds the FidoMtcLogEntry binary preimage which is hashed to form a Merkle leaf:
 *   uint16(len(caId)) || caId || uint64(serial) || uint64(notBefore) || uint64(notAfter) || aaguid (16)
 *   || fwBytes (0x00, or 0x01 || uint64(firmwareVersion)) || SHA-256(coseKeyBytes) (32)
 *   || uint16(len(extensions)) || extensions
 *
 * notAfter defaults to 253402300799 (9999-12-31T23:59:59Z), and extensions defaults to empty.
 * coseKeyBytes must be the canonical CBOR encoding of the COSE_Key.
 *
 * Note that the field sizes sum to 76 + len(caId) + len(fwBytes) + len(extensions) bytes.
 *
 * @returns {Buffer}
 */
function buildFidoMtcLogEntry({ caId, serial, notBefore, notAfter, aaguid, firmwareVersion, coseKeyBytes, extensions }) {
    const caIdBuf = checkedCaId(caId);
    const aaguidBuf = toBuffer(aaguid, "aaguid");
    if (aaguidBuf.length !== 16) {
        throw new RangeError("aaguid must be 16 bytes");
    }
    const coseKeyBuf = toBuffer(coseKeyBytes, "coseKeyBytes");
    if (coseKeyBuf.length === 0) {
        throw new RangeError("coseKeyBytes must not be empty");
    }
    const extBuf = (extensions == null) ? Buffer.alloc(0) : toBuffer(extensions, "extensions");
    if (extBuf.length > 0xffff) {
        throw new RangeError("extensions is too long");
    }
    const fwBuf = (firmwareVersion == null)
        ? Buffer.from([0x00])
        : Buffer.concat([Buffer.from([0x01]), uintToBE(firmwareVersion, 8, "firmwareVersion")]);

    return Buffer.concat([
        uintToBE(caIdBuf.length, 2, "caId length"),
        caIdBuf,
        uintToBE(serial, 8, "serial"),
        uintToBE(notBefore, 8, "notBefore"),
        uintToBE(notAfter == null ? MTC_NOT_AFTER_NEVER : notAfter, 8, "notAfter"),
        aaguidBuf,
        fwBuf,
        sha256(coseKeyBuf),
        uintToBE(extBuf.length, 2, "extensions length"),
        extBuf
    ]);
}

/**
 * Computes the RFC 9162 §2.1.1 leaf hash: SHA-256(0x00 || logEntryBytes)
 *
 * @returns {Buffer} 32 byte leaf hash
 */
function computeFidoMtcLeafHash(logEntryBytes) {
    return sha256(Buffer.concat([Buffer.from([0x00]), toBuffer(logEntryBytes, "logEntryBytes")]));
}

/**
 * Computes the RFC 9162 §2.1.1 interior node hash: SHA-256(0x01 || left || right)
 */
function hashRFC9162Node(left, right) {
    return sha256(Buffer.concat([Buffer.from([0x01]), left, right]));
}

/**
 * Builds an RFC 9162 SHA-256 Merkle tree over already-computed leaf hashes (see computeFidoMtcLeafHash),
 * using the merkletreejs library. Interior nodes are SHA-256(0x01 || left || right). Trees whose size is not a
 * power of two have the RFC 9162 shape (the left subtree is the largest power of two smaller than n).
 *
 * @param leafHashes - array of 32 byte leaf hashes (at least one)
 * @returns {{ rootHash: Buffer, leafCount: number, getProof: function(number): Buffer[] }}
 *   getProof(leafIndex) returns the RFC 9162 inclusion proof (array of 32 byte sibling hashes, leaf to root)
 *   for the leaf at the (zero-based, subtree relative) leafIndex.
 */
function buildRFC9162MerkleTree(leafHashes) {
    if (!Array.isArray(leafHashes) || leafHashes.length === 0) {
        throw new TypeError("leafHashes must be a non-empty array");
    }
    const leaves = leafHashes.map((h, i) => {
        const buf = toBuffer(h, "leafHashes[" + i + "]");
        if (buf.length !== 32) {
            throw new RangeError("leafHashes[" + i + "] must be 32 bytes");
        }
        return buf;
    });

    const tree = new MerkleTree(
        leaves,
        sha256,
        // leaves are already hashed; interior nodes get the 0x01 domain separation prefix
        { concatenator: (nodes) => Buffer.concat([Buffer.from([0x01]), ...nodes]) }
    );

    return {
        rootHash: tree.getRoot(),
        leafCount: leaves.length,
        getProof: function(leafIndex) {
            if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= leaves.length) {
                throw new RangeError("leafIndex is out of range");
            }
            return tree.getProof(leaves[leafIndex], leafIndex).map((p) => p.data);
        }
    };
}

/**
 * Verifies an RFC 9162 §2.1.3.2 Merkle inclusion proof for a leaf within the subtree [start, end).
 * The proof is relative to the subtree, so the relative index is leafIndex - start and the tree size is end - start.
 * This is the RFC algorithm (rather than a simple parity climb) so that it is also correct for trees whose size
 * is not a power of two.
 *
 * @param leafHash - 32 byte leaf hash
 * @param proof - array of 32 byte sibling hashes, ordered from the leaf upwards
 * @param leafIndex - absolute leaf index (serial & 0xFFFFFFFFFFFF)
 * @param start - inclusive start index of the subtree (defaults to 0)
 * @param end - exclusive end index of the subtree
 * @param rootHash - expected 32 byte subtree root hash
 * @returns {boolean} true only if the proof is well formed and climbs to rootHash
 */
function verifyRFC9162MerkleProof({ leafHash, proof, leafIndex, start, end, rootHash }) {
    try {
        const leafHashBuf = toBuffer(leafHash, "leafHash");
        const rootHashBuf = toBuffer(rootHash, "rootHash");
        if (leafHashBuf.length !== 32 || rootHashBuf.length !== 32 || !Array.isArray(proof)) {
            return false;
        }
        const siblings = proof.map((p) => toBuffer(p, "proof element"));
        if (siblings.some((p) => p.length !== 32)) {
            return false;
        }

        const idx = BigInt(leafIndex);
        const startIdx = BigInt(start == null ? 0 : start);
        const endIdx = BigInt(end);
        if (startIdx < 0n || idx < startIdx || idx >= endIdx) {
            return false;
        }

        let fn = idx - startIdx;
        let sn = endIdx - startIdx - 1n;
        let r = leafHashBuf;
        for (const p of siblings) {
            if (sn === 0n) {
                return false;
            }
            if ((fn & 1n) === 1n || fn === sn) {
                r = hashRFC9162Node(p, r);
                if ((fn & 1n) === 0n) {
                    while ((fn & 1n) === 0n && fn !== 0n) {
                        fn >>= 1n;
                        sn >>= 1n;
                    }
                }
            } else {
                r = hashRFC9162Node(r, p);
            }
            fn >>= 1n;
            sn >>= 1n;
        }
        return sn === 0n && nodeCrypto.timingSafeEqual(r, rootHashBuf);
    } catch (e) {
        return false;
    }
}

module.exports = {
    berToJavaScript: berToJavaScript,
    berListToJavaScript: berListToJavaScript,
    parseCertificate: parseCertificate,
    parsePublicKeyBytes: parsePublicKeyBytes,
    buildFidoMtcSubtreeCheckpoint: buildFidoMtcSubtreeCheckpoint,
    buildFidoMtcLogEntry: buildFidoMtcLogEntry,
    computeFidoMtcLeafHash: computeFidoMtcLeafHash,
    buildRFC9162MerkleTree: buildRFC9162MerkleTree,
    verifyRFC9162MerkleProof: verifyRFC9162MerkleProof
};
