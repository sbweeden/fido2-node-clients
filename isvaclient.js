
// get configuration in place
require('dotenv').config();

const fidoutils = require('./fidoutils.js');
const tm = require('./oauthtokenmanager.js');
const logger = require('./logging.js');
const commonServices = require('./commonservices.js');

const JUNCTION="/mgaauth";
const FIOD2_RP_UUID = "d03ef3f4-0633-41ff-b8b2-c84f82e5a780";


// hack to use a supplied access token
if (process.env.ISVA_USER_ACCESS_TOKEN != null) {
    // just set it as expiring in 2 hours
    tm.setTokenResponse({
        expires_at_ms: (new Date().getTime() + (120*60*1000)),
        access_token: process.env.ISVA_USER_ACCESS_TOKEN
    });
}

//
// this debugging function just reformats what ISVA accepts into the standardised toJSON
// format that many other tools use for decoding
//
function isvaSPKCToStandardPublicKeyCredentialJSON (spkc) {
    // these are only required for this debugging method
    const cbor = require('cbor'); // https://www.npmjs.com/package/cbor
    const jsrsasign = require('jsrsasign'); // https://www.npmjs.com/package/jsrsasign

    //
    // copy
    //
    let result = JSON.parse(JSON.stringify(spkc));

    //
    // modify
    //

    // Delete rawId
    delete result.rawId;

    // Delete nickname
    delete result.nickname;

    // Delete enabled
    delete result.enabled;

    // Delete type
    delete result.type;

    // Change getClientExtensionResults to clientExtensionResults
    result.clientExtensionResults = result.getClientExtensionResults;
    delete result.getClientExtensionResults;

    // Change getTransports to transports
    result.transports = result.getTransports;
    delete result.getTransports;

    // Convert attestationObject from b64url to b64
    result.response.attestationObject = jsrsasign.b64utob64(result.response.attestationObject);

    // Add response.publicKeyAlgorithm and response.publicKey
    let attestationObjectBytes = jsrsasign.b64toBA(jsrsasign.b64utob64(result.response.attestationObject));
    let decodedAttestationObject = cbor.decode((new Uint8Array(attestationObjectBytes)).buffer);
    let unpackedAuthData = fidoutils.unpackAuthData(fidoutils.bytesFromArray(decodedAttestationObject.authData, 0, -1));

    result.response.publicKeyAlgorithm = unpackedAuthData.attestedCredData.credentialPublicKey["3"];
    if (result.response.publicKeyAlgorithm == -7) {
        // this is a dirty hack since we know we really only support EC256 keys in this client, 
        // and this is what the ASN.1 of SubjectPublicKeyInfo of an EC key looks like
        // Its this magic string followed by the bytes of the x and y coordinates
        result.response.publicKey = jsrsasign.hextob64(
            "3059301306072A8648CE3D020106082A8648CE3D03010703420004"+
            jsrsasign.BAtohex(unpackedAuthData.attestedCredData.credentialPublicKey["-2"]) +
            jsrsasign.BAtohex(unpackedAuthData.attestedCredData.credentialPublicKey["-3"])
        );
    } else {
        console.log("isvaSPKCToStandardPublicKeyCredentialJSON: Unexpected algorithm for public key: " +result.response.publicKeyAlgorithm);
    }

    return result;
}

function performAttestation(username, attestationFormat) {
	let access_token = null;
    let rpUuid = null;
    let authenticatorSelection = {
        "userVerification": "required",
        "requireResidentKey": true

    };
    if (attestationFormat == "fido-u2f") {
        authenticatorSelection = {
            "userVerification": "discouraged",
            "requireResidentKey": false
    
        };
    }
	let bodyToSend = {
        "username": null,
        "authenticatorSelection": authenticatorSelection
    };
    bodyToSend["username"] = process.env.ISVA_USERNAME;


    let result = {
        credentialCreationResult: null,
        attestationResultResponse: null
    }

	return tm.getAccessToken()
	.then((at) => {
		access_token = at;
    }).then(() => {
		logger.logWithTS("performAttestation sending attestation options to ISVA: " + JSON.stringify(bodyToSend));
		return commonServices.timedFetch(
			process.env.ISVA_ENDPOINT + JUNCTION + "/sps/fido2/"+FIOD2_RP_UUID+"/attestation/options",
			{
				method: "POST",
				headers: {
					"Content-type": "application/json",
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				body: JSON.stringify(bodyToSend),
				returnAsJSON: true
			}
		);
	}).then((attestationOptionsResponse) => {
        logger.logWithTS("performAttestation: attestationOptionsResponse: " + JSON.stringify(attestationOptionsResponse));        
        let cco = fidoutils.attestationOptionsResponeToCredentialCreationOptions(attestationOptionsResponse);
        //logger.logWithTS("performAttestation: CredentialCreationOptions: " + JSON.stringify(cco));
        let credentialCreationResult = fidoutils.processCredentialCreationOptions(cco, attestationFormat);

        // add stuff required (and optional) for ISVA
        credentialCreationResult.spkc["nickname"] = "NodeClient - " + attestationOptionsResponse.challenge;
        credentialCreationResult.spkc["getTransports"] = ["node"];
        //logger.logWithTS("Standard JSON format SPKC: " + JSON.stringify(isvaSPKCToStandardPublicKeyCredentialJSON(credentialCreationResult.spkc)));
		logger.logWithTS("performAttestation sending attestation result to ISVA: " + JSON.stringify(credentialCreationResult.spkc));

        result.credentialCreationResult = credentialCreationResult;

		return commonServices.timedFetch(
            process.env.ISVA_ENDPOINT + JUNCTION + "/sps/fido2/"+FIOD2_RP_UUID+"/attestation/result",
			{
				method: "POST",
				headers: {
					"Content-type": "application/json",
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				body: JSON.stringify(credentialCreationResult.spkc),
				returnAsJSON: true
			}
		);
	}).then((attestationResultResponse) => {
		logger.logWithTS("performAttestation got attestationResultResponse: " + JSON.stringify(attestationResultResponse));
        result.attestationResultResponse = attestationResultResponse;
        return result;
	}).catch((e) => {
        let fido2Error = commonServices.normaliseError("performAttestation", e, "Unable to complete attestation");
		//logger.logWithTS("performAttestation got exception: " + JSON.stringify(fido2Error));
        throw fido2Error;
	});
}

/**
 * 
 * Perform an assertion flow.
 * The username parameter is optional, but if supplied will be used in the /attestation/options call, which will
 * retrieve a set of allowCredentials for the user. If performing a completely usernameless flow, pass it as empty string.
 * 
 * The authenticatorRecords is required, as this contains a list of private keys that might be used for
 * login. The authenticatorRecords is a map of credentialID to record, with the objects as they come from the results of a 
 * performAttestation call.
 * 
 * Take a look at isva_example1.js for a demonstration of how to use this in combination with performAttestation.
 */
function performAssertion(username, authenticatorRecords) {
    let access_token = null;
    let rpUuid = null;
    let bodyToSend = {
        "userVerification": "required"
    };

    if (username != null) {
        bodyToSend["username"] = username;
    }

    return tm.getAccessToken()
    .then((at) => {
        access_token = at;
    }).then(() => {
        logger.logWithTS("performAssertion sending assertion options to ISVA: " + JSON.stringify(bodyToSend));
        return commonServices.timedFetch(
            process.env.ISVA_ENDPOINT + JUNCTION + "/sps/fido2/"+FIOD2_RP_UUID+"/assertion/options",
            {
                method: "POST",
                headers: {
                "Content-type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer " + access_token
                },
                body: JSON.stringify(bodyToSend),
                returnAsJSON: true
            }
        );
    }).then((assertionOptionsResponse) => {
        // if performing the usernameless flow, make sure there are no allowCredentials in the list
        if (username == null) {
            delete assertionOptionsResponse.allowCredentials;
        }
        logger.logWithTS("performAssertion: assertionOptionsResponse: " + JSON.stringify(assertionOptionsResponse));        
        let cro = fidoutils.assertionOptionsResponeToCredentialRequestOptions(assertionOptionsResponse);
        let spkc = fidoutils.processCredentialRequestOptions(cro, authenticatorRecords);
        logger.logWithTS("performAssertion sending assertion result to ISVA: " + JSON.stringify(spkc));        

        return commonServices.timedFetch(
            process.env.ISVA_ENDPOINT + JUNCTION + "/sps/fido2/"+FIOD2_RP_UUID+"/assertion/result",
            {
                method: "POST",
                headers: {
                    "Content-type": "application/json",
                    "Accept": "application/json",
                    "Authorization": "Bearer " + access_token
                },
                body: JSON.stringify(spkc),
                returnAsJSON: true
            }
        );
    }).then((assertionResultResponse) => {
        logger.logWithTS("performAssertion got assertionResultResponse: " + JSON.stringify(assertionResultResponse));
        return assertionResultResponse;
    }).catch((e) => {
        let fido2Error = commonServices.normaliseError("performAssertion", e, "Unable to complete assertion");
        throw fido2Error;
    });
}


module.exports = { 
	performAttestation: performAttestation,
	performAssertion: performAssertion
};

