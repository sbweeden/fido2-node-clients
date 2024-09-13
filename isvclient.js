
// get configuration in place
require('dotenv').config();

const logger = require('./logging.js');
const tm = require('./oauthtokenmanager.js');
const fido2error = require('./fido2error.js');
const commonServices = require('./commonservices.js');
const fidoutils = require('./fidoutils.js');

// hack to use a supplied access token
if (process.env.OIDC_USER_ACCESS_TOKEN != null) {
    // just set it as expiring in 2 hours
    tm.setTokenResponse({
        expires_at_ms: (new Date().getTime() + (120*60*1000)),
        access_token: process.env.OIDC_USER_ACCESS_TOKEN
    });
}

//
// Caching logic to reduce number of calls to ISV
//

// cache to map rpId to rpUuid
var rpIdMap = {};
// cache to map rpUuid to rpId
var rpUuidMap = {};
// cache to map user lookup filters to ISV user
var userFilterMap = {};

function lookupUserWithFilter(userFilter) {

    let usingMeResource = false;
    let url = process.env.ISV_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({filter: userFilter});

	return tm.getAccessToken()
	.then((access_token) => {
        if (process.env.OIDC_USER_ACCESS_TOKEN != null) {
            url = process.env.ISV_TENANT_ENDPOINT + "/v2.0/Me";
            usingMeResource = true;
        }

        //logger.logWithTS("lookupUserWithFilter usingMeResource: " + usingMeResource + " url: " + url);
		return commonServices.timedFetch(
			url,
			{
				bucket: process.env.ISV_TENANT_ENDPOINT + "/v2.0/Users?filter=<userFilter>",
				method: "GET",
				headers: {
					"Accept": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true
			}
		);
	}).then((scimResponse) => {
        let scimResource = null;
        if (usingMeResource) {
            // the /Me resource returns the scim response as the entire result
            scimResource = scimResponse;
        } else {
            // should be exactly one result - if so, add to cache
            if (scimResponse && scimResponse.totalResults == 1) {
                scimResource = scimResponse.Resources[0];
            }
        }
        if (scimResource != null) {
            userFilterMap[userFilter] = scimResource;
        }

        return scimResource;
	}).catch((e) => {
		logger.logWithTS("isvclient.lookupUserWithFilter e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
	});
}

function usernameToId(username) {
	let result = null;

	let userFilter = 'username eq "' + username + '"';
    if (userFilterMap[userFilter] != null) {
		return userFilterMap[userFilter].id;
	} else {
		return lookupUserWithFilter(userFilter)
		.then((scimResult) => {
			// userFilterMap should be updated
			if (userFilterMap[userFilter] != null) {
				return userFilterMap[userFilter].id;
			} else {
				// fatal
				throw new fido2error.fido2Error("userId could not be resolved");
			}
		}).catch((e) => {
            let fido2Error = commonServices.normaliseError("userIdToUsername", e, "Error resolving username: " + username);
			logger.logWithTS("usernameToId: Unable to resolve id for username: " + username + " error: " + JSON.stringify(fido2Error));
		});
	} 
}

function updateRPMaps() {
	// reads all relying parties from discovery service updates local caches
	return tm.getAccessToken()
	.then((access_token) => {
		return commonServices.timedFetch(
			process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/discover/fido2",
			{
				method: "GET",
				headers: {
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true
			}
		);
	}).then((discoverResponse) => {
		rpUuidMap = {};
		rpIdMap = {};
		// there is a response message schema change happening - tolerate the old and new...
		var rpWrapper = (discoverResponse.fido2 != null ? discoverResponse.fido2 : discoverResponse);
		rpWrapper.relyingParties.forEach((rp) => {
			rpUuidMap[rp.id] = rp.rpId;
			rpIdMap[rp.rpId] = rp.id;
		});
	}).catch((e) => {
		logger.logWithTS("isvclient.updateRPMaps e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
	});
}


function rpIdTorpUuid(rpId) {
	if (rpIdMap[rpId] != null) {
		return rpIdMap[rpId];
	} else {
		return updateRPMaps()
		.then(() => {
			if (rpIdMap[rpId] != null) {
				return rpIdMap[rpId];
			} else {
				// hmm - no rpId, fatal at this point.
				throw new fido2error.fido2Error("rpId: " + rpId + " could not be resolved");
			}			
		});
	}
}

//
// this debugging function just reformats what ISV accepts into the standardised toJSON
// format that many other tools use for decoding
// see: https://w3c.github.io/webauthn/#dom-authenticatorattestationresponsejson-publickeyalgorithm
//
function isvSPKCToStandardPublicKeyCredentialJSON (spkc) {
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

    // Change getTransports to transports and move into response
    result.response.transports = result.getTransports;
    delete result.getTransports;

    // Add response.authenticatorData, response.publicKeyAlgorithm and response.publicKey
    let attestationObjectBytes = jsrsasign.b64toBA(jsrsasign.b64utob64(result.response.attestationObject));
    let decodedAttestationObject = cbor.decode((new Uint8Array(attestationObjectBytes)).buffer);
    let unpackedAuthData = fidoutils.unpackAuthData(fidoutils.bytesFromArray(decodedAttestationObject.authData, 0, -1));

    result.response.authenticatorData = jsrsasign.hextob64u(jsrsasign.BAtohex(unpackedAuthData.rawBytes));

    result.response.publicKeyAlgorithm = unpackedAuthData.attestedCredData.credentialPublicKey["3"];
    if (result.response.publicKeyAlgorithm == -7) {
        // this is a dirty hack since we know we really only support EC256 keys in this client, 
        // and this is what the ASN.1 of SubjectPublicKeyInfo of an EC key looks like
        // Its this magic string followed by the bytes of the x and y coordinates
        result.response.publicKey = jsrsasign.hextob64u(
            "3059301306072A8648CE3D020106082A8648CE3D03010703420004"+
            jsrsasign.BAtohex(unpackedAuthData.attestedCredData.credentialPublicKey["-2"]) +
            jsrsasign.BAtohex(unpackedAuthData.attestedCredData.credentialPublicKey["-3"])
        );
    } else {
        console.log("isvSPKCToStandardPublicKeyCredentialJSON: Unexpected algorithm for public key: " +result.response.publicKeyAlgorithm);
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
        "userId": "TBD",
        "authenticatorSelection": authenticatorSelection
    };

    let result = {
        credentialCreationResult: null,
        attestationResultResponse: null
    }

	return tm.getAccessToken()
	.then((at) => {
		access_token = at;
    }).then(() => {
        return usernameToId(username);
    }).then((iui) => {
        bodyToSend.userId = iui;
		return rpIdTorpUuid(process.env.RPID);
	}).then((rpuniqueIdentifier) => {
        rpUuid = rpuniqueIdentifier;
		logger.logWithTS("performAttestation sending attestation options to ISV: " + JSON.stringify(bodyToSend));
		return commonServices.timedFetch(
			process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/attestation/options",
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
        //logger.logWithTS("performAttestation: attestationOptionsResponse: " + JSON.stringify(attestationOptionsResponse));        
        let cco = fidoutils.attestationOptionsResponeToCredentialCreationOptions(attestationOptionsResponse);
        //logger.logWithTS("performAttestation: CredentialCreationOptions: " + JSON.stringify(cco));
        let credentialCreationResult = fidoutils.processCredentialCreationOptions(cco, attestationFormat);

        // add stuff required (and optional) for ISV
        credentialCreationResult.spkc["nickname"] = "NodeClient - " + attestationOptionsResponse.challenge;
        credentialCreationResult.spkc["enabled"] = true;
        credentialCreationResult.spkc["getTransports"] = ["node"];
        //logger.logWithTS("Standard JSON format SPKC: " + JSON.stringify(isvSPKCToStandardPublicKeyCredentialJSON(credentialCreationResult.spkc)));
		logger.logWithTS("performAttestation sending attestation result to ISV: " + JSON.stringify(credentialCreationResult.spkc));

        result.credentialCreationResult = credentialCreationResult;

		return commonServices.timedFetch(
			process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/attestation/result",
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
 * The userId parameter is optional, but if supplied it must be the unique identifier of an ISV user and 
 * will be used in the /attestation/options call, which will retrieve a set of allowCredentials for the user. 
 * If performing a completely usernameless flow, pass it as null.
 * 
 * The authenticatorRecords is required, as this contains a list of private keys that may be used for
 * login. The authenticatorRecords is a map of credentialID to "record". This parameter should come from the results 
 * of a previous performAttestation call.
 * 
 * Take a look at isv_example1.js for a demonstration of how to use this in combination with performAttestation.
 */
function performAssertion(userId, authenticatorRecords) {
    let access_token = null;
    let rpUuid = null;
    let bodyToSend = {
        "userVerification": "required"
    };

    if (userId != null) {
        bodyToSend["userId"] = userId;
    }

    return tm.getAccessToken()
    .then((at) => {
        access_token = at;
    }).then(() => {
        return rpIdTorpUuid(process.env.RPID);
    }).then((rpuniqueIdentifier) => {
        rpUuid = rpuniqueIdentifier;
        logger.logWithTS("performAssertion sending assertion options to ISV: " + JSON.stringify(bodyToSend));
        return commonServices.timedFetch(
            process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/options",
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
        if (userId == null) {
            delete assertionOptionsResponse.allowCredentials;
        }
        logger.logWithTS("performAssertion: assertionOptionsResponse: " + JSON.stringify(assertionOptionsResponse));
        let cro = fidoutils.assertionOptionsResponeToCredentialRequestOptions(assertionOptionsResponse);
        let spkc = fidoutils.processCredentialRequestOptions(cro, authenticatorRecords);

        logger.logWithTS("performAssertion sending assertion result to ISV: " + JSON.stringify(spkc));
        return commonServices.timedFetch(
            process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/result",
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

