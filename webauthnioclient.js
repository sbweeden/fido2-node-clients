
// get configuration in place
require('dotenv').config();

const logger = require('./logging.js');
const tm = require('./oauthtokenmanager.js');
const fido2error = require('./fido2error.js');
const commonServices = require('./commonservices.js');
const fidoutils = require('./fidoutils.js');

// note that webauthnio requires this origin, so may as well override anything from .env
let fidoutilsConfig = fidoutils.getFidoUtilsConfig();
fidoutilsConfig.origin = "https://webauthn.io";
fidoutils.setFidoUtilsConfig(fidoutilsConfig);

function performAttestation(username, attestationFormat) {
    let authenticatorSelection = {
        "userVerification": "required",
        "requireResidentKey": true

    };
    let bodyToSend = {
        "username": username,
        "user_verification": "preferred",
        "attestation": "direct",
        "attachment": "all",
        "algorithms": [
            "es256"
        ],
        "discoverable_credential": "preferred",
        "hints": []
    };
    if (attestationFormat == "fido-u2f") {
        bodyToSend.user_verification = "discouraged";
        bodyToSend.discoverable_credential = "discouraged";
    }
    let result = {
        credentialCreationResult: null,
        attestationResultResponse: null
    }

	logger.logWithTS("performAttestation sending attestation options to webauthn.io: " + JSON.stringify(bodyToSend));
    return commonServices.timedFetch(
        "https://webauthn.io/registration/options",
        {
            method: "POST",
            headers: {
                "Content-type": "application/json",
                "Accept": "application/json",
            },
            body: JSON.stringify(bodyToSend),
            returnAsJSON: true
        }
    ).then((attestationOptionsResponse) => {
        //logger.logWithTS("performAttestation: attestationOptionsResponse: " + JSON.stringify(attestationOptionsResponse));        
        let cco = fidoutils.attestationOptionsResponeToCredentialCreationOptions(attestationOptionsResponse);
        //logger.logWithTS("performAttestation: CredentialCreationOptions: " + JSON.stringify(cco));
        let credentialCreationResult = fidoutils.processCredentialCreationOptions(cco, attestationFormat, true, true, true);

        // format payload required by webauthn.io verification endpoint
        let webauthnioAttestationResponsePayload = {
            username: username,
            response: credentialCreationResult.spkc
        };
        webauthnioAttestationResponsePayload.response.response.transports = ["internal"];
        webauthnioAttestationResponsePayload.response.clientExtensionResults = webauthnioAttestationResponsePayload.response.getClientExtensionResults;
        delete webauthnioAttestationResponsePayload.response.getClientExtensionResults;
		logger.logWithTS("performAttestation sending attestation result to webauthn.io: " + JSON.stringify(webauthnioAttestationResponsePayload));

        result.credentialCreationResult = credentialCreationResult;

		return commonServices.timedFetch(
			"https://webauthn.io/registration/verification",
			{
				method: "POST",
				headers: {
					"Content-type": "application/json",
					"Accept": "application/json"
				},
				body: JSON.stringify(webauthnioAttestationResponsePayload),
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
 * The username parameter is optional. If a value is prvovided, it should be the username associated with registered credentials in authenticatorRecords.
 * If performing a username-less login flow, pass null or the empty string
 * 
 * The authenticatorRecords is required, as this contains a list of private keys that may be used for
 * login. The authenticatorRecords is a map of credentialID to "record". This parameter should come from the results 
 * of a previous performAttestation call.
 * 
 * Take a look at webauthnio_example1.js for a demonstration of how to use this in combination with performAttestation.
 */
function performAssertion(username, authenticatorRecords) {
    let access_token = null;
    let rpUuid = null;
    let bodyToSend = {
        "username": ((username != null && username.length > 0) ? username : ""),
        "user_verification": "preferred"
    };

    console.log("webauthnioclient performAssertion options request body: " + JSON.stringify(bodyToSend));

    // webauthn.io has some session requirement on its website, so the first fetch here is a no-op just to get a valid session cookie
    let sessionCookieValue = null;
    return commonServices.timedFetch(
        "https://webauthn.io/",
        {
            method: "GET"
        }
    ).then((rsp) => {
        // eg ["sessionid=wgy058l09gzo4i1mil2q0kax9tl73qnu; HttpOnly; Path=/; SameSite=Lax"]
        rsp.headers.getSetCookie().forEach((c) => {
            m = c.match(/^sessionid=([^;]+);.*$/);
            if (m != null && m.length == 2) {
                sessionCookieValue = m[1];
                //console.log("Using session cookie value: " + sessionCookieValue);
            }
        });
    }).then(() => {
        return commonServices.timedFetch(
            "https://webauthn.io/authentication/options",
            {
                method: "POST",
                headers: {
                "Content-type": "application/json",
                "Accept": "application/json",
                "Cookie": "sessionid="+sessionCookieValue,
                },
                body: JSON.stringify(bodyToSend),
                returnAsJSON: true
            });
    }).then((assertionOptionsResponse) => {
        // if performing the usernameless flow, make sure there are no allowCredentials in the list
        if (username == null) {
            delete assertionOptionsResponse.allowCredentials;
        }
        logger.logWithTS("performAssertion: assertionOptionsResponse: " + JSON.stringify(assertionOptionsResponse));
        let cro = fidoutils.assertionOptionsResponeToCredentialRequestOptions(assertionOptionsResponse);
        let spkc = fidoutils.processCredentialRequestOptions(cro, authenticatorRecords);

        // format payload required by webauthn.io verification endpoint
        let webauthnioAssertionResponsePayload = {
            username: bodyToSend.username,
            response: spkc
        };
        // change the name of this one
        webauthnioAssertionResponsePayload.response.clientExtensionResults = webauthnioAssertionResponsePayload.response.getClientExtensionResults;
        delete webauthnioAssertionResponsePayload.response.getClientExtensionResults;


        logger.logWithTS("performAssertion sending assertion result to webauthn.io: " + JSON.stringify(webauthnioAssertionResponsePayload));
        return commonServices.timedFetch(
            "https://webauthn.io/authentication/verification",
            {
                method: "POST",
                headers: {
                    "Content-type": "application/json",
                    "Accept": "application/json",
                    "Cookie": "sessionid="+sessionCookieValue,

                },
                body: JSON.stringify(webauthnioAssertionResponsePayload),
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

