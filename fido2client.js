
// get configuration in place
require('dotenv').config();

const identityServices = require('./ciservices.js')
const fidoutils = require('./fidoutils.js');
const tm = require('./oauthtokenmanager.js');
const logger = require('./logging.js');


function performAttestation(username) {
	let access_token = null;
    let rpUuid = null;
	let bodyToSend = {
        "userId": "TBD",
        "authenticatorSelection": {
            "userVerification": "required",
            "requireResidentKey": true
        }
    };

    let result = {
        credentialCreationResult: null,
        attestationResultResponse: null
    }

	return tm.getAccessToken()
	.then((at) => {
		access_token = at;
    }).then(() => {
        return identityServices.usernameToId(username);
    }).then((iui) => {
        bodyToSend.userId = iui;
		return identityServices.rpIdTorpUuid(process.env.RPID);
	}).then((rpuniqueIdentifier) => {
        rpUuid = rpuniqueIdentifier;
		logger.logWithTS("performAttestation sending attestation options to CI: " + JSON.stringify(bodyToSend));
		return identityServices.timedFetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/attestation/options",
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
        let attestationFormat = "packed-self";
        let credentialCreationResult = fidoutils.processCredentialCreationOptions(cco, attestationFormat);

        // add stuff required (and optional) for ISV
        credentialCreationResult.spkc["nickname"] = "NodeClient - " + attestationOptionsResponse.challenge;
        credentialCreationResult.spkc["enabled"] = true;
        credentialCreationResult.spkc["getTransports"] = ["platform"];
		logger.logWithTS("performAttestation sending attestation result to CI: " + JSON.stringify(credentialCreationResult.spkc));

        result.credentialCreationResult = credentialCreationResult;

		return identityServices.timedFetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/attestation/result",
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
        let fido2Error = identityServices.normaliseError("performAttestation", e, "Unable to complete attestation");
		//logger.logWithTS("performAttestation got exception: " + JSON.stringify(fido2Error));
        throw fido2Error;
	});
}

function performAssertion(attestationResult, authenticatorRecords) {
    // example input
    /*
    {
        "id": "1f249191-6478-4213-b0c4-1d44841ed1ec",
        "userId": "32600086BX",
        "type": "fido2",
        "created": "2024-06-28T03:40:57.834Z",
        "updated": "2024-06-28T03:40:57.834Z",
        "enabled": true,
        "validated": true,
        "attributes": {
          "attestationType": "Self",
          "attestationFormat": "packed",
          "nickname": "NodeClient - ugu_WWR7pXfNF45tCEXiLvXxW0TM9Q0wRcP0nMYVi4c",
          "userVerified": true,
          "userPresent": true,
          "credentialId": "4M7RAW3qw821XVxwa2whZyzAieU8IIT3ezha13leCnzV17vvp_RvflxzvlxrjzZx_znnnXrV5ppr3t7h_xtvdrrp1pvxxzvjvjnt7j3b3Vxvl5_vrnvXbxzT1rdtvXTvrV3vhvrTh_jvjXd7rZ3p7ffV9zzl_1rjfzvjfvfx3b1vzTZpp_rzn3V5zZr3t3rV9pvjrfx7Tvs",
          "credentialPublicKey": "v2EzYi03Yi0xAWItMlggEpo2LAUrtBeE8kd2rbOpFbbxxxbZR1wp0FEhMVSeLG1hMQJhMyZiLTNYIPQSFPYy1scNGfkPXQ8sgmcL+ugrFbwhrYa/K/eXiYL9/w==",
          "rpId": "myidp.dev.verify.ibmcloudsecurity.com",
          "counter": 1719546056,
          "aaGuid": "1811EC8B-8A91-4592-99F2-17F35D53242E",
          "transports": [],
          "backupEligibility": false,
          "backupState": false
        },
        "references": {
          "rpUuid": "9c22daca-6186-4954-a8a7-490b90b1a6b9"
        }
    }
    */

    let access_token = null;
    let rpUuid = null;
    let bodyToSend = {
        "userVerification": "required",
        "userId": attestationResult.attestationResultResponse.userId
    };

    return tm.getAccessToken()
    .then((at) => {
        access_token = at;
    }).then(() => {
        return identityServices.rpIdTorpUuid(process.env.RPID);
    }).then((rpuniqueIdentifier) => {
        rpUuid = rpuniqueIdentifier;
        logger.logWithTS("performAssertion sending assertion options to CI: " + JSON.stringify(bodyToSend));
        return identityServices.timedFetch(
            process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/options",
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
        //delete assertionOptionsResponse.allowCredentials;
        logger.logWithTS("performAssertion: assertionOptionsResponse: " + JSON.stringify(assertionOptionsResponse));        
        let cro = fidoutils.assertionOptionsResponeToCredentialRequestOptions(assertionOptionsResponse);
        let spkc = fidoutils.processCredentialRequestOptions(cro, authenticatorRecords);

        logger.logWithTS("performAssertion sending assertion result to CI: " + JSON.stringify(spkc));

        return identityServices.timedFetch(
            process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + "/assertion/result",
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
        let fido2Error = identityServices.normaliseError("performAssertion", e, "Unable to complete assertion");
        throw fido2Error;
    });
}

// MAIN starts here

// hack to use a supplied access token
if (process.env.OIDC_USER_ACCESS_TOKEN != null) {
    tm.setTokenResponse({
        expires_at_ms: (new Date().getTime() + (200*60*1000)),
        access_token: process.env.OIDC_USER_ACCESS_TOKEN
    });
}

let authenticatorRecords = {};

performAttestation(process.env.CI_USERNAME)
.then((attestationResult) => {
    logger.logWithTS("credentialCreated: " + JSON.stringify(attestationResult.credentialCreationResult.authenticatorRecord));
    authenticatorRecords[attestationResult.credentialCreationResult.authenticatorRecord.credentialID] = attestationResult.credentialCreationResult.authenticatorRecord;
    return performAssertion(attestationResult, authenticatorRecords);
}).then((assertionResult) => {
    logger.logWithTS("assertionResultResponse: " + JSON.stringify(assertionResult));
}).catch((e) => {
    let fido2Error = identityServices.normaliseError("main_flow", e, "Unable to complete operations");
    logger.logWithTS("main_flow got exception: " + JSON.stringify(fido2Error));
});
