// isv_fido_for_session_cookie.js

const fido2client = require('./isvclient.js');
const fido2error = require('./fido2error.js');
const logger = require('./logging.js');
const commonServices = require('./commonservices.js');

//
// This example app shows how to use an existing FIDO credential to authenticate a user and create a browser session.
// It leverages the policyauth grant type for an application client. References:
//   https://docs.verify.ibm.com/verify/docs/policy-based-authentication
//   https://docs.verify.ibm.com/verify/docs/first-factor-authentication-fido2-login
//


//
// UPDATE this with a value previously captured from an attestation flow (such as in isv_example1.js)
//
//let authenticatorRecords = {"YOUR_CREDENTIAL_ID":{"rpId":"mytenant.verify.ibmcloudsecurity.com","privateKeyHex":"YOUR_PRIVATE_KEY","credentialID":"YOUR_CREDENTIAL_ID","userHandle":"YOUR_USER_HANDLE"}};


//
// 
// the POLICYAUTH application client is an OIDC application that is configured in ISV with these grant types enabled: 
//   JWT bearer
//   Context-based authorization
// 
// Additionally the client has the session endpoint enabled (Allow and revoke token)
// and uses a custom access policy (of type "Native custom app") that has one first contact rule:
//     Authentication action = Challenge
//     Specific methods: FIDO2 (only in my case)
const TOKEN_ENDPOINT =  process.env.ISV_TENANT_ENDPOINT + "/oauth2/token";
const SESSION_ENDPOINT =  process.env.ISV_TENANT_ENDPOINT + "/v1.0/auth/session";


//
// MAIN entry point starts here
//

fido2client.init()
.then(() => {
    // kick off the policyauth grant type. The access policy associated with this client application should require a FIDO2 challenge
    let formData = {
        grant_type: "policyauth",
        client_id: process.env.POLICYAUTH_CLIENT_ID
    }
    if (process.env.POLICYAUTH_CLIENT_SECRET != null) {
        formData["client_secret"] = process.env.POLICYAUTH_CLIENT_SECRET;
    }
    let myBody = new URLSearchParams(formData);


    return commonServices.timedFetch(
        TOKEN_ENDPOINT,
        {
            method: "POST",
            headers: {
                "Accept": "application/json",
            },
            body: myBody,
			returnAsJSON: true
        }
    );
}).then((tokenResult) => {
    logger.logWithTS("tokenResult: " + JSON.stringify(tokenResult));
    if (tokenResult.scope != null && tokenResult.scope == "mfa_challenge" && tokenResult.allowedFactors != null && tokenResult.allowedFactors.indexOf("fido2") >= 0) {
        // perform the FIDO2 authentication
        return fido2client.performAssertion(null, authenticatorRecords, tokenResult.access_token, true);
    } else {
        // no FIDO2 challenge
        throw new fido2error.fido2Error("policyauth response did not contain fido2 challenge");
    }
}).then((assertionResult) => {
    logger.logWithTS("assertionResultResponse: " + JSON.stringify(assertionResult));
    if (assertionResult.assertion) {
        // perform jwt bearer flow with the assertion from the fido2 authentication to get an access token as the user
        let formData = {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
            client_id: process.env.POLICYAUTH_CLIENT_ID,
            assertion: assertionResult.assertion
        }
        if (process.env.POLICYAUTH_CLIENT_SECRET != null) {
            formData["client_secret"] = process.env.POLICYAUTH_CLIENT_SECRET;
        }
        let myBody = new URLSearchParams(formData);


        return commonServices.timedFetch(
            TOKEN_ENDPOINT,
            {
                method: "POST",
                headers: {
                    "Accept": "application/json",
                },
                body: myBody,
                returnAsJSON: true
            }
        );

    } else {
        throw new fido2error.fido2Error("No JWT assertion in the fido2 authentication response");
    }
}).then((tokenResult) => {
    logger.logWithTS("tokenResult for jwt bearer flow: " + JSON.stringify(tokenResult));
    console.log('Redirect the browser to: ' + SESSION_ENDPOINT + '?access_token=' + tokenResult.access_token + '&redirect_url=%2Fusc');
}).catch((e) => {
    let fido2Error = commonServices.normaliseError("main_flow", e, "Unable to complete operations");
    logger.logWithTS("main_flow got exception: " + JSON.stringify(fido2Error));
});
