// isv_example1.js

// strings together an attestation and assertion flow

const fido2client = require('./isvclient.js');
const logger = require('./logging.js');
const identityServices = require('./isvservices.js');

//
// MAIN entry point starts here
//
let attestationFormat = "packed-self"; // one of "packed", "packed-self", "fido-u2f"
let authenticatorRecords = {};

fido2client.performAttestation(process.env.ISV_USERNAME, attestationFormat)
.then((attestationResult) => {

    // store this credential in our authenticatorRecords
    authenticatorRecords[attestationResult.credentialCreationResult.authenticatorRecord.credentialID] = attestationResult.credentialCreationResult.authenticatorRecord;
    logger.logWithTS("authenticatorRecords: " + JSON.stringify(authenticatorRecords));

    // now use it in a login flow - you can set userId to null here to perform a "usernameless" flow.
    let userId = attestationResult.attestationResultResponse.userId;
    return fido2client.performAssertion(userId, authenticatorRecords);
}).then((assertionResult) => {
    logger.logWithTS("assertionResultResponse: " + JSON.stringify(assertionResult));
}).catch((e) => {
    let fido2Error = identityServices.normaliseError("main_flow", e, "Unable to complete operations");
    logger.logWithTS("main_flow got exception: " + JSON.stringify(fido2Error));
});
