// example1.js

// strings together an attestation and assertion flow

const logger = require('./logging.js');
const commonServices = require('./commonservices.js');
const fido2client = require('./isvaclient.js');

//
// MAIN entry point starts here
//
let attestationFormat = "packed"; // one of "packed", "packed-self", "fido-u2f"
let authenticatorRecords = {};

fido2client.performAttestation(process.env.ISVA_USERNAME, attestationFormat)
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
    let fido2Error = commonServices.normaliseError("main_flow", e, "Unable to complete operations");
    logger.logWithTS("main_flow got exception: " + JSON.stringify(fido2Error));
});
