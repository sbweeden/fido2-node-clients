// example1.js

// strings together an attestation and assertion flow

const logger = require('./logging.js');
const commonServices = require('./commonservices.js');
const fido2client = require('./webauthnioclient.js');

const printStats = false;

const USERNAME="fred";

//
// MAIN entry point starts here
//
let attestationFormats = [ "packed" ]; // To have this example create one of each, use [ "packed", "packed-self", "tpm", "fido-u2f", "none" ]
let authenticatorRecords = {};

attestationFormats.forEach((attestationFormat) => {
    
    console.log("Performing attestation and assertion for format: " + attestationFormat);

    fido2client.performAttestation(USERNAME, attestationFormat)
    .then((attestationResult) => {

        // store this credential in our authenticatorRecords
        authenticatorRecords[attestationResult.credentialCreationResult.authenticatorRecord.credentialID] = attestationResult.credentialCreationResult.authenticatorRecord;

        // You can set authenticateUsername to null here to perform a "usernameless" flow.
        let authenticateUsername = USERNAME;

        let iterations = 1;
        let allPromises = [];
        for (let i = 0; i < iterations; i++) {
            allPromises.push(fido2client.performAssertion(authenticateUsername, authenticatorRecords));
        }
    
        return Promise.all(allPromises);
    }).then((assertionResultResponses) => {
        logger.logWithTS("assertionResultResponses: " + JSON.stringify(assertionResultResponses));
        logger.logWithTS("==============================================================");
        logger.logWithTS("authenticatorRecords: " + JSON.stringify(authenticatorRecords));
        if (printStats) {
            logger.logWithTS("======================= STATS =======================");
            logger.logWithTS(JSON.stringify(commonServices.getStatsSummary()));
        }
    }).catch((e) => {
        let fido2Error = commonServices.normaliseError("main_flow", e, "Unable to complete operations");
        logger.logWithTS("main_flow got exception: " + JSON.stringify(fido2Error));
    });
});