// webauthnio_example2.js

// performs a usernameless assertion flow using authenticatorRecords captured from a previous registration

const fido2client = require('./webauthnioclient.js');
const logger = require('./logging.js');
const commonServices = require('./commonservices.js');

//
// UPDATE this with a value previously captured from an attestation flow (such as in webauthnio_example1.js)
//
let authenticatorRecords = {"YOUR_CREDENTIAL_ID":{"rpId":"webauthn.io","privateKeyHex":"YOUR_PRIVATE_KEY","credentialID":"YOUR_CREDENTIAL_ID","userHandle":"YOUR_USER_HANDLE"}};

//
// MAIN entry point starts here
//

fido2client.performAssertion(null, authenticatorRecords)
.then((assertionResult) => {
    logger.logWithTS("assertionResultResponse: " + JSON.stringify(assertionResult));
}).catch((e) => {
    let fido2Error = commonServices.normaliseError("main_flow", e, "Unable to complete operations");
    logger.logWithTS("main_flow got exception: " + JSON.stringify(fido2Error));
});
