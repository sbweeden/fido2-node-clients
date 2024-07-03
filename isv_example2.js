// isv_example2.js

// performs a usernameless assertion flow using authenticatorRecords captured from a previous registration

const fido2client = require('./isvclient.js');
const logger = require('./logging.js');
const commonServices = require('./commonservices.js');

//
// UPDATE this with a value previously captured from an attestation flow (such as in isv_example1.js)
//
let authenticatorRecords = {"YOUR_CREDENTIAL_ID":{"rpId":"mytenant.verify.ibmcloudsecurity.com","privateKeyHex":"YOUR_PRIVATE_KEY","credentialID":"YOUR_CREDENTIAL_ID","userHandle":"YOUR_USER_HANDLE"}};
authenticatorRecords={"U2FsdGVkX19k9Vgs_TO1MZCFPkPESzNgFwt2Tq9JaI8sujSVftGBpUGPVMnnq9dfAhp3pcq_pkBnoUJlDhCUkkNpRFU1kEB6obE1H7zJFBVqRZAzjy6ZQU-oQcnKzlI2":{"rpId":"myidp.ice.ibmcloud.com","privateKeyHex":"d4e77343558f80e743c7b21fcdfb2daf8303b4abf146acb66506359f19264768","credentialID":"U2FsdGVkX19k9Vgs_TO1MZCFPkPESzNgFwt2Tq9JaI8sujSVftGBpUGPVMnnq9dfAhp3pcq_pkBnoUJlDhCUkkNpRFU1kEB6obE1H7zJFBVqRZAzjy6ZQU-oQcnKzlI2","userHandle":"NTBCQ1JRVk5DMA"}}

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
