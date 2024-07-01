/**
* Simply wrapper for an error message.
* Will set status "failed" and an errorMessage.
*
*/
function fido2Error(msg) {
	this.status = "failed";
   	this.errorMessage = "TS: " + (new Date()).toISOString() + " errorMessage: " + msg;
}

module.exports = { 
	fido2Error: fido2Error
};
