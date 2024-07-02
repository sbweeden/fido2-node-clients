// commonservices.js

const fido2error = require('./fido2error.js');

// used for stats
var statsMap = {};

// calls fetch, but times the event so that stats can be gathered later
function timedFetch(url, fetchOptions) {
	let start = (new Date()).getTime();
	let bucket = fetchOptions.method + "_" + url;
	if (fetchOptions["bucket"] != null) {
		bucket = fetchOptions.method + "_" + fetchOptions.bucket;
		delete fetchOptions.bucket;
	}

	let returnAsJSON = false;
	if (fetchOptions["returnAsJSON"] != null) {
		returnAsJSON = fetchOptions.returnAsJSON;
		delete fetchOptions.returnAsJSON;
	}

	return fetch(
		url,
		fetchOptions
	).then((result) => {
		let now = (new Date()).getTime();
		if (statsMap[bucket] != null) {
			statsMap[bucket].push(now-start);
		} else {
			statsMap[bucket] = [ now-start ];
		}

		if (returnAsJSON) {
			if (!result.ok) {
				logger.logWithTS("timedFetch unexpected result. status: " + result.status);
				return result.text().then((txt) => {
					throw new fido2error.fido2Error("Unexpected HTTP response code: " + result.status + (txt != null ? (" body: " + txt) : ""));
				});
			} else {
				return result.json();
			}
		} else {
			return result;
		}
	});
}

function resetStats(req, rsp) {
	statsMap = {};
	rsp.json(statsMap);
}

function getStats(req, rsp) {
	rsp.json(statsMap);
}

function normaliseError(methodName, e, genericError) {
	// log what we can about this error case
	var fidoError = null;

	// if e is already a fido2Error, return it, otherwise try to perform discovery of
	// the error message, otherwise return a generic error message
	if (e != null && e.status == "failed") {
		// seems to already be a fido2Error
		fidoError = e;
	} else if (e != null && e.error != null && e.error.messageId != null && e.error.messageDescription != null) {
		// this looks like one of the typical CI error messages
		fidoError = new fido2error.fido2Error(e.error.messageId + ": " + e.error.messageDescription);

	} else {
		// fallback to the generic error
		fidoError = new fido2error.fido2Error(genericError);
	}

	return fidoError;
}

module.exports = { 
    timedFetch: timedFetch,
	resetStats: resetStats,
	getStats: getStats,
    normaliseError: normaliseError
};
