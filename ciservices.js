//
// ciservices - performs user and FIDO2 operations against IBM Cloud Identity
//
const fs = require('fs');
const path = require('path');
const base64url = require('base64url');
const logger = require('./logging.js');
const tm = require('./oauthtokenmanager.js');
const fido2error = require('./fido2error.js');

//
// Caching logic to reduce number of calls to CI
//

// cache to map rpId to rpUuid
var rpIdMap = {};
// cache to map rpUuid to rpId
var rpUuidMap = {};
// cache to map user lookup filters to CI user
var userFilterMap = {};

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

function deleteRegistration(req, rsp) {
	var access_token = null;
	tm.getAccessToken()
	.then((access_token) => {
		if (req.body.id != null) {
			return timedFetch(
				process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + req.body.id,
				{
					bucket: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/<id>",
					method: "DELETE",
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					}
				}
			);
		}
	}).then(() => {
		// when done, return the remaining set of registrations
		getAllFIDO2Registrations(req, rsp);		
	}).catch((e) => {
		// for failures
        throw normaliseError("deleteRegistration", e, "Error deleting registration -  see server log for details");
	});
}

/**
* Returns the details of the indicated registration.
*/
function registrationDetails(req, rsp) {
	var regId = req.query.id;
	if (regId != null) {
		var access_token = null;
		tm.getAccessToken().then((at) => {
			access_token = at;
			// first retrieve the suggested registration
			return timedFetch(
				process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
				{				
					bucket: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/<id>",
					method: "GET",
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					returnAsJSON: true
				}
			);
		}).then((reg) => {
			rsp.json(reg);
		}).catch((e)  => {
            throw normaliseError("registrationDetails", e, "Unable to retrieve registration");
		});
	} else {
		rsp.json(new fido2error.fido2Error("Invalid id in request"));
	}
}


function getAllFIDO2Registrations(req, rsp) {
	tm.getAccessToken()
	.then((access_token) => {
		return timedFetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations",
			{
				method: "GET",
				headers: {
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true
			}
		);
	}).then((registrations) => {
		var rspBody = {
			"status": "ok",
			"registrations": registrations
		};
		rsp.json(rspBody);
	}).catch((e) => {
        throw normaliseError("getAllFIDO2Registrations", e, "Error retrieving registrations -  see server log for details");
	});
}

function lookupMe() {
	return tm.getAccessToken()
	.then((access_token) => {
		return timedFetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/Me",
			{
				bucket: process.env.CI_TENANT_ENDPOINT + "/v2.0/Me",
				method: "GET",
				headers: {
					"Accept": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true
			}
		);
	}).then((scimResponse) => {
		// should be exactly one result - if so, add to cache
		if (scimResponse && scimResponse.totalResults == 1) {
			userFilterMap[userFilter] = scimResponse.Resources[0];
		}
	}).catch((e) => {
		logger.logWithTS("ciservices.lookupUserWithFilter e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
	});
}

function lookupUserWithFilter(userFilter) {

    let usingMeResource = false;
    let url = process.env.CI_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({filter: userFilter});

	return tm.getAccessToken()
	.then((access_token) => {
        if (process.env.OIDC_USER_ACCESS_TOKEN != null) {
            url = process.env.CI_TENANT_ENDPOINT + "/v2.0/Me";
            usingMeResource = true;
        }

        //logger.logWithTS("lookupUserWithFilter usingMeResource: " + usingMeResource + " url: " + url);
		return timedFetch(
			url,
			{
				bucket: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users?filter=<userFilter>",
				method: "GET",
				headers: {
					"Accept": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true
			}
		);
	}).then((scimResponse) => {
        let scimResource = null;
        if (usingMeResource) {
            // the /Me resource returns the scim response as the entire result
            scimResource = scimResponse;
        } else {
            // should be exactly one result - if so, add to cache
            if (scimResponse && scimResponse.totalResults == 1) {
                scimResource = scimResponse.Resources[0];
            }
        }
        if (scimResource != null) {
            userFilterMap[userFilter] = scimResource;
        }

        return scimResource;
	}).catch((e) => {
		logger.logWithTS("ciservices.lookupUserWithFilter e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
	});
}

function usernameToId(username) {
	let result = null;

	let userFilter = 'username eq "' + username + '"';
    if (userFilterMap[userFilter] != null) {
		return userFilterMap[userFilter].id;
	} else {
		return lookupUserWithFilter(userFilter)
		.then((scimResult) => {
			// userFilterMap should be updated
			if (userFilterMap[userFilter] != null) {
				return userFilterMap[userFilter].id;
			} else {
				// fatal
				throw new fido2error.fido2Error("userId could not be resolved");
			}
		}).catch((e) => {
            let fido2Error = normaliseError("userIdToUsername", e, "Error resolving username: " + username);
			logger.logWithTS("usernameToId: Unable to resolve id for username: " + username + " error: " + JSON.stringify(fido2Error));
		});
	} 
}

function updateRPMaps() {
	// reads all relying parties from discovery service updates local caches
	return tm.getAccessToken()
	.then((access_token) => {
		return timedFetch(
			process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/discover/fido2",
			{
				method: "GET",
				headers: {
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				returnAsJSON: true
			}
		);
	}).then((discoverResponse) => {
		rpUuidMap = {};
		rpIdMap = {};
		// there is a response message schema change happening - tolerate the old and new...
		var rpWrapper = (discoverResponse.fido2 != null ? discoverResponse.fido2 : discoverResponse);
		rpWrapper.relyingParties.forEach((rp) => {
			rpUuidMap[rp.id] = rp.rpId;
			rpIdMap[rp.rpId] = rp.id;
		});
	}).catch((e) => {
		logger.logWithTS("ciservices.updateRPMaps e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
	});
}


function rpIdTorpUuid(rpId) {
	if (rpIdMap[rpId] != null) {
		return rpIdMap[rpId];
	} else {
		return updateRPMaps()
		.then(() => {
			if (rpIdMap[rpId] != null) {
				return rpIdMap[rpId];
			} else {
				// hmm - no rpId, fatal at this point.
				throw new fido2error.fido2Error("rpId: " + rpId + " could not be resolved");
			}			
		});
	}
}

function metadataExists(basename, existingMetadata) {
	var result = null;
	for (var i = 0; i < existingMetadata.metadata.length && result == null; i++) {
		if (existingMetadata.metadata[i].name == basename) {
			result = existingMetadata.metadata[i];
		}
	}
	return result;
}

/*
* Returns a promise that the file will be processed
*/
function processMetadataFile(file, existingMetadata) {
	const mdTypeMap = { ".json": "FIDO2", ".yubico": "YUBICO" };

	return tm.getAccessToken()
	.then((access_token) => {

		var basename = path.basename(file);
		var mdType = mdTypeMap[path.extname(file)];

		if (mdType != null) {
			// we're going to do something with this file
			var fileContents = fs.readFileSync(file, "utf8");

			var existingMdEntry = metadataExists(basename, existingMetadata);
			var methodToUse = null;
			var urlToUse = null;
			var bodyToUse = null;

			if (existingMdEntry != null) {
				// update metadata
				logger.logWithTS("Updating existing metadata with name: " + basename);
				methodToUse = "PUT";
				urlToUse = process.env.CI_TENANT_ENDPOINT + "/config/v2.0/factors/fido2/metadata/" + existingMdEntry.id;
				bodyToUse = existingMdEntry;
				bodyToUse.metadataStatement = fileContents;
			} else {
				// create metadata
				logger.logWithTS("Uploading new metadata with name: " + basename);
				methodToUse = "POST";
				urlToUse = process.env.CI_TENANT_ENDPOINT + "/config/v2.0/factors/fido2/metadata";
				bodyToUse = {
					"category": "conformance",
					"name": basename,
					"metadataStatement": fileContents,
					"enabled": true,
	    			"type": mdType
				};
			}
			return timedFetch(
				urlToUse,
				{
					bucket: process.env.CI_TENANT_ENDPOINT + "/config/v2.0/factors/fido2/metadata",
					method: methodToUse,
					headers: {
						"Content-type": "application/json",
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					body: JSON.stringify(bodyToUse)
				}
			);
		} else {
			logger.logWithTS("Skipping metadata processing for unrecognised file: " + file);
		}
		return file;
	});
}



module.exports = { 
    timedFetch: timedFetch,
    rpIdTorpUuid: rpIdTorpUuid,
	deleteRegistration: deleteRegistration,
	registrationDetails: registrationDetails,
    usernameToId: usernameToId,
	resetStats: resetStats,
	getStats: getStats,
    normaliseError: normaliseError
};
