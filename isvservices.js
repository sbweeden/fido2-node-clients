//
// isvservices - performs user and FIDO2 operations against IBM Security Verify
//
const logger = require('./logging.js');
const tm = require('./oauthtokenmanager.js');
const fido2error = require('./fido2error.js');
const commonServices = require('./commonservices.js');
//
// Caching logic to reduce number of calls to CI
//

// cache to map rpId to rpUuid
var rpIdMap = {};
// cache to map rpUuid to rpId
var rpUuidMap = {};
// cache to map user lookup filters to CI user
var userFilterMap = {};



function deleteRegistration(req, rsp) {
	var access_token = null;
	tm.getAccessToken()
	.then((access_token) => {
		if (req.body.id != null) {
			return commonServices.timedFetch(
				process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + req.body.id,
				{
					bucket: process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/<id>",
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
			return commonServices.timedFetch(
				process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
				{				
					bucket: process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/<id>",
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
		return commonServices.timedFetch(
			process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations",
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

function lookupUserWithFilter(userFilter) {

    let usingMeResource = false;
    let url = process.env.ISV_TENANT_ENDPOINT + "/v2.0/Users?" + new URLSearchParams({filter: userFilter});

	return tm.getAccessToken()
	.then((access_token) => {
        if (process.env.OIDC_USER_ACCESS_TOKEN != null) {
            url = process.env.ISV_TENANT_ENDPOINT + "/v2.0/Me";
            usingMeResource = true;
        }

        //logger.logWithTS("lookupUserWithFilter usingMeResource: " + usingMeResource + " url: " + url);
		return commonServices.timedFetch(
			url,
			{
				bucket: process.env.ISV_TENANT_ENDPOINT + "/v2.0/Users?filter=<userFilter>",
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
		logger.logWithTS("isvservices.lookupUserWithFilter e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
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
		return commonServices.timedFetch(
			process.env.ISV_TENANT_ENDPOINT + "/v2.0/factors/discover/fido2",
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
		logger.logWithTS("isvservices.updateRPMaps e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
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

module.exports = { 
    rpIdTorpUuid: rpIdTorpUuid,
	deleteRegistration: deleteRegistration,
	registrationDetails: registrationDetails,
    usernameToId: usernameToId,
};
