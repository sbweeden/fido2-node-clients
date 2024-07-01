//
// Utility functions for common logging
//

//
// prints msg to console log with a timestamp prefix
//
function logWithTS(msg) {
	console.log((new Date()).toISOString() + " " + msg);
}


module.exports = { 
	logWithTS: logWithTS
};
