// isv_jwt_bearer.js

const jsrsasign = require('jsrsasign'); // https://www.npmjs.com/package/jsrsasign
const { v4: uuidv4 } = require('uuid');

let prvKeyPEM = "-----BEGIN PRIVATE KEY-----" + "\n" +
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgM7eeoE+9OAKTbFL4" + "\n" +
"e7tgsCifLbnUG0P0KIc4MHpOyLmhRANCAASIUhRPm9aegaxzb4MG5YlcKDHBS1XI" + "\n" +
"ESXx2Ig+e+R/E1it1tijc/UABdkWPnyReVBnKNeRMBHzLojwLEvl1mbk" + "\n" +
"-----END PRIVATE KEY-----";

let pubKeyPEM = "-----BEGIN PUBLIC KEY-----" + "\n" +
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiFIUT5vWnoGsc2+DBuWJXCgxwUtV" + "\n" +
"yBEl8diIPnvkfxNYrdbYo3P1AAXZFj58kXlQZyjXkTAR8y6I8CxL5dZm5A==" + "\n" +
"-----END PUBLIC KEY-----";

let pubKey = jsrsasign.KEYUTIL.getKey(pubKeyPEM);
let jwkObj = jsrsasign.KEYUTIL.getJWKFromKey(pubKey);
jwkObj.kid = jsrsasign.KJUR.jws.JWS.getJWKthumbprint(jwkObj);
jwkObj.use = "sig";

/*
// jwks string is shown below
// following example from https://kjur.github.io/jsrsasign/api/symbols/KEYUTIL.html#.getJWKFromKey
console.log("JWK: " + JSON.stringify(jwkObj));

{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "iFIUT5vWnoGsc2-DBuWJXCgxwUtVyBEl8diIPnvkfxM",
      "y": "WK3W2KNz9QAF2RY-fJF5UGco15EwEfMuiPAsS-XWZuQ",
      "kid": "iFzjsSbR4GtNSnhLIxgOMebmzoL12HD3nNlwLjSuIbM",
      "use": "sig"
    }
  ]
}  
*/

const CLIENT_ID="67484627-8fb0-47a6-aecb-f229587370b2";
const CLIENT_SECRET="7vIim09ukM";
const TENANT="myidp.ite4.idng.ibmcloudsecurity.com";
let userId = "813003NNJ7"; // the uid for emily - a user in my tenant
let lifetimeSec=120;
let skewSec=10; 


let prvKey = jsrsasign.KEYUTIL.getKey(prvKeyPEM);
let nowSec = Math.floor(new Date().getTime()/1000);
let tokenEndpoint =  "https://"+TENANT+"/oauth2/token";

let jwtHeader = { alg: "ES256", typ: "JWT", kid: jwkObj.kid};
let jwtClaims = {
    iss: "https://" + TENANT,
    aud: tokenEndpoint,
    sub: userId,
    scope: "openid",
    nbf: (nowSec-skewSec),
    iat: nowSec,
    exp: (nowSec+skewSec+lifetimeSec),
    jti: uuidv4()
};

let sHeader = JSON.stringify(jwtHeader);
let sPayload = JSON.stringify(jwtClaims);
let assertion = jsrsasign.KJUR.jws.JWS.sign(jwtHeader.alg, sHeader, sPayload, prvKey);

//console.log(assertion);

// perform grant type: urn:ietf:params:oauth:grant-type:jwt-bearer
let formData = {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    assertion: assertion
}
let myBody = new URLSearchParams(formData);

//console.log('curl -i -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&client_id=67484627-8fb0-47a6-aecb-f229587370b2&client_secret=7vIim09ukM&assertion=' + assertion + '" "https://' + TENANT + '/oauth2/token"');

fetch(
   tokenEndpoint,
    {
        method: "POST",
        headers: {
            "Accept": "application/json",
        },
        body: myBody
    }
).then((rsp) => {
    return rsp.json();
}).then((tr) => {
    console.log("Received JSON response: " + JSON.stringify(tr));

    // do more here
    if (tr.access_token) {
        let sessionEndpoint = "https://" + TENANT + "/v1.0/auth/session";
        console.log('Redirect the browser to: ' + sessionEndpoint + '?access_token=' + tr.access_token + '&redirect_url=%2Fusc');
        
    }
});
