// test/testpqc.js

const crypto = require('node:crypto');

const TESTALGS = [ 
    {
        name: 'ES256',
        algId: -7,
        createParams: {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        signParams: {
            name: 'ECDSA',
            hash: 'SHA-256'
        },
        verifyParams: {
            name: 'ECDSA',
            hash: 'SHA-256'
        }
    }, 
    {
        name: 'ML-DSA-44',
        algId: -49,
        createParams: 'ML-DSA-44',
        signParams: 'ML-DSA-44',
        verifyParams: 'ML-DSA-44'
    }
];

function subtleKeyToPEM(k) {
    const kObj = crypto.KeyObject.from(k);
    return kObj.export({ type: (k.type == "private" ? 'pkcs8' : 'spki'), format: 'pem'});
}


(async function main() {
  TESTALGS.forEach(async (TESTALG) => {
    console.log("TESTING ALG: " + TESTALG.name)
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
        TESTALG.createParams,
        true,
        ['sign', 'verify'],
    );

    console.log(TESTALG.name + " publicKey:", publicKey);
    console.log(TESTALG.name + " privateKey:", privateKey);

    let pubKeyAB = await crypto.subtle.exportKey('spki', publicKey);
    console.log(TESTALG.name + " pubKeyAB: ", pubKeyAB);
    console.log(TESTALG.name + " pubKeyAB hex: ", Buffer.from(pubKeyAB).toString("hex"));
    console.log(TESTALG.name + " publicKeyPEM: " + subtleKeyToPEM(publicKey));

    let privKeyAB = await crypto.subtle.exportKey('pkcs8', privateKey);
    console.log(TESTALG.name + " privKeyAB: ", privKeyAB);
    console.log(TESTALG.name + " privKeyAB hex: ", Buffer.from(privKeyAB).toString("hex"));
    console.log(TESTALG.name + " privateKeyPEM: " + subtleKeyToPEM(privateKey));

    const data = new TextEncoder().encode('some data to sign');

    // https://nodejs.org/docs/latest-v24.x/api/webcrypto.html#subtlesignalgorithm-key-data
    const signature = await crypto.subtle.sign(TESTALG.signParams, privateKey, data);
    console.log(TESTALG.name + " signature:", Buffer.from(signature).toString('hex'));

    // https://nodejs.org/docs/latest-v24.x/api/webcrypto.html#subtleverifyalgorithm-key-signature-data
    const verified = await crypto.subtle.verify(TESTALG.verifyParams, publicKey, signature, data);
    console.log(TESTALG.name + ' signature verified:', verified);
  });
})();

