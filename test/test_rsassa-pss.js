

var pubKeyPEM = "-----BEGIN PUBLIC KEY-----\n" + 
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgjcCiH/abllE/q/XtvCv\n" + 
"EWdexxqcHYeLDy+bV0GhPXbz7sQ1fp9i4UrmvQ07BauiEIITZnLTPu3YVMA1flTZ\n" + 
"LiNoekUdj7395+na2tTzAxhwwGdxR08huHaBcQu2VBQKLTBb1/0sjUNJz7IUFWLC\n" + 
"1Jrl14MPU95KLOG5p6vzJpnRm0GZEy23H+wcFJkF9aXCoXdGxtxcxdys2xZT3lkc\n" + 
"17EZAmAT8yEs7674X/F6BVMzK8zx166M/5Zk/2NQuPcjeUwPB+lE0k1FObTATbPx\n" + 
"KuXIxAYLTHgT2OX5voV4XmPXlalHBzG+u0VudfB9BJLkwpNW0QOz/GS26NQ0R8jG\n" + 
"TwIDAQAB\n" + 
"-----END PUBLIC KEY-----";

var privKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\n" + 
"MIIEogIBAAKCAQEAgjcCiH/abllE/q/XtvCvEWdexxqcHYeLDy+bV0GhPXbz7sQ1\n" + 
"fp9i4UrmvQ07BauiEIITZnLTPu3YVMA1flTZLiNoekUdj7395+na2tTzAxhwwGdx\n" + 
"R08huHaBcQu2VBQKLTBb1/0sjUNJz7IUFWLC1Jrl14MPU95KLOG5p6vzJpnRm0GZ\n" + 
"Ey23H+wcFJkF9aXCoXdGxtxcxdys2xZT3lkc17EZAmAT8yEs7674X/F6BVMzK8zx\n" + 
"166M/5Zk/2NQuPcjeUwPB+lE0k1FObTATbPxKuXIxAYLTHgT2OX5voV4XmPXlalH\n" + 
"BzG+u0VudfB9BJLkwpNW0QOz/GS26NQ0R8jGTwIDAQABAoIBAGZsGIz/a/OSOgfO\n" + 
"jnFx/XJGCbG4h4VeoQ3P13MZx1cOYq6zHJS9j8w/2yBm8L70EqTDe7kAppKACMIY\n" + 
"8bqtyKpW5Y4PIUJ4Iegx9JheGcuchMuCUgLSBmcOp6Ago0ic/qguun84v7tZawx4\n" + 
"OP3dUfxi3ljW2M6SMWv+HMb7JGV+RhL67YDkyWNc+5+LxRuo6h3qKyp8YI6aqy2M\n" + 
"HzYmdDxCOrxrp7lggVPiYLtU3a2L69NF2CLlJlHHgIdQMttbyEU4QzpvGh+DPMYJ\n" + 
"mUL8QlDCMUu/bkk2jRz7HcbFJWJXhFpGXAjQswZbwen9n8AD40ZeaP5FRsna6k9R\n" + 
"rXOWH7ECgYEAw2cWwwo3egh5c2Mrr4pZdqtLrkJrkCeOJUCNz0EPAAnVQl9Jy+MD\n" + 
"hOTfP754RWLSZyBHBspgtvJ40xpYwPG2VJmyXYTJchr0yQ4cGyf0gZ3bBzlueeLU\n" + 
"ctRbfm4x7c8JLQsGJFTnC79/1RrjHWxz6MsnL0nFapcIXtX1lQvrIKkCgYEAqpiy\n" + 
"cwLJmfuPpXy+hqDc4JglEJxHyJ2inNZ7roW7VDAkOFZ8ujrGH+ImaYbDNgsJnhjk\n" + 
"xQM3ZJ6qDkXWexTlTb5ehP9Fe843yp09YXX+QtDXolv2FqvMjGVJDIZHacQdcexs\n" + 
"EcBHHUiar2ld8gw4sUtRM4m8J0hmTOOHAqZd8jcCgYB/FIZrJjPaO7Sw5Gg+690v\n" + 
"HkxD8pJ92BvMAmW3ynn07nAxkEMwRF2/ihHfJQKXLaPkycsnkWrA0ITf1hyurwSD\n" + 
"lMm5pGhWu01DjNeemaecvIr78c/1mR3N6Gnwmb4DCUjQcID4E/eHXm3GrIvUUPo5\n" + 
"BhZf3Lx1i/A3rTLgUjYCsQKBgHgmNUBVTUGa8A+gbNuKviWcYjZxqwj7JMULNm6z\n" + 
"Fz1y7n+TQiMzM8jO0TjvRdtxKKPlanHrEv9V0/VbcHSdQeZgVlebJgfNNHQKDGnw\n" + 
"3VOXnNdnp0lOVDDpQOqGRBOUoRxUY8SYxD02nmM+dYD85IzRu+3tasvL7OjoMnVG\n" + 
"UNI/AoGANGppQIwFOrqIQJtbfu9V3XtQG2ga50M9QmPzGuqS1lXbaqZpVpQnokNa\n" + 
"tL8ekqPO25mKKdOTrpBi6uoLDk4LZFPs52gOxYBVPEcLfkPWArC7goPT0py17EUP\n" + 
"znGpyhd7RAFBlXzh7/+DOrbDLpgjlOkKd5WhGRjPPuvEF1IlfdQ=\n" + 
"-----END RSA PRIVATE KEY-----";

function pemStringToBytes(s) {
    // remove header and footer
    s = s.replace(/-----(BEGIN|END) ([^-]+)-----/g, '');
    //remove newlines
    s = s.replace(/\n/g, '');
    // convert base64 to bytes
    return b64toBA(s);
}

var msg = "test";
var prvKey = null;
var pubKey = null;
/*
crypto.subtle.importKey(
    "spki",
    new Uint8Array(pemStringToBytes(pubKeyPEM)),
    {
        name: "RSA-PSS",
        hash: "SHA-256"
    },
    true,
    ["verify"]
).then(pk => {
    pubKey = pk;
    return crypto.subtle.importKey(
        "pkcs8",
        new Uint8Array(pemStringToBytes(privKeyPEM)),
        {
            name: "RSA-PSS",
            hash: "SHA-256"
        },
        true,
        ["sign"]);
}).then(pk => {
    prvKey = pk;
    console.log("Key imports complete");
    return;
}).then(() => {
*/

// PS256
/*
var genParams = {
    name: "RSA-PSS",
    modulusLength: 2048, //can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
};
var signParams = {
    name: "RSA-PSS",
    saltLength: 32
};

var verifyParams = signParams;
*/

// PS384
var genParams = {
    name: "RSA-PSS",
    modulusLength: 2048, //can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-384"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
};
var signParams = {
    name: "RSA-PSS",
    saltLength: 48
};
var verifyParams = signParams;

// PS512
/*
var genParams = {
    name: "RSA-PSS",
    modulusLength: 2048, //can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-512"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
};
var signParams = {
    name: "RSA-PSS",
    saltLength: 64
};
var verifyParams = signParams;
*/

// RS256
/*
var genParams = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-256',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1,0,1])
};
var signParams = 'RSASSA-PKCS1-v1_5';
var verifyParams = signParams;
*/


// main entry point
crypto.subtle.generateKey(
    genParams,
    true, ['sign', 'verify']
).then((kp) => {
    prvKey = kp.privateKey;
    pubKey = kp.publicKey;
    console.log("Key generation complete");
    return crypto.subtle.exportKey("spki", pubKey);
}).then((spki) => {
    let pkBytes = fidotools.bytesFromArray(new Uint8Array(spki), 0, -1);
    let pkB64 = hextob64(BAtohex(pkBytes));
    let pkPEM = "-----BEGIN PUBLIC KEY-----" + "\n" + pkB64.match(/.{1,64}/g).join('\n') + "\n" + "-----END PUBLIC KEY-----";
    console.log(pkPEM);

    return crypto.subtle.sign(
        signParams,
        prvKey,
        new TextEncoder().encode(msg)
    );
}).then(signature => {
    let sigB64 = hextob64(BAtohex(fidotools.bytesFromArray(new Uint8Array(signature), 0, -1)));
    console.log("msg: " + msg);
    console.log("sigB64: " + sigB64);
});

