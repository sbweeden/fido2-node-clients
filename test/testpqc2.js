// ml-dsa-44-signer.js

const crypto = require('node:crypto');
const util = require('node:util');

// Convert callback-based functions to promise-based
const generateKeyPairAsync = util.promisify(crypto.generateKeyPair);

/**
 * Generate an ML-DSA-44 key pair
 * @returns {Promise<Object>} Object containing public and private keys
 */
async function generateMLDSA44KeyPair() {
    try {
        const { publicKey, privateKey } = await generateKeyPairAsync('ml-dsa-44', {
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem',
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
            },
        });
        
        return { publicKey, privateKey };
    } catch (error) {
        console.error('Error generating ML-DSA-44 key pair:', error.message);
        throw error;
    }
}

/**
 * Sign a text string using ML-DSA-44
 * @param {string} text - The text to sign
 * @param {string} privateKey - The private key in PEM format
 * @returns {Promise<string>} The signature in hex format
 */
async function signText(text, privateKey) {
    try {
        // ML-DSA-44 uses SHAKE256 as the hash function
        const sign = crypto.createSign('shake256');
        sign.update(text);
        const signature = sign.sign(privateKey, 'hex');
        return signature;
    } catch (error) {
        console.error('Error signing text:', error.message);
        throw error;
    }
}

/**
 * Verify a signature using ML-DSA-44
 * @param {string} text - The original text
 * @param {string} signature - The signature in hex format
 * @param {string} publicKey - The public key in PEM format
 * @returns {Promise<boolean>} Whether the signature is valid
 */
async function verifySignature(text, signature, publicKey) {
    try {
        const verify = crypto.createVerify('shake256');
        verify.update(text);
        const isValid = verify.verify(publicKey, signature, 'hex');
        return isValid;
    } catch (error) {
        console.error('Error verifying signature:', error.message);
        throw error;
    }
}

/**
 * Main function to demonstrate ML-DSA-44 signing
 * @param {string} text - The text to sign
 */
async function demonstrateMLDSA44Signing(text) {
    console.log('='.repeat(60));
    console.log('ML-DSA-44 Signing Demonstration');
    console.log('='.repeat(60));
    console.log(`\nText to sign: "${text}"\n`);
    
    try {
        // Step 1: Generate key pair
        console.log('Generating ML-DSA-44 key pair...');
        const { publicKey, privateKey } = await generateMLDSA44KeyPair();
        
        console.log('Key pair generated successfully:');
        console.log('\nPublic Key (first 100 chars):');
        console.log(publicKey.substring(0, 100) + '...');
        console.log('\nPrivate Key (first 100 chars):');
        console.log(privateKey.substring(0, 100) + '...');
        
        // Step 2: Sign the text
        console.log('\nSigning text...');
        const signature = await signText(text, privateKey);
        
        console.log('Text signed successfully:');
        console.log('\nSignature (hex):');
        console.log(signature);
        
        // Step 3: Verify the signature
        console.log('\nVerifying signature...');
        const isValid = await verifySignature(text, signature, publicKey);
        
        console.log(`Signature verification: ${isValid ? 'SUCCESS ✓' : 'FAILED ✗'}`);
        
        // Step 4: Demonstrate invalid verification
        console.log('\nDemonstrating invalid verification (modified text)...');
        const modifiedText = text + ' (modified)';
        const isInvalidValid = await verifySignature(modifiedText, signature, publicKey);
        
        console.log(`Invalid signature verification: ${isInvalidValid ? 'FAILED (should be invalid)' : 'SUCCESS (correctly identified as invalid) ✓'}`);
        
    } catch (error) {
        console.error('\nAn error occurred during the demonstration:', error.message);
    }
    
    console.log('\n' + '='.repeat(60));
}

// Execute the demonstration with a sample text
const sampleText = 'This is a sample text to be signed with ML-DSA-44 algorithm.';
demonstrateMLDSA44Signing(sampleText);
