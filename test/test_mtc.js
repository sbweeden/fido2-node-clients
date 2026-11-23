//
// test/test_mtc.js - Integration tests for Merkle Tree Certificate (MTC) attestation (fmt "mtc", WebAuthn Level 4)
//
// Run with: npm run test:mtc   (or: node test/test_mtc.js)
//
// See MTC_IMPLEMENTATION_PLAN.md (Task 6). Unlike test_mtc_primitives.js (unit tests with hand-built fixtures) this
// runner exercises the complete chain using the artifacts produced by the real generator:
//
//   certs/generate_attestation_certs.js --mtc-only   (ML-DSA-87 root CA, 1024 leaf tree, signed checkpoint, MDS3 JSON)
//     -> FIDO2_CLIENT_CONFIG "mtc" block -> emulated authenticator (fidoutils.processCredentialCreationOptions)
//     -> Relying Party verification (fidoutils.verifyMTCAttestation)
//
// The generator is executed in a fresh temporary directory so the test never depends on (or modifies) the developer's
// own certs/ artifacts or .env. Requires Node 24+ (ML-DSA in node:crypto). The test does not need the openssl CLI.
//
// Tests:
//   1. MDS3 mode: registration verified against the generated metadata (all trust levels) + generator output sanity.
//   2. In-band mode: registration with the mtcDebug extension verified autonomously (no metadata, untrusted result).
//   3. Negative security tests: invalid signature, altered AAGUID, forged leaf, bad Merkle path, expired timestamp,
//      tampered checkpoint (plus in-band and RP rule variants).
//

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const cbor = require('cbor');
const fidoutils = require('../fidoutils.js');
const mycertutil = require('../mycertutil.js');
const mykeyutil = require('../mykeyutil.js');

//
// Fixture: run the real generator once in a temporary directory
//
let artifactsPromise = null;
function getArtifacts() {
    if (artifactsPromise == null) {
        artifactsPromise = Promise.resolve().then(() => {
            const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mtc-it-'));
            try {
                fs.copyFileSync(path.join(__dirname, '..', 'certs', 'icon.txt'), path.join(dir, 'icon.txt'));
                const stdout = execFileSync(process.execPath,
                    [path.join(__dirname, '..', 'certs', 'generate_attestation_certs.js'), '--mtc-only'],
                    { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000 }).toString();
                const mtcConfig = JSON.parse(stdout);
                const metadata = JSON.parse(fs.readFileSync(path.join(dir, 'fidotest-mtc.json'), 'utf8'));
                // second run must be idempotent and emit the identical configuration
                const stdout2 = execFileSync(process.execPath,
                    [path.join(__dirname, '..', 'certs', 'generate_attestation_certs.js'), '--mtc-only'],
                    { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000 }).toString();
                return { mtcConfig, metadata, rerunConfig: JSON.parse(stdout2) };
            } finally {
                fs.rmSync(dir, { recursive: true, force: true });
            }
        });
    }
    return artifactsPromise;
}

const clone = (o) => JSON.parse(JSON.stringify(o));
const decodeAtt = (bytes) => cbor.decode(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
// cbor encodes Uint8Array as a tagged typed array, so convert byte strings to Buffers first
const toBufs = (o) => (o instanceof Uint8Array ? Buffer.from(o) : (o && typeof o === 'object' && !Buffer.isBuffer(o))
    ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, toBufs(v)])) : o);
const encodeAtt = (o) => Buffer.from(cbor.encode(toBufs(o)));

/*
 * Registers with the emulated authenticator using the given "mtc" configuration block.
 * Returns { res, attObjBytes, clientDataHash }.
 */
async function register(mtcConfig, extensions) {
    await fidoutils.init();
    fidoutils.setFidoUtilsConfig({ origin: "https://localhost:8443", encryptionPassphrase: "test", mtc: mtcConfig });
    const cco = {
        publicKey: {
            rp: { id: "localhost", name: "MTC Integration RP" },
            user: { id: [1, 2, 3, 4], name: "alice", displayName: "Alice" },
            challenge: [...crypto.randomBytes(32)],
            pubKeyCredParams: [{ alg: -7, type: "public-key" }]
        }
    };
    if (extensions) cco.publicKey.extensions = extensions;
    const res = await fidoutils.processCredentialCreationOptions(cco, "mtc");
    const attObjBytes = mykeyutil.fromBase64Url(res.spkc.response.attestationObject);
    const clientDataHash = crypto.createHash("sha256").update(mykeyutil.fromBase64Url(res.spkc.response.clientDataJSON)).digest();
    return { res, attObjBytes, clientDataHash };
}

// ---------------------------------------------------------------------------------------------
// Generator output sanity (artifacts consumed by Tasks 3-5)
// ---------------------------------------------------------------------------------------------
test('generator: emits consistent MDS3 metadata and client configuration, and is idempotent', async () => {
    const { mtcConfig, metadata, rerunConfig } = await getArtifacts();

    assert.deepEqual(rerunConfig, mtcConfig, 're-running the generator must reuse existing artifacts');

    // MDS3 metadata statement
    assert.equal(metadata.schema, 3);
    assert.equal(metadata.protocolFamily, 'fido2');
    assert.equal(metadata.aaguid, mtcConfig.aaguid);
    assert.equal(metadata.attestationRootCertificates.length, 1);
    assert.equal(metadata.mtcTrustAnchors.length, 1);

    const anchor = metadata.mtcTrustAnchors[0];
    const caId = Buffer.from(anchor.caId, 'base64');
    assert.equal(caId.toString('hex'), mtcConfig.caId);
    assert.equal(anchor.subtrees.length, 1);
    assert.equal(anchor.batchKeys.length, 1);
    const subtree = anchor.subtrees[0];
    const batchKey = anchor.batchKeys[0];

    // Level 1: the root certificate is an ML-DSA-87 certificate, Level 2: it signed the 85 byte checkpoint
    const root = new crypto.X509Certificate(Buffer.from(metadata.attestationRootCertificates[0], 'base64'));
    assert.equal(subtree.alg, -50);
    assert.equal(subtree.end - subtree.start, 1024);
    const rootHash = Buffer.from(subtree.rootHash, 'base64');
    assert.equal(rootHash.length, 32);
    const checkpoint = mycertutil.buildFidoMtcSubtreeCheckpoint({
        caId, logNumber: subtree.logNumber, start: subtree.start, end: subtree.end, rootHash
    });
    assert.equal(checkpoint.length, 85);
    assert.equal(crypto.verify(null, checkpoint, root.publicKey, Buffer.from(subtree.signature, 'base64')), true);

    // Levels 3 / 4: the leaf for the batch key climbs to the checkpoint root hash
    const serial = BigInt(batchKey.serial);
    assert.equal(serial, (BigInt(subtree.logNumber) << 48n) | (serial & 0xFFFFFFFFFFFFn));
    const coseKeyBytes = Buffer.from(batchKey.coseKey, 'base64');
    assert.equal(coseKeyBytes.toString('hex'), mtcConfig.coseKey);
    const entry = mycertutil.buildFidoMtcLogEntry({
        caId, serial, notBefore: batchKey.notBefore, notAfter: batchKey.notAfter,
        aaguid: Buffer.from(metadata.aaguid.replaceAll('-', ''), 'hex'), coseKeyBytes
    });
    assert.equal(entry.length, 82);
    const proofBytes = Buffer.from(batchKey.mtcProof, 'base64');
    assert.equal(proofBytes.length, 320);
    assert.equal(proofBytes.toString('hex'), mtcConfig.mtcProof);
    const proof = [];
    for (let i = 0; i < proofBytes.length; i += 32) proof.push(proofBytes.subarray(i, i + 32));
    assert.equal(mycertutil.verifyRFC9162MerkleProof({
        leafHash: mycertutil.computeFidoMtcLeafHash(entry), proof, leafIndex: serial & 0xFFFFFFFFFFFFn,
        start: subtree.start, end: subtree.end, rootHash
    }), true);
    assert.equal(rootHash.toString('hex'), mtcConfig.rootHash);

    // client configuration: private key matches the committed public key
    assert.equal(mtcConfig.alg, -48);
    const privateKey = await mykeyutil.getPrivateKeyFromHex(mtcConfig.alg, mtcConfig.privateKeyHex);
    const coseMap = cbor.decodeFirstSync(coseKeyBytes);
    const publicKey = await mykeyutil.getPublicKeyFromCOSE({ "1": coseMap.get(1), "3": coseMap.get(3), "-1": coseMap.get(-1) });
    const msg = Buffer.from('generator sanity');
    const sig = await mykeyutil.signBytesWithPrivateKey(mtcConfig.alg, privateKey, msg);
    assert.equal(await mykeyutil.validateSignature(mtcConfig.alg, publicKey, msg, sig), true);
});

// ---------------------------------------------------------------------------------------------
// Test 1: full registration and verification with FIDO MDS3 metadata
// ---------------------------------------------------------------------------------------------
test('Test 1: registration verifies against the MDS3 metadata (Levels 1-5)', async () => {
    const { mtcConfig, metadata } = await getArtifacts();
    const batchKey = metadata.mtcTrustAnchors[0].batchKeys[0];

    for (const extensions of [null, { mtcDebug: true }]) {
        const { res, attObjBytes, clientDataHash } = await register(mtcConfig, extensions);

        // wire format: fmt "mtc" with exactly { alg, sig, mtcCert: { caId, serial } }
        const att = decodeAtt(attObjBytes);
        assert.equal(att.fmt, 'mtc');
        assert.deepEqual(Object.keys(att.attStmt).sort(), ['alg', 'mtcCert', 'sig']);
        assert.deepEqual(Object.keys(att.attStmt.mtcCert).sort(), ['caId', 'serial']);
        assert.equal(att.attStmt.alg, mtcConfig.alg);

        const r = await fidoutils.verifyMTCAttestation(res.spkc.response.attestationObject, clientDataHash, metadata);
        assert.equal(r.verified, true);
        assert.equal(r.mode, 'mds');
        assert.equal(r.trusted, true);
        assert.equal(r.attestationType, 'basic');
        assert.equal(r.alg, mtcConfig.alg);
        assert.equal(r.serial, BigInt(batchKey.serial));
        assert.equal(r.leafIndex, 0n);
        assert.equal(r.logNumber, 1);
        assert.equal(r.subtree.start, 0n);
        assert.equal(r.subtree.end, 1024n);
        assert.equal(r.rootHash.toString('hex'), mtcConfig.rootHash);
        assert.equal(r.aaguid.toString('hex'), metadata.aaguid.replaceAll('-', ''));
        assert.equal(r.batchPublicKeyCose.toString('hex'), mtcConfig.coseKey);

        // the same result is obtained from raw CBOR bytes and from a decoded attestationObject
        await fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, metadata);
        await fidoutils.verifyMTCAttestation(att, clientDataHash, metadata);

        // RP rule: mtc-debug output is only acceptable with fmt "mtc"
        assert.equal(fidoutils.assertNoMTCDebugUnlessMTC(attObjBytes, res.spkc.getClientExtensionResults), true);
    }
});

test('Test 1b: metadata is not trusted for a different AAGUID or an unknown CA', async () => {
    const { mtcConfig, metadata } = await getArtifacts();
    const { attObjBytes, clientDataHash } = await register(mtcConfig, null);

    const otherAaguid = clone(metadata);
    otherAaguid.aaguid = '00000000-0000-0000-0000-000000000001';
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, otherAaguid), /aaguid does not match/);

    const otherCa = clone(metadata);
    otherCa.mtcTrustAnchors[0].caId = Buffer.from('0102030405', 'hex').toString('base64');
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, otherCa), /no batch key found/);

    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, null), /no batch key found/);
});

// ---------------------------------------------------------------------------------------------
// Test 2: in-band registration and autonomous verification with the mtcDebug extension
// ---------------------------------------------------------------------------------------------
test('Test 2: in-band (mtc-debug) registration is verified autonomously and is untrusted', async () => {
    const { mtcConfig } = await getArtifacts();
    const { res, attObjBytes, clientDataHash } = await register(mtcConfig, { mtcDebug: true });

    // authenticator data extension and client extension output
    const att = decodeAtt(attObjBytes);
    const authData = Buffer.from(att.authData);
    assert.equal(authData[32] & 0xC0, 0xC0, 'AT and ED flags are set');
    const ext = fidoutils.unpackAuthData(authData).extensions['mtc-debug'];
    assert.equal(Buffer.from(ext.pubKey).toString('hex'), mtcConfig.coseKey);
    assert.equal(Buffer.from(ext.mtcProof).toString('hex'), mtcConfig.mtcProof);
    assert.equal(Buffer.from(ext.rootHash).toString('hex'), mtcConfig.rootHash);
    assert.equal(ext.notBefore, mtcConfig.notBefore);
    assert.equal(ext.notAfter, mtcConfig.notAfter);
    assert.equal(ext.deviceSerial, undefined, 'deviceSerial must not be disclosed without enterprise attestation');

    const out = res.spkc.getClientExtensionResults.mtcDebug;
    assert.equal(out.pubKey, Buffer.from(mtcConfig.coseKey, 'hex').toString('base64url'));
    assert.equal(out.mtcProof, Buffer.from(mtcConfig.mtcProof, 'hex').toString('base64url'));
    assert.equal(out.rootHash, Buffer.from(mtcConfig.rootHash, 'hex').toString('base64url'));

    // not allowed by default
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, null), /no batch key found/);

    // allowed explicitly: verifies with no metadata at all, but is flagged as untrusted
    const r = await fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, null, { allowInBand: true });
    assert.equal(r.verified, true);
    assert.equal(r.mode, 'in-band');
    assert.equal(r.trusted, false);
    assert.equal(r.leafIndex, 0n);
    assert.equal(r.rootHash.toString('hex'), mtcConfig.rootHash);
    assert.equal(r.batchPublicKeyCose.toString('hex'), mtcConfig.coseKey);

    // a registration without the extension cannot be verified in-band
    const plain = await register(mtcConfig, null);
    await assert.rejects(fidoutils.verifyMTCAttestation(plain.attObjBytes, plain.clientDataHash, null, { allowInBand: true }),
        /no batch key found/);
});

test('Test 2b: in-band registration with the extension is also fully trusted when MDS metadata is supplied', async () => {
    const { mtcConfig, metadata } = await getArtifacts();
    const { attObjBytes, clientDataHash } = await register(mtcConfig, { mtcDebug: true });
    const r = await fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, metadata, { allowInBand: true });
    assert.equal(r.mode, 'mds');
    assert.equal(r.trusted, true);
});

// ---------------------------------------------------------------------------------------------
// Test 3: negative security tests
// ---------------------------------------------------------------------------------------------
test('Test 3a: invalid signature / clientDataHash / tampered authenticatorData are rejected', async () => {
    const { mtcConfig, metadata } = await getArtifacts();
    const { attObjBytes, clientDataHash } = await register(mtcConfig, null);
    const verify = (att, hash = clientDataHash) => fidoutils.verifyMTCAttestation(Buffer.isBuffer(att) ? att : encodeAtt(att), hash, metadata);
    await verify(attObjBytes); // baseline

    // flipped bit in the signature
    let att = decodeAtt(attObjBytes);
    const sig = Buffer.from(att.attStmt.sig); sig[sig.length >> 1] ^= 1; att.attStmt.sig = sig;
    await assert.rejects(verify(att), /attStmt\.sig is not a valid signature/);

    // truncated signature
    att = decodeAtt(attObjBytes);
    att.attStmt.sig = Buffer.from(att.attStmt.sig).subarray(0, 100);
    await assert.rejects(verify(att), /attStmt\.sig is not a valid signature/);

    // signature belongs to a different ceremony (clientDataHash)
    const badHash = Buffer.from(clientDataHash); badHash[31] ^= 1;
    await assert.rejects(verify(attObjBytes, badHash), /attStmt\.sig is not a valid signature/);

    // authenticatorData altered after signing (rpIdHash, flags/counter and AAGUID)
    for (const offset of [0, 33, 40]) {
        att = decodeAtt(attObjBytes);
        const ad = Buffer.from(att.authData); ad[offset] ^= 1; att.authData = ad;
        await assert.rejects(verify(att), /./, 'authData byte ' + offset);
    }
});

test('Test 3b: altered AAGUID is rejected (metadata mismatch and leaf commitment)', async () => {
    const { mtcConfig, metadata } = await getArtifacts();

    // an authenticator that signs correctly, but reports a different AAGUID than the one committed in the log
    const rogue = Object.assign({}, mtcConfig, { aaguid: '11111111-2222-3333-4444-555555555555' });
    const { attObjBytes, clientDataHash } = await register(rogue, null);
    assert.equal(Buffer.from(decodeAtt(attObjBytes).authData).subarray(37, 53).toString('hex'), '11111111222233334444555555555555');

    // rejected because the metadata statement is for another AAGUID
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, metadata), /aaguid does not match/);

    // even if the RP metadata does not pin an AAGUID, the leaf hash commits to it so the Merkle proof fails
    const unpinned = clone(metadata); delete unpinned.aaguid;
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, unpinned), /Merkle inclusion proof/);
});

test('Test 3c: forged leaf (any committed field or the batch key) is rejected', async () => {
    const { mtcConfig, metadata } = await getArtifacts();
    const { attObjBytes, clientDataHash } = await register(mtcConfig, null);
    const verify = (md) => fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, md);

    // committed notBefore changed
    let md = clone(metadata); md.mtcTrustAnchors[0].batchKeys[0].notBefore += 1;
    await assert.rejects(verify(md), /Merkle inclusion proof/);

    // committed notAfter changed (still valid at "now")
    md = clone(metadata); md.mtcTrustAnchors[0].batchKeys[0].notAfter -= 1;
    await assert.rejects(verify(md), /Merkle inclusion proof/);

    // committed firmware version / extensions added to the entry
    md = clone(metadata); md.mtcTrustAnchors[0].batchKeys[0].firmwareVersion = 1;
    await assert.rejects(verify(md), /Merkle inclusion proof/);

    // metadata lists a different public key for this serial: the signature check fails
    const other = await mykeyutil.generateKeypair(mtcConfig.alg);
    const otherCose = cbor.encodeCanonical(new Map([[1, 7], [3, mtcConfig.alg], [-1, Buffer.from((await mykeyutil.getPublicKeyCOSE(mtcConfig.alg, other))["-1"])]]));
    md = clone(metadata); md.mtcTrustAnchors[0].batchKeys[0].coseKey = otherCose.toString('base64');
    await assert.rejects(verify(md), /attStmt\.sig is not a valid signature/);

    // an attacker's own key, validly signing, but never logged: serial of a real entry, wrong key
    const attackerCfg = Object.assign({}, mtcConfig, {
        privateKeyHex: await mykeyutil.getPrivateKeyHex(other),
        coseKey: otherCose.toString('hex')
    });
    const forged = await register(attackerCfg, null);
    await assert.rejects(fidoutils.verifyMTCAttestation(forged.attObjBytes, forged.clientDataHash, metadata),
        /attStmt\.sig is not a valid signature/);
    // ... and if the attacker also swaps the key in the (untrusted) metadata the commitment no longer matches the leaf
    md = clone(metadata); md.mtcTrustAnchors[0].batchKeys[0].coseKey = otherCose.toString('base64');
    await assert.rejects(fidoutils.verifyMTCAttestation(forged.attObjBytes, forged.clientDataHash, md), /Merkle inclusion proof/);

    // a serial that is not in the log
    const att = decodeAtt(attObjBytes); att.attStmt.mtcCert.serial = Number(att.attStmt.mtcCert.serial) + 1;
    await assert.rejects(fidoutils.verifyMTCAttestation(encodeAtt(att), clientDataHash, metadata), /no batch key found/);
});

test('Test 3d: bad Merkle path is rejected', async () => {
    const { mtcConfig, metadata } = await getArtifacts();
    const { attObjBytes, clientDataHash } = await register(mtcConfig, null);
    const verify = (md) => fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, md);
    const proof = Buffer.from(metadata.mtcTrustAnchors[0].batchKeys[0].mtcProof, 'base64');

    // flip a bit in every sibling in turn
    for (let i = 0; i < proof.length / 32; i++) {
        const p = Buffer.from(proof); p[i * 32] ^= 1;
        const md = clone(metadata); md.mtcTrustAnchors[0].batchKeys[0].mtcProof = p.toString('base64');
        await assert.rejects(verify(md), /Merkle inclusion proof/, 'sibling ' + i);
    }

    // swapped siblings, truncated, extended, misaligned and missing proofs
    const swapped = Buffer.concat([proof.subarray(32, 64), proof.subarray(0, 32), proof.subarray(64)]);
    const cases = [
        [swapped, /Merkle inclusion proof/],
        [proof.subarray(0, proof.length - 32), /Merkle inclusion proof/],
        [Buffer.concat([proof, proof.subarray(0, 32)]), /Merkle inclusion proof/],
        [proof.subarray(0, proof.length - 1), /multiple of 32/],
        [null, /mtcProof is required/]
    ];
    for (const [value, expected] of cases) {
        const md = clone(metadata);
        if (value == null) delete md.mtcTrustAnchors[0].batchKeys[0].mtcProof;
        else md.mtcTrustAnchors[0].batchKeys[0].mtcProof = value.toString('base64');
        await assert.rejects(verify(md), expected);
    }
});

test('Test 3e: expired / not yet valid timestamps are rejected', async () => {
    const { mtcConfig, metadata } = await getArtifacts();
    const { attObjBytes, clientDataHash } = await register(mtcConfig, null);
    const batchKey = metadata.mtcTrustAnchors[0].batchKeys[0];

    await fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, metadata, { now: batchKey.notBefore });
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, metadata, { now: batchKey.notBefore - 1 }),
        /validity period/);
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, metadata, { now: batchKey.notAfter + 1 }),
        /validity period/);

    // a log entry that has genuinely expired (metadata notAfter in the past)
    const md = clone(metadata); md.mtcTrustAnchors[0].batchKeys[0].notAfter = batchKey.notBefore - 1000;
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, md), /validity period/);

    // revoked serial range (RP supplied)
    const revoked = clone(metadata);
    revoked.mtcTrustAnchors[0].revokedSerialRanges = [{ start: batchKey.serial, end: batchKey.serial }];
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, revoked), /revoked/);
});

test('Test 3f: tampered checkpoint is rejected', async () => {
    const { mtcConfig, metadata } = await getArtifacts();
    const { attObjBytes, clientDataHash } = await register(mtcConfig, null);
    const verify = (md) => fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, md);

    // flipped bit in the checkpoint signature
    let md = clone(metadata);
    const sig = Buffer.from(md.mtcTrustAnchors[0].subtrees[0].signature, 'base64'); sig[7] ^= 1;
    md.mtcTrustAnchors[0].subtrees[0].signature = sig.toString('base64');
    await assert.rejects(verify(md), /checkpoint signature/);

    // root hash replaced: the leaf no longer climbs to it
    md = clone(metadata);
    const rh = Buffer.from(md.mtcTrustAnchors[0].subtrees[0].rootHash, 'base64'); rh[0] ^= 1;
    md.mtcTrustAnchors[0].subtrees[0].rootHash = rh.toString('base64');
    await assert.rejects(verify(md), /Merkle inclusion proof/);

    // range or log number changed: the signed preimage no longer matches
    md = clone(metadata); md.mtcTrustAnchors[0].subtrees[0].end = 2048;
    await assert.rejects(verify(md), /Merkle inclusion proof|checkpoint signature/);
    md = clone(metadata); md.mtcTrustAnchors[0].subtrees[0].logNumber = 2;
    await assert.rejects(verify(md), /no subtree|checkpoint|Merkle|batch key/);

    // attacker re-signs the checkpoint (valid root hash) with its own ML-DSA-87 key, which is not the vendor root
    const attacker = crypto.generateKeyPairSync('ml-dsa-87');
    const subtree = metadata.mtcTrustAnchors[0].subtrees[0];
    const checkpoint = mycertutil.buildFidoMtcSubtreeCheckpoint({
        caId: Buffer.from(metadata.mtcTrustAnchors[0].caId, 'base64'), logNumber: subtree.logNumber,
        start: subtree.start, end: subtree.end, rootHash: Buffer.from(subtree.rootHash, 'base64')
    });
    md = clone(metadata);
    md.mtcTrustAnchors[0].subtrees[0].signature = crypto.sign(null, checkpoint, attacker.privateKey).toString('base64');
    await assert.rejects(verify(md), /checkpoint signature/);

    // no vendor root certificate to check the checkpoint against
    md = clone(metadata); md.attestationRootCertificates = [];
    await assert.rejects(verify(md), /checkpoint signature|attestationRootCertificates/);
});

test('Test 3g: in-band verification detects tampering and RP rejects mtc-debug with other formats', async () => {
    const { mtcConfig } = await getArtifacts();
    const { attObjBytes, clientDataHash } = await register(mtcConfig, { mtcDebug: true });
    const inband = (att) => fidoutils.verifyMTCAttestation(Buffer.isBuffer(att) ? att : encodeAtt(att), clientDataHash, null, { allowInBand: true });
    await inband(attObjBytes); // baseline

    // altered extension bytes break the signature, which covers authenticatorData
    let att = decodeAtt(attObjBytes);
    const ad = Buffer.from(att.authData); ad[ad.length - 3] ^= 1; att.authData = ad;
    await assert.rejects(inband(att), /./);

    // altered serial: a different leaf index/entry, so the in-band proof does not climb to the in-band root
    att = decodeAtt(attObjBytes); att.attStmt.mtcCert.serial = Number(att.attStmt.mtcCert.serial) + 1;
    await assert.rejects(inband(att), /Merkle inclusion proof/);

    // altered caId changes the leaf entry
    att = decodeAtt(attObjBytes); att.attStmt.mtcCert.caId = Buffer.from('0102030405', 'hex');
    await assert.rejects(inband(att), /Merkle inclusion proof/);

    // an authenticator that publishes a proof/root for some other key (internally inconsistent in-band data)
    const bad = Object.assign({}, mtcConfig, { rootHash: crypto.randomBytes(32).toString('hex') });
    const b = await register(bad, { mtcDebug: true });
    await assert.rejects(fidoutils.verifyMTCAttestation(b.attObjBytes, b.clientDataHash, null, { allowInBand: true }),
        /Merkle inclusion proof/);

    // RP rule: mtc-debug present with fmt != "mtc" must fail registration
    att = decodeAtt(attObjBytes); att.fmt = 'none'; att.attStmt = {};
    assert.throws(() => fidoutils.assertNoMTCDebugUnlessMTC(encodeAtt(att), {}), /only allowed with fmt "mtc"/);
    assert.throws(() => fidoutils.assertNoMTCDebugUnlessMTC(encodeAtt(att), { mtcDebug: {} }), /only allowed with fmt "mtc"/);
});

test('Test 3h: malformed attestation statements are rejected', async () => {
    const { mtcConfig, metadata } = await getArtifacts();
    const { attObjBytes, clientDataHash } = await register(mtcConfig, null);
    const verify = (att) => fidoutils.verifyMTCAttestation(encodeAtt(att), clientDataHash, metadata);
    const fresh = () => decodeAtt(attObjBytes);

    let att = fresh(); att.fmt = 'packed';
    await assert.rejects(verify(att), /fmt is not "mtc"/);
    att = fresh(); att.attStmt.x5c = [Buffer.alloc(1)];
    await assert.rejects(verify(att), /exactly alg, sig and mtcCert/);
    att = fresh(); delete att.attStmt.mtcCert;
    await assert.rejects(verify(att), /exactly alg, sig and mtcCert/);
    att = fresh(); att.attStmt.mtcCert.extra = 1;
    await assert.rejects(verify(att), /exactly caId and serial/);
    att = fresh(); att.attStmt.mtcCert.serial = -1;
    await assert.rejects(verify(att), /serial is not an unsigned 64-bit integer/);
    att = fresh(); att.attStmt.alg = -7;
    await assert.rejects(verify(att), /COSE_Key alg does not match/);
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, clientDataHash, metadata, { acceptableAlgs: [-50] }), /not acceptable/);
    await assert.rejects(fidoutils.verifyMTCAttestation(attObjBytes, Buffer.alloc(16), metadata), /clientDataHash must be 32 bytes/);
});
