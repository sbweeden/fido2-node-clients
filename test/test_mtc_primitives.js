// test/test_mtc_primitives.js
//
// Unit tests for the MTC (Merkle Tree Certificate) primitives in mycertutil.js and mykeyutil.js.
// Run with: node --test test/test_mtc_primitives.js   (or: npm run test:mtc-primitives)

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const cbor = require('cbor');
const fidoutils = require('../fidoutils.js');
const mycertutil = require('../mycertutil.js');
const mykeyutil = require('../mykeyutil.js');

function sha256(buf) {
    return crypto.createHash('sha256').update(buf).digest();
}

/*
 * Independent reference implementation of RFC 9162 §2.1.1 MTH() and §2.1.3.1 PATH(), written directly from the
 * RFC text (recursive definition, largest power of two smaller than n), used to cross-check the merkletreejs based
 * implementation in mycertutil.js.
 */
function largestPowerOfTwoLessThan(n) {
    let k = 1;
    while (k * 2 < n) {
        k *= 2;
    }
    return k;
}

function refMTH(leafHashes) {
    if (leafHashes.length === 1) {
        return leafHashes[0];
    }
    const k = largestPowerOfTwoLessThan(leafHashes.length);
    return sha256(Buffer.concat([Buffer.from([0x01]), refMTH(leafHashes.slice(0, k)), refMTH(leafHashes.slice(k))]));
}

function refPath(m, leafHashes) {
    const n = leafHashes.length;
    if (n === 1) {
        return [];
    }
    const k = largestPowerOfTwoLessThan(n);
    if (m < k) {
        return refPath(m, leafHashes.slice(0, k)).concat([refMTH(leafHashes.slice(k))]);
    }
    return refPath(m - k, leafHashes.slice(k)).concat([refMTH(leafHashes.slice(0, k))]);
}

function makeLeafHashes(n) {
    const result = [];
    for (let i = 0; i < n; i++) {
        result.push(mycertutil.computeFidoMtcLeafHash(Buffer.from("entry-" + i)));
    }
    return result;
}

// ---------------------------------------------------------------------------------------------
// FidoMtcSubtreeCheckpoint
// ---------------------------------------------------------------------------------------------
test('buildFidoMtcSubtreeCheckpoint: exact layout for a 5 byte caId (85 bytes)', () => {
    const caId = Buffer.from('83993f0101', 'hex');
    const rootHash = Buffer.alloc(32, 0xab);
    const cp = mycertutil.buildFidoMtcSubtreeCheckpoint({
        caId, logNumber: 0x0102, start: 0, end: 1024, rootHash
    });

    assert.equal(cp.length, 85);
    // domain separator: 30 ASCII chars + 2 zero bytes
    assert.equal(cp.subarray(0, 30).toString('ascii'), 'FIDO-MTC-SUBTREE-CHECKPOINT-V1');
    assert.deepEqual([...cp.subarray(30, 32)], [0, 0]);
    // caIdLen, caId
    assert.equal(cp.subarray(32, 34).toString('hex'), '0005');
    assert.equal(cp.subarray(34, 39).toString('hex'), '83993f0101');
    // logNumber, start, end
    assert.equal(cp.subarray(39, 41).toString('hex'), '0102');
    assert.equal(cp.subarray(41, 47).toString('hex'), '000000000000');
    assert.equal(cp.subarray(47, 53).toString('hex'), '000000000400');
    // rootHash
    assert.equal(cp.subarray(53, 85).toString('hex'), 'ab'.repeat(32));
});

test('buildFidoMtcSubtreeCheckpoint: size is 80 + len(caId) and accepts Uint8Array/bigint inputs', () => {
    const rootHash = new Uint8Array(32).fill(1);
    for (const n of [0, 1, 5, 20]) {
        const cp = mycertutil.buildFidoMtcSubtreeCheckpoint({
            caId: new Uint8Array(n).fill(7), logNumber: 65535, start: 5n, end: (1n << 48n) - 1n, rootHash
        });
        assert.equal(cp.length, 80 + n);
    }
    const cp = mycertutil.buildFidoMtcSubtreeCheckpoint({
        caId: [1, 2, 3], logNumber: 1, start: 0, end: (1n << 48n) - 1n, rootHash
    });
    assert.equal(cp.subarray(cp.length - 32 - 6, cp.length - 32).toString('hex'), 'ffffffffffff');
});

test('buildFidoMtcSubtreeCheckpoint: rejects invalid inputs', () => {
    const base = { caId: Buffer.from('0102030405', 'hex'), logNumber: 0, start: 0, end: 1, rootHash: Buffer.alloc(32) };
    assert.doesNotThrow(() => mycertutil.buildFidoMtcSubtreeCheckpoint(base));
    assert.throws(() => mycertutil.buildFidoMtcSubtreeCheckpoint({ ...base, rootHash: Buffer.alloc(31) }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcSubtreeCheckpoint({ ...base, rootHash: 'abcd' }), TypeError);
    assert.throws(() => mycertutil.buildFidoMtcSubtreeCheckpoint({ ...base, logNumber: 65536 }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcSubtreeCheckpoint({ ...base, logNumber: -1 }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcSubtreeCheckpoint({ ...base, start: 1, end: 1 }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcSubtreeCheckpoint({ ...base, start: 2, end: 1 }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcSubtreeCheckpoint({ ...base, end: 1n << 48n }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcSubtreeCheckpoint({ ...base, caId: null }), TypeError);
    assert.throws(() => mycertutil.buildFidoMtcSubtreeCheckpoint({ ...base, start: 1.5 }), RangeError);
});

// ---------------------------------------------------------------------------------------------
// FidoMtcLogEntry and leaf hash
// ---------------------------------------------------------------------------------------------
const ENTRY_INPUT = {
    caId: Buffer.from('83993f0101', 'hex'),
    serial: (3n << 48n) | 7n,
    notBefore: 1700000000,
    aaguid: Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'),
    coseKeyBytes: Buffer.from('a301072e3830a0', 'hex') // content is opaque to the serializer
};

test('buildFidoMtcLogEntry: exact layout with defaults (fw=null, ext empty, notAfter sentinel)', () => {
    const entry = mycertutil.buildFidoMtcLogEntry(ENTRY_INPUT);
    const expected = Buffer.concat([
        Buffer.from('0005', 'hex'),
        Buffer.from('83993f0101', 'hex'),
        Buffer.from('0003000000000007', 'hex'),       // serial
        Buffer.from('000000006553f100', 'hex'),       // notBefore 1700000000
        Buffer.from('0000003afff4417f', 'hex'),       // notAfter 253402300799
        Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'),
        Buffer.from('00', 'hex'),                     // no firmware version
        sha256(ENTRY_INPUT.coseKeyBytes),
        Buffer.from('0000', 'hex')                    // no extensions
    ]);
    assert.equal(entry.toString('hex'), expected.toString('hex'));
    // 76 + len(caId) + 1 fw byte + 0 ext bytes
    assert.equal(entry.length, 76 + 5 + 1);
});

test('buildFidoMtcLogEntry: firmwareVersion, explicit notAfter and extensions', () => {
    const ext = Buffer.from('deadbeef', 'hex');
    const entry = mycertutil.buildFidoMtcLogEntry({
        ...ENTRY_INPUT, firmwareVersion: 0x0102030405, notAfter: 1800000000, extensions: ext
    });
    // 76 + N + 9 (fw) + M
    assert.equal(entry.length, 76 + 5 + 9 + 4);

    const fwOffset = 2 + 5 + 8 + 8 + 8 + 16;
    assert.equal(entry.subarray(fwOffset - 16 - 8, fwOffset - 16).toString('hex'), '00000000' + (1800000000).toString(16)); // notAfter
    assert.equal(entry.subarray(fwOffset, fwOffset + 9).toString('hex'), '010000000102030405');
    assert.equal(entry.subarray(fwOffset + 9, fwOffset + 41).toString('hex'), sha256(ENTRY_INPUT.coseKeyBytes).toString('hex'));
    assert.equal(entry.subarray(fwOffset + 41).toString('hex'), '0004deadbeef');
});

test('buildFidoMtcLogEntry: firmwareVersion 0 is distinct from no firmwareVersion', () => {
    const none = mycertutil.buildFidoMtcLogEntry(ENTRY_INPUT);
    const zero = mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, firmwareVersion: 0 });
    assert.equal(zero.length, none.length + 8);
    assert.notEqual(zero.toString('hex'), none.toString('hex'));
});

test('buildFidoMtcLogEntry: accepts max uint64 serial as bigint and rejects out of range values', () => {
    const entry = mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, serial: (1n << 64n) - 1n });
    assert.equal(entry.subarray(7, 15).toString('hex'), 'ffffffffffffffff');

    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, serial: 1n << 64n }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, serial: -1 }), RangeError);
    // numbers beyond the safe integer range would silently lose precision
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, serial: 2 ** 60 }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, serial: "7" }), TypeError);
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, notBefore: undefined }), TypeError);
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, firmwareVersion: -1 }), RangeError);
});

test('buildFidoMtcLogEntry: rejects invalid aaguid, coseKeyBytes, extensions', () => {
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, aaguid: Buffer.alloc(15) }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, aaguid: undefined }), TypeError);
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, coseKeyBytes: Buffer.alloc(0) }), RangeError);
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, coseKeyBytes: undefined }), TypeError);
    assert.throws(() => mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, extensions: Buffer.alloc(65536) }), RangeError);
});

test('buildFidoMtcLogEntry: every committed field changes the entry', () => {
    const base = mycertutil.buildFidoMtcLogEntry(ENTRY_INPUT).toString('hex');
    const variants = [
        { caId: Buffer.from('83993f0102', 'hex') },
        { serial: ENTRY_INPUT.serial + 1n },
        { notBefore: ENTRY_INPUT.notBefore + 1 },
        { notAfter: 1900000000 },
        { aaguid: Buffer.alloc(16, 9) },
        { firmwareVersion: 1 },
        { coseKeyBytes: Buffer.from('a301072e3830a1', 'hex') },
        { extensions: Buffer.from('00', 'hex') }
    ];
    for (const v of variants) {
        assert.notEqual(mycertutil.buildFidoMtcLogEntry({ ...ENTRY_INPUT, ...v }).toString('hex'), base, JSON.stringify(Object.keys(v)));
    }
});

test('computeFidoMtcLeafHash: SHA-256(0x00 || entry), with known SHA-256 vectors', () => {
    // SHA-256(0x00) - empty entry
    assert.equal(mycertutil.computeFidoMtcLeafHash(Buffer.alloc(0)).toString('hex'),
        '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d');

    const entry = mycertutil.buildFidoMtcLogEntry(ENTRY_INPUT);
    const h = mycertutil.computeFidoMtcLeafHash(entry);
    assert.equal(h.length, 32);
    assert.equal(h.toString('hex'), sha256(Buffer.concat([Buffer.from([0]), entry])).toString('hex'));
    // domain separation: must differ from plain SHA-256 of the entry
    assert.notEqual(h.toString('hex'), sha256(entry).toString('hex'));
    // accepts Uint8Array too
    assert.equal(mycertutil.computeFidoMtcLeafHash(new Uint8Array(entry)).toString('hex'), h.toString('hex'));
    assert.throws(() => mycertutil.computeFidoMtcLeafHash("not bytes"), TypeError);
});

// ---------------------------------------------------------------------------------------------
// RFC 9162 Merkle tree
// ---------------------------------------------------------------------------------------------

// Well known Merkle tree test vectors from the Certificate Transparency reference implementation
// (originally RFC 6962 era; the leaf/interior hashing is identical in RFC 9162 §2.1.1).
const CT_LEAF_INPUTS = [
    '', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'
];
const CT_ROOTS = [
    '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
    'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
    'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
    '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
    'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
    '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328'
];

test('buildRFC9162MerkleTree: matches known CT root hashes for tree sizes 1..8', () => {
    const leafHashes = CT_LEAF_INPUTS.map((h) => mycertutil.computeFidoMtcLeafHash(Buffer.from(h, 'hex')));
    for (let n = 1; n <= 8; n++) {
        const tree = mycertutil.buildRFC9162MerkleTree(leafHashes.slice(0, n));
        assert.equal(tree.leafCount, n);
        assert.equal(tree.rootHash.toString('hex'), CT_ROOTS[n - 1], 'root for size ' + n);
    }
});

test('buildRFC9162MerkleTree: matches the RFC 9162 reference MTH/PATH for sizes 1..40', () => {
    for (let n = 1; n <= 40; n++) {
        const leafHashes = makeLeafHashes(n);
        const tree = mycertutil.buildRFC9162MerkleTree(leafHashes);
        assert.equal(tree.rootHash.toString('hex'), refMTH(leafHashes).toString('hex'), 'root for size ' + n);
        for (let i = 0; i < n; i++) {
            const proof = tree.getProof(i);
            const expected = refPath(i, leafHashes);
            assert.deepEqual(proof.map((p) => p.toString('hex')), expected.map((p) => p.toString('hex')),
                'proof for index ' + i + ' of ' + n);
        }
    }
});

test('buildRFC9162MerkleTree: single leaf tree has the leaf hash as root and an empty proof', () => {
    const [lh] = makeLeafHashes(1);
    const tree = mycertutil.buildRFC9162MerkleTree([lh]);
    assert.equal(tree.rootHash.toString('hex'), lh.toString('hex'));
    assert.deepEqual(tree.getProof(0), []);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ leafHash: lh, proof: [], leafIndex: 0, start: 0, end: 1, rootHash: lh }), true);
});

test('buildRFC9162MerkleTree: two leaf tree uses the 0x01 interior node prefix', () => {
    const [a, b] = makeLeafHashes(2);
    const tree = mycertutil.buildRFC9162MerkleTree([a, b]);
    assert.equal(tree.rootHash.toString('hex'),
        sha256(Buffer.concat([Buffer.from([1]), a, b])).toString('hex'));
    assert.deepEqual(tree.getProof(0).map((p) => p.toString('hex')), [b.toString('hex')]);
    assert.deepEqual(tree.getProof(1).map((p) => p.toString('hex')), [a.toString('hex')]);
});

test('buildRFC9162MerkleTree: rejects invalid inputs', () => {
    assert.throws(() => mycertutil.buildRFC9162MerkleTree([]), TypeError);
    assert.throws(() => mycertutil.buildRFC9162MerkleTree(null), TypeError);
    assert.throws(() => mycertutil.buildRFC9162MerkleTree([Buffer.alloc(31)]), RangeError);
    assert.throws(() => mycertutil.buildRFC9162MerkleTree(["abc"]), TypeError);

    const tree = mycertutil.buildRFC9162MerkleTree(makeLeafHashes(3));
    assert.throws(() => tree.getProof(-1), RangeError);
    assert.throws(() => tree.getProof(3), RangeError);
    assert.throws(() => tree.getProof(1.5), RangeError);
});

test('buildRFC9162MerkleTree: duplicate leaf hashes still yield the proof for the requested index', () => {
    const [a, b] = makeLeafHashes(2);
    const leaves = [a, b, a, b, a];
    const tree = mycertutil.buildRFC9162MerkleTree(leaves);
    for (let i = 0; i < leaves.length; i++) {
        assert.equal(mycertutil.verifyRFC9162MerkleProof({
            leafHash: leaves[i], proof: tree.getProof(i), leafIndex: i, start: 0, end: leaves.length, rootHash: tree.rootHash
        }), true, 'index ' + i);
    }
});

// ---------------------------------------------------------------------------------------------
// verifyRFC9162MerkleProof
// ---------------------------------------------------------------------------------------------
test('verifyRFC9162MerkleProof: accepts every valid proof for sizes 1..40', () => {
    for (let n = 1; n <= 40; n++) {
        const leafHashes = makeLeafHashes(n);
        const tree = mycertutil.buildRFC9162MerkleTree(leafHashes);
        for (let i = 0; i < n; i++) {
            assert.equal(mycertutil.verifyRFC9162MerkleProof({
                leafHash: leafHashes[i], proof: tree.getProof(i), leafIndex: i, start: 0, end: n, rootHash: tree.rootHash
            }), true, 'size ' + n + ' index ' + i);
        }
    }
});

test('verifyRFC9162MerkleProof: handles a subtree [start, end) with absolute leaf indexes', () => {
    // a subtree of 6 leaves covering absolute indexes [1024, 1030)
    const start = 1024;
    const leafHashes = makeLeafHashes(6);
    const tree = mycertutil.buildRFC9162MerkleTree(leafHashes);
    for (let i = 0; i < 6; i++) {
        assert.equal(mycertutil.verifyRFC9162MerkleProof({
            leafHash: leafHashes[i], proof: tree.getProof(i), leafIndex: start + i, start, end: start + 6, rootHash: tree.rootHash
        }), true);
    }
    // the same proof presented at a different absolute index must fail
    assert.equal(mycertutil.verifyRFC9162MerkleProof({
        leafHash: leafHashes[2], proof: tree.getProof(2), leafIndex: start + 3, start, end: start + 6, rootHash: tree.rootHash
    }), false);
    // start defaults to 0
    assert.equal(mycertutil.verifyRFC9162MerkleProof({
        leafHash: leafHashes[2], proof: tree.getProof(2), leafIndex: 2, end: 6, rootHash: tree.rootHash
    }), true);
});

test('verifyRFC9162MerkleProof: supports bigint indexes up to 2^48', () => {
    const leafHashes = makeLeafHashes(5);
    const tree = mycertutil.buildRFC9162MerkleTree(leafHashes);
    const start = (1n << 47n);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({
        leafHash: leafHashes[4], proof: tree.getProof(4), leafIndex: start + 4n, start, end: start + 5n, rootHash: tree.rootHash
    }), true);
});

test('verifyRFC9162MerkleProof: rejects tampering', () => {
    const n = 11;
    const leafHashes = makeLeafHashes(n);
    const tree = mycertutil.buildRFC9162MerkleTree(leafHashes);
    const idx = 6;
    const good = { leafHash: leafHashes[idx], proof: tree.getProof(idx), leafIndex: idx, start: 0, end: n, rootHash: tree.rootHash };
    assert.equal(mycertutil.verifyRFC9162MerkleProof(good), true);

    const flip = (buf) => { const c = Buffer.from(buf); c[0] ^= 0x01; return c; };

    // wrong leaf, wrong root
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, leafHash: flip(good.leafHash) }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, leafHash: leafHashes[idx + 1] }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, rootHash: flip(good.rootHash) }), false);

    // each proof element tampered
    for (let i = 0; i < good.proof.length; i++) {
        const proof = good.proof.map((p, j) => (i === j ? flip(p) : p));
        assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, proof }), false, 'tampered proof element ' + i);
    }

    // wrong index / range
    for (let i = 0; i < n; i++) {
        if (i !== idx) {
            assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, leafIndex: i }), false, 'wrong index ' + i);
        }
    }
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, leafIndex: n }), false);
    // note: the tree size is not separately authenticated by the proof - the root hash is what binds the content
    // a tree size that implies a different proof length is rejected
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, end: idx + 1 }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, end: idx }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, start: 1 }), false);

    // truncated, extended, and reordered proofs
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, proof: good.proof.slice(0, -1) }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, proof: good.proof.concat([good.proof[0]]) }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, proof: [...good.proof].reverse() }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...good, proof: [] }), false);
});

test('verifyRFC9162MerkleProof: a leaf hash cannot be passed off as an interior node (second preimage)', () => {
    const leafHashes = makeLeafHashes(4);
    const tree = mycertutil.buildRFC9162MerkleTree(leafHashes);
    // forge a "leaf" whose hash equals an interior node: SHA-256(0x00 || 0x01 || a || b) != SHA-256(0x01 || a || b)
    const forgedEntry = Buffer.concat([Buffer.from([0x01]), leafHashes[0], leafHashes[1]]);
    const forgedLeaf = mycertutil.computeFidoMtcLeafHash(forgedEntry);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({
        leafHash: forgedLeaf, proof: [tree.getProof(0)[1]], leafIndex: 0, start: 0, end: 2, rootHash: tree.rootHash
    }), false);
});

test('verifyRFC9162MerkleProof: returns false (does not throw) for malformed input', () => {
    const [lh] = makeLeafHashes(1);
    const ok = { leafHash: lh, proof: [], leafIndex: 0, start: 0, end: 1, rootHash: lh };
    assert.equal(mycertutil.verifyRFC9162MerkleProof(ok), true);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, leafHash: Buffer.alloc(31) }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, rootHash: Buffer.alloc(33) }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, rootHash: null }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, leafHash: undefined }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, proof: null }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, proof: [Buffer.alloc(31)] }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, proof: ["abc"] }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, leafIndex: "x" }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, leafIndex: 1.5 }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, end: undefined }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, end: 0 }), false);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({ ...ok, start: -1 }), false);
});

test('MTC end to end: log entries -> leaf hashes -> tree -> verified proof and checkpoint', () => {
    const caId = Buffer.from('83993f0101', 'hex');
    const logNumber = 2;
    const coseKeys = [0, 1, 2, 3, 4].map((i) => Buffer.from('a30107032e20' + i.toString(16).padStart(2, '0'), 'hex'));
    const entries = coseKeys.map((k, i) => mycertutil.buildFidoMtcLogEntry({
        caId, serial: (BigInt(logNumber) << 48n) | BigInt(i), notBefore: 1700000000 + i,
        aaguid: Buffer.alloc(16, 0x11), coseKeyBytes: k
    }));
    const leafHashes = entries.map((e) => mycertutil.computeFidoMtcLeafHash(e));
    const tree = mycertutil.buildRFC9162MerkleTree(leafHashes);

    const checkpoint = mycertutil.buildFidoMtcSubtreeCheckpoint({
        caId, logNumber, start: 0, end: 1024, rootHash: tree.rootHash
    });
    assert.equal(checkpoint.length, 85);
    assert.equal(checkpoint.subarray(53).toString('hex'), tree.rootHash.toString('hex'));

    // leaf index is derived from the serial exactly as a relying party would
    const serial = (BigInt(logNumber) << 48n) | 3n;
    const leafIndex = serial & 0xFFFFFFFFFFFFn;
    assert.equal(leafIndex, 3n);
    assert.equal(mycertutil.verifyRFC9162MerkleProof({
        leafHash: leafHashes[3], proof: tree.getProof(3), leafIndex, start: 0, end: 5, rootHash: tree.rootHash
    }), true);
});

// ---------------------------------------------------------------------------------------------
// mykeyutil.js: native encoding utilities
// ---------------------------------------------------------------------------------------------
test('mykeyutil encoding utilities: hex', () => {
    assert.equal(mykeyutil.toHex(Buffer.from([0, 1, 0xab, 0xff])), '0001abff');
    assert.equal(mykeyutil.toHex([0, 1, 0xab, 0xff]), '0001abff');
    assert.equal(mykeyutil.toHex(new Uint8Array([0xde, 0xad])), 'dead');
    assert.equal(mykeyutil.toHex(new Uint8Array([1, 2, 3, 4]).buffer), '01020304');
    assert.equal(mykeyutil.toHex(new Uint8Array([9, 1, 2, 3]).subarray(1, 3)), '0102');
    assert.equal(mykeyutil.toHex(new Uint8Array(0)), '');
    assert.deepEqual([...mykeyutil.fromHex('0001ABff')], [0, 1, 0xab, 0xff]);
    assert.equal(mykeyutil.fromHex('').length, 0);
    assert.throws(() => mykeyutil.fromHex('abc'), TypeError);
    assert.throws(() => mykeyutil.fromHex('zz'), TypeError);
    assert.throws(() => mykeyutil.fromHex(null), TypeError);
    assert.throws(() => mykeyutil.toHex("abc"), TypeError);
});

test('mykeyutil encoding utilities: base64url and base64', () => {
    // 0xfb 0xff 0xfe exercises the +/ vs -_ alphabet difference and padding
    const bytes = Buffer.from([0xfb, 0xff, 0xfe, 0x01]);
    assert.equal(mykeyutil.toBase64(bytes), '+//+AQ==');
    assert.equal(mykeyutil.toBase64Url(bytes), '-__-AQ');
    assert.deepEqual([...mykeyutil.fromBase64('+//+AQ==')], [...bytes]);
    assert.deepEqual([...mykeyutil.fromBase64Url('-__-AQ')], [...bytes]);
    // base64url decoding tolerates optional padding? we only accept the unpadded alphabet
    assert.throws(() => mykeyutil.fromBase64Url('-__-AQ=='), TypeError);
    assert.throws(() => mykeyutil.fromBase64Url('+//+AQ'), TypeError);
    assert.throws(() => mykeyutil.fromBase64('-__-AQ=='), TypeError);
    assert.throws(() => mykeyutil.fromBase64(123), TypeError);
    assert.equal(mykeyutil.toBase64Url(new Uint8Array(0)), '');

    // round trip and agreement with the existing jsrsasign-based helpers
    const random = crypto.randomBytes(37);
    assert.deepEqual([...mykeyutil.fromBase64Url(mykeyutil.toBase64Url(random))], [...random]);
    assert.deepEqual([...mykeyutil.fromBase64(mykeyutil.toBase64(random))], [...random]);
    assert.equal(mykeyutil.toBase64Url(random), random.toString('base64url'));
});

// ---------------------------------------------------------------------------------------------
// mykeyutil.js: ML-DSA X.509 SPKI support in getPublicKeyFromCertBytes
// ---------------------------------------------------------------------------------------------
const MLDSA_ALGS = [
    { name: 'ml-dsa-44', algId: -48, oid: '2.16.840.1.101.3.4.3.17' },
    { name: 'ml-dsa-65', algId: -49, oid: '2.16.840.1.101.3.4.3.18' },
    { name: 'ml-dsa-87', algId: -50, oid: '2.16.840.1.101.3.4.3.19' }
];

/*
 * Creates a self-signed X.509 certificate with an ML-DSA key using the openssl CLI (3.5+), returning
 * { certDER, privateKey (node KeyObject) } or null if openssl cannot do ML-DSA on this machine.
 */
function makeMLDSACert(algName) {
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const { execFileSync } = require('node:child_process');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mtc-prim-'));
    try {
        const keyFile = path.join(dir, 'key.pem');
        const certFile = path.join(dir, 'cert.der');
        execFileSync('openssl', ['genpkey', '-algorithm', algName.replaceAll('-', ''), '-out', keyFile], { stdio: 'pipe' });
        execFileSync('openssl', ['req', '-x509', '-new', '-key', keyFile, '-subj', '/CN=mtc-test', '-days', '2',
            '-outform', 'DER', '-out', certFile], { stdio: 'pipe' });
        return {
            certDER: fs.readFileSync(certFile),
            privateKey: crypto.createPrivateKey(fs.readFileSync(keyFile))
        };
    } catch (e) {
        return null;
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

for (const { name, algId, oid } of MLDSA_ALGS) {
    test('getPublicKeyFromCertBytes: ' + name + ' certificate SPKI (alg ' + algId + ')', async (t) => {
        const generated = makeMLDSACert(name);
        if (generated == null) {
            t.skip('openssl with ML-DSA support is not available');
            return;
        }

        const parsed = mycertutil.parseCertificate([...generated.certDER]);
        assert.equal(parsed.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm, oid);

        const pk = await mykeyutil.getPublicKeyFromCertBytes([...generated.certDER], algId);
        assert.equal(pk.type, 'public');
        assert.equal(pk.algorithm.name.toLowerCase(), name);

        // the imported key must verify a signature made with the matching private key
        const data = Buffer.from('verification data');
        const sig = crypto.sign(null, data, generated.privateKey);
        assert.equal(await mykeyutil.validateSignature(algId, pk, [...data], [...sig]), true);
        const badData = Buffer.from('verification datb');
        assert.equal(await mykeyutil.validateSignature(algId, pk, [...badData], [...sig]), false);
    });
}

// ---------------------------------------------------------------------------------------------
// fidoutils.js: Authenticator MTC Attestation Statement Generation (Task 3)
// ---------------------------------------------------------------------------------------------
test('processCredentialCreationOptions: creates valid fmt: "mtc" attestation statement', async () => {
    await fidoutils.init();

    // Test with ML-DSA-44 batch key
    const batchKp = await mykeyutil.generateKeypair(-48);
    const batchPrvHex = await mykeyutil.getPrivateKeyHex(batchKp);
    const batchPubHex = await mykeyutil.getPublicKeyHex(batchKp);
    const batchPubKey = await mykeyutil.getPublicKeyFromHex(-48, batchPubHex);

    const mtcConfig = {
        aaguid: "12345678-abcd-5678-ef01-567812345678",
        caId: "83993f0101",
        serial: 281474976710656,
        alg: -48,
        privateKeyHex: batchPrvHex
    };

    fidoutils.setFidoUtilsConfig({
        origin: "https://localhost:8443",
        encryptionPassphrase: "test",
        mtc: mtcConfig
    });

    const cco = {
        publicKey: {
            rp: { id: "localhost", name: "Test RP" },
            user: { id: [1, 2, 3, 4], name: "alice", displayName: "Alice" },
            challenge: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31],
            pubKeyCredParams: [{ alg: -7, type: "public-key" }]
        }
    };

    const res = await fidoutils.processCredentialCreationOptions(cco, "mtc");
    assert.ok(res.spkc);
    assert.ok(res.spkc.response);
    assert.ok(res.spkc.response.attestationObject);
    assert.ok(res.spkc.response.clientDataJSON);

    // Decode attestationObject
    const attObjBytes = mykeyutil.fromBase64Url(res.spkc.response.attestationObject);
    const ab = attObjBytes.buffer.slice(attObjBytes.byteOffset, attObjBytes.byteOffset + attObjBytes.byteLength);
    const attObj = cbor.decode(ab);

    // Check CDDL structure per WebAuthn Level 4 §8.10
    assert.equal(attObj.fmt, "mtc");
    assert.equal(attObj.attStmt.alg, -48);
    assert.ok(attObj.attStmt.sig);
    assert.equal(attObj.attStmt.sig.length, 2420);
    assert.ok(attObj.attStmt.mtcCert);
    assert.equal(Buffer.from(attObj.attStmt.mtcCert.caId).toString("hex"), "83993f0101");
    assert.equal(attObj.attStmt.mtcCert.serial, 281474976710656);

    // Verify attStmt.sig over authenticatorData || SHA-256(clientDataJSON)
    const clientDataJSONBuf = mykeyutil.fromBase64Url(res.spkc.response.clientDataJSON);
    const clientDataHash = crypto.createHash("sha256").update(clientDataJSONBuf).digest();
    const authDataBuf = Buffer.from(attObj.authData);
    const verificationData = Buffer.concat([authDataBuf, clientDataHash]);

    const isSigValid = await mykeyutil.validateSignature(
        attObj.attStmt.alg,
        batchPubKey,
        verificationData,
        attObj.attStmt.sig
    );
    assert.equal(isSigValid, true);

    // Verify tampering with verificationData causes signature validation failure
    const tamperedData = Buffer.concat([authDataBuf, clientDataHash]);
    tamperedData[0] ^= 0x01;
    assert.equal(await mykeyutil.validateSignature(attObj.attStmt.alg, batchPubKey, tamperedData, attObj.attStmt.sig), false);

    // Verify authData contains correct AAGUID
    const unpacked = fidoutils.unpackAuthData(authDataBuf);
    assert.equal(unpacked.status, true);
    assert.equal(Buffer.from(unpacked.attestedCredData.aaguid).toString("hex"), mtcConfig.aaguid.replace(/-/g, ""));
});

test('processCredentialCreationOptions: supports ML-DSA-87 (alg -50) batch keys for MTC', async () => {
    await fidoutils.init();

    const batchKp = await mykeyutil.generateKeypair(-50);
    const batchPrvHex = await mykeyutil.getPrivateKeyHex(batchKp);
    const batchPubHex = await mykeyutil.getPublicKeyHex(batchKp);
    const batchPubKey = await mykeyutil.getPublicKeyFromHex(-50, batchPubHex);

    const mtcConfig = {
        aaguid: "abcdef01-2345-6789-abcd-ef0123456789",
        caId: "010203040506",
        serial: 100,
        alg: -50,
        privateKeyHex: batchPrvHex
    };

    fidoutils.setFidoUtilsConfig({
        origin: "https://localhost:8443",
        encryptionPassphrase: "test",
        mtc: mtcConfig
    });

    const cco = {
        publicKey: {
            rp: { id: "localhost", name: "Test RP" },
            user: { id: [5, 6, 7, 8], name: "bob", displayName: "Bob" },
            challenge: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            pubKeyCredParams: [{ alg: -7, type: "public-key" }]
        }
    };

    const res = await fidoutils.processCredentialCreationOptions(cco, "mtc");
    const attObjBytes = mykeyutil.fromBase64Url(res.spkc.response.attestationObject);
    const ab = attObjBytes.buffer.slice(attObjBytes.byteOffset, attObjBytes.byteOffset + attObjBytes.byteLength);
    const attObj = cbor.decode(ab);

    assert.equal(attObj.fmt, "mtc");
    assert.equal(attObj.attStmt.alg, -50);
    assert.equal(attObj.attStmt.sig.length, 4627);
    assert.equal(Buffer.from(attObj.attStmt.mtcCert.caId).toString("hex"), "010203040506");
    assert.equal(attObj.attStmt.mtcCert.serial, 100);

    const clientDataJSONBuf = mykeyutil.fromBase64Url(res.spkc.response.clientDataJSON);
    const clientDataHash = crypto.createHash("sha256").update(clientDataJSONBuf).digest();
    const verificationData = Buffer.concat([Buffer.from(attObj.authData), clientDataHash]);

    const isSigValid = await mykeyutil.validateSignature(
        attObj.attStmt.alg,
        batchPubKey,
        verificationData,
        attObj.attStmt.sig
    );
    assert.equal(isSigValid, true);
});

// ---------------------------------------------------------------------------------------------
// fidoutils.js: mtcDebug / mtc-debug in-band diagnostic extension (Task 4)
// ---------------------------------------------------------------------------------------------
async function registerWithMtcDebug(mtcExtra, extensions, attestation, fmt = "mtc") {
    await fidoutils.init();
    const batchKp = await mykeyutil.generateKeypair(-48);
    const batchPrvHex = await mykeyutil.getPrivateKeyHex(batchKp);
    const batchPubKey = await mykeyutil.getPublicKeyFromHex(-48, await mykeyutil.getPublicKeyHex(batchKp));
    const coseKeyBytes = cbor.encodeCanonical(new Map([[1, 7], [3, -48], [-1, Buffer.from(await mykeyutil.getPublicKeyHex(batchKp), 'hex')]]));

    const mtcConfig = Object.assign({
        aaguid: "12345678-abcd-5678-ef01-567812345678",
        caId: "83993f0101",
        serial: 281474976710656,
        alg: -48,
        privateKeyHex: batchPrvHex,
        coseKey: coseKeyBytes.toString('hex')
    }, mtcExtra);
    fidoutils.setFidoUtilsConfig({ origin: "https://localhost:8443", encryptionPassphrase: "test", mtc: mtcConfig });

    const cco = {
        publicKey: {
            rp: { id: "localhost", name: "Test RP" },
            user: { id: [1, 2, 3, 4], name: "alice", displayName: "Alice" },
            challenge: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
            pubKeyCredParams: [{ alg: -7, type: "public-key" }]
        }
    };
    if (extensions) cco.publicKey.extensions = extensions;
    if (attestation) cco.publicKey.attestation = attestation;

    const res = await fidoutils.processCredentialCreationOptions(cco, fmt);
    const attObjBytes = mykeyutil.fromBase64Url(res.spkc.response.attestationObject);
    const attObj = cbor.decode(attObjBytes.buffer.slice(attObjBytes.byteOffset, attObjBytes.byteOffset + attObjBytes.byteLength));
    return { res, attObj, coseKeyBytes, batchPubKey, mtcConfig };
}

test('mtcDebug: authenticatorData carries mtc-debug (ED flag) and signature still verifies', async () => {
    const proof = crypto.randomBytes(320);
    const rootHash = crypto.randomBytes(32);
    const { res, attObj, coseKeyBytes, batchPubKey } = await registerWithMtcDebug({
        notBefore: 1767225600, notAfter: 253402300799, firmwareVersion: 332805,
        mtcProof: proof.toString('hex'), rootHash: rootHash.toString('hex'), deviceSerial: "SN-1"
    }, { mtcDebug: true });

    const authData = Buffer.from(attObj.authData);
    assert.equal(authData[32] & 0x80, 0x80);
    assert.equal(authData[32] & 0x40, 0x40);

    const unpacked = fidoutils.unpackAuthData(authData);
    assert.equal(unpacked.status, true);
    const ext = unpacked.extensions["mtc-debug"];
    assert.ok(ext);
    assert.deepEqual(Buffer.from(ext.pubKey), coseKeyBytes);
    assert.equal(ext.notBefore, 1767225600);
    assert.equal(ext.notAfter, 253402300799);
    assert.equal(ext.firmwareVersion, 332805);
    assert.deepEqual(Buffer.from(ext.mtcProof), proof);
    assert.deepEqual(Buffer.from(ext.rootHash), rootHash);
    // enterprise attestation not granted, so deviceSerial must be omitted
    assert.equal(ext.deviceSerial, undefined);

    // attStmt.sig covers authData including the extension bytes
    const clientDataHash = crypto.createHash("sha256").update(mykeyutil.fromBase64Url(res.spkc.response.clientDataJSON)).digest();
    assert.equal(await mykeyutil.validateSignature(-48, batchPubKey, Buffer.concat([authData, clientDataHash]), attObj.attStmt.sig), true);

    // client extension output uses base64url strings for the ArrayBuffer members
    const out = res.spkc.getClientExtensionResults.mtcDebug;
    assert.equal(out.pubKey, coseKeyBytes.toString('base64url'));
    assert.equal(out.mtcProof, proof.toString('base64url'));
    assert.equal(out.rootHash, rootHash.toString('base64url'));
    assert.equal(out.notBefore, 1767225600);
    assert.equal(out.notAfter, 253402300799);
    assert.equal(out.firmwareVersion, 332805);
    assert.equal(out.deviceSerial, undefined);
});

test('mtcDebug: deviceSerial only with enterprise attestation; optional fields omitted when unknown', async () => {
    const { res, attObj } = await registerWithMtcDebug({ deviceSerial: "SN-00142857" }, { mtcDebug: true }, "enterprise");
    const ext = fidoutils.unpackAuthData(Buffer.from(attObj.authData)).extensions["mtc-debug"];
    assert.equal(ext.deviceSerial, "SN-00142857");
    assert.deepEqual(Object.keys(ext).sort(), ["deviceSerial", "pubKey"]);
    assert.equal(res.spkc.getClientExtensionResults.mtcDebug.deviceSerial, "SN-00142857");
});

test('mtcDebug: ignored unless requested and unless fmt is "mtc"', async () => {
    // not requested
    let r = await registerWithMtcDebug({}, null);
    assert.equal(Buffer.from(r.attObj.authData)[32] & 0x80, 0);
    assert.deepEqual(r.res.spkc.getClientExtensionResults, {});
    r = await registerWithMtcDebug({}, { mtcDebug: false });
    assert.equal(Buffer.from(r.attObj.authData)[32] & 0x80, 0);

    // requested, but fmt is not "mtc" -> input ignored, no output
    r = await registerWithMtcDebug({}, { mtcDebug: true }, undefined, "none");
    assert.equal(Buffer.from(r.attObj.authData)[32] & 0x80, 0);
    assert.deepEqual(r.res.spkc.getClientExtensionResults, {});
});

test('mtcDebug: requires coseKey in the mtc configuration', async () => {
    await assert.rejects(
        registerWithMtcDebug({ coseKey: null }, { mtcDebug: true }),
        /coseKey/
    );
});

// ---------------------------------------------------------------------------------------------
// fidoutils.js: Relying Party MTC attestation verification (Task 5)
// ---------------------------------------------------------------------------------------------
const MTC_CA_ID = Buffer.from('83993f0101', 'hex');
const MTC_AAGUID = '12345678-abcd-5678-ef01-567812345678';
const MTC_LOG_NUMBER = 1;
const MTC_LEAF_INDEX = 5;
const MTC_SERIAL = (MTC_LOG_NUMBER * 2 ** 48) + MTC_LEAF_INDEX;
const MTC_NOT_BEFORE = 1767225600;
const MTC_NOT_AFTER = 253402300799;

/*
 * Builds a complete fixture: an ML-DSA-87 root CA certificate, an 8 leaf tree with the batch key at index 5, a signed
 * checkpoint, an MDS style metadata statement, and a registration made by the emulated authenticator.
 * Returns null if openssl cannot create an ML-DSA-87 certificate.
 */
async function makeMtcFixture(batchAlg = -48, extensions = { mtcDebug: true }) {
    await fidoutils.init();
    const root = makeMLDSACert('ml-dsa-87');
    if (root == null) return null;

    const batchKp = await mykeyutil.generateKeypair(batchAlg);
    const batchPubBytes = Buffer.from((await mykeyutil.getPublicKeyCOSE(batchAlg, batchKp))["-1"]); // raw ML-DSA public key
    const coseKeyBytes = cbor.encodeCanonical(new Map([[1, 7], [3, batchAlg], [-1, batchPubBytes]]));
    const aaguidBytes = Buffer.from(MTC_AAGUID.replaceAll('-', ''), 'hex');

    const leafOf = (i) => mycertutil.computeFidoMtcLeafHash(Buffer.from('placeholder-' + i));
    const realLeaf = mycertutil.computeFidoMtcLeafHash(mycertutil.buildFidoMtcLogEntry({
        caId: MTC_CA_ID, serial: MTC_SERIAL, notBefore: MTC_NOT_BEFORE, notAfter: MTC_NOT_AFTER,
        aaguid: aaguidBytes, coseKeyBytes
    }));
    const leaves = [];
    for (let i = 0; i < 8; i++) leaves.push(i === MTC_LEAF_INDEX ? realLeaf : leafOf(i));
    const tree = mycertutil.buildRFC9162MerkleTree(leaves);
    const proof = Buffer.concat(tree.getProof(MTC_LEAF_INDEX));

    const checkpoint = mycertutil.buildFidoMtcSubtreeCheckpoint({
        caId: MTC_CA_ID, logNumber: MTC_LOG_NUMBER, start: 0, end: 8, rootHash: tree.rootHash
    });
    const checkpointSig = crypto.sign(null, checkpoint, root.privateKey);

    const metadata = {
        aaguid: MTC_AAGUID,
        attestationRootCertificates: [root.certDER.toString('base64')],
        mtcTrustAnchors: [{
            caId: MTC_CA_ID.toString('base64'),
            subtrees: [{
                logNumber: MTC_LOG_NUMBER, start: 0, end: 8, rootHash: tree.rootHash.toString('base64'),
                alg: -50, signature: checkpointSig.toString('base64')
            }],
            batchKeys: [{
                serial: MTC_SERIAL, coseKey: coseKeyBytes.toString('base64'),
                notBefore: MTC_NOT_BEFORE, notAfter: MTC_NOT_AFTER, mtcProof: proof.toString('base64')
            }]
        }]
    };

    fidoutils.setFidoUtilsConfig({
        origin: "https://localhost:8443",
        encryptionPassphrase: "test",
        mtc: {
            aaguid: MTC_AAGUID, caId: MTC_CA_ID.toString('hex'), serial: MTC_SERIAL, alg: batchAlg,
            privateKeyHex: await mykeyutil.getPrivateKeyHex(batchKp), coseKey: coseKeyBytes.toString('hex'),
            notBefore: MTC_NOT_BEFORE, notAfter: MTC_NOT_AFTER,
            mtcProof: proof.toString('hex'), rootHash: tree.rootHash.toString('hex')
        }
    });
    const cco = {
        publicKey: {
            rp: { id: "localhost", name: "Test RP" },
            user: { id: [1, 2, 3, 4], name: "alice", displayName: "Alice" },
            challenge: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
            pubKeyCredParams: [{ alg: -7, type: "public-key" }]
        }
    };
    if (extensions) cco.publicKey.extensions = extensions;
    const res = await fidoutils.processCredentialCreationOptions(cco, "mtc");
    const attObjBytes = mykeyutil.fromBase64Url(res.spkc.response.attestationObject);
    const clientDataHash = crypto.createHash("sha256").update(mykeyutil.fromBase64Url(res.spkc.response.clientDataJSON)).digest();
    return { metadata, res, attObjBytes, clientDataHash, tree, proof, coseKeyBytes, root, batchAlg };
}

const decodeAtt = (bytes) => cbor.decode(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
// cbor encodes Uint8Array as a tagged typed array, so convert byte strings to Buffers first
const toBufs = (o) => (o instanceof Uint8Array ? Buffer.from(o) : (o && typeof o === 'object' && !Buffer.isBuffer(o))
    ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, toBufs(v)])) : o);
const encodeAtt = (o) => Buffer.from(cbor.encode(toBufs(o)));
const clone = (o) => JSON.parse(JSON.stringify(o));

test('verifyMTCAttestation: valid registration verifies against MDS metadata (Levels 0-5 chain)', async (t) => {
    const f = await makeMtcFixture();
    if (f == null) { t.skip('openssl with ML-DSA support is not available'); return; }

    const r = await fidoutils.verifyMTCAttestation(f.attObjBytes, f.clientDataHash, f.metadata);
    assert.equal(r.verified, true);
    assert.equal(r.mode, 'mds');
    assert.equal(r.trusted, true);
    assert.equal(r.alg, -48);
    assert.equal(r.serial, BigInt(MTC_SERIAL));
    assert.equal(r.leafIndex, BigInt(MTC_LEAF_INDEX));
    assert.equal(r.logNumber, MTC_LOG_NUMBER);
    assert.deepEqual(r.rootHash, f.tree.rootHash);
    assert.deepEqual(r.batchPublicKeyCose, f.coseKeyBytes);
    assert.equal(r.aaguid.toString('hex'), MTC_AAGUID.replaceAll('-', ''));

    // also accepts a base64url string and an already decoded attestationObject
    await fidoutils.verifyMTCAttestation(f.res.spkc.response.attestationObject, f.clientDataHash, f.metadata);
    await fidoutils.verifyMTCAttestation(decodeAtt(f.attObjBytes), f.clientDataHash, f.metadata);
});

test('verifyMTCAttestation: ML-DSA-87 batch key and no mtc-debug extension', async (t) => {
    const f = await makeMtcFixture(-50, null);
    if (f == null) { t.skip('openssl with ML-DSA support is not available'); return; }
    const r = await fidoutils.verifyMTCAttestation(f.attObjBytes, f.clientDataHash, f.metadata);
    assert.equal(r.alg, -50);
});

test('verifyMTCAttestation: in-band mtc-debug verification only when allowed, and is untrusted', async (t) => {
    const f = await makeMtcFixture();
    if (f == null) { t.skip('openssl with ML-DSA support is not available'); return; }

    // no metadata, in-band not allowed
    await assert.rejects(fidoutils.verifyMTCAttestation(f.attObjBytes, f.clientDataHash, null), /no batch key found/);

    const r = await fidoutils.verifyMTCAttestation(f.attObjBytes, f.clientDataHash, null, { allowInBand: true });
    assert.equal(r.mode, 'in-band');
    assert.equal(r.trusted, false);
    assert.deepEqual(r.rootHash, f.tree.rootHash);
    assert.equal(r.leafIndex, BigInt(MTC_LEAF_INDEX));

    // metadata that does not contain the key falls back to in-band when allowed
    const other = clone(f.metadata);
    other.mtcTrustAnchors[0].batchKeys = [];
    assert.equal((await fidoutils.verifyMTCAttestation(f.attObjBytes, f.clientDataHash, other, { allowInBand: true })).mode, 'in-band');
    await assert.rejects(fidoutils.verifyMTCAttestation(f.attObjBytes, f.clientDataHash, other), /no batch key found/);

    // registration without mtc-debug cannot be verified in-band
    const g = await makeMtcFixture(-48, null);
    await assert.rejects(fidoutils.verifyMTCAttestation(g.attObjBytes, g.clientDataHash, null, { allowInBand: true }), /no batch key found/);
});

test('verifyMTCAttestation: negative tests (signature, aaguid, serial, key, proof, checkpoint, validity, revocation)', async (t) => {
    const f = await makeMtcFixture();
    if (f == null) { t.skip('openssl with ML-DSA support is not available'); return; }
    const verify = (att, md = f.metadata, hash = f.clientDataHash, opts) =>
        fidoutils.verifyMTCAttestation(Buffer.isBuffer(att) ? att : encodeAtt(att), hash, md, opts);

    // invalid signature
    let att = decodeAtt(f.attObjBytes);
    const badSig = Buffer.from(att.attStmt.sig); badSig[10] ^= 1; att.attStmt.sig = badSig;
    await assert.rejects(verify(att), /attStmt\.sig is not a valid signature/);

    // wrong clientDataHash
    const badHash = Buffer.from(f.clientDataHash); badHash[0] ^= 1;
    await assert.rejects(verify(f.attObjBytes, f.metadata, badHash), /attStmt\.sig is not a valid signature/);

    // altered authData (aaguid) invalidates the signature
    att = decodeAtt(f.attObjBytes);
    const ad = Buffer.from(att.authData); ad[37] ^= 1; att.authData = ad;
    await assert.rejects(verify(att), /aaguid does not match|attStmt\.sig is not a valid signature/);
    await assert.rejects(verify(att, { ...f.metadata, aaguid: undefined }), /attStmt\.sig is not a valid signature/);

    // metadata aaguid differs from the authenticator's
    const md = clone(f.metadata); md.aaguid = '00000000-0000-0000-0000-000000000001';
    await assert.rejects(verify(f.attObjBytes, md), /aaguid does not match/);

    // altered serial: not in metadata
    att = decodeAtt(f.attObjBytes); att.attStmt.mtcCert.serial = MTC_SERIAL + 1;
    await assert.rejects(verify(att), /no batch key found/);

    // unknown caId
    att = decodeAtt(f.attObjBytes); att.attStmt.mtcCert.caId = Buffer.from('0102030405');
    await assert.rejects(verify(att), /no batch key found/);

    // alg mismatch between attStmt.alg and COSE_Key, and unacceptable alg
    att = decodeAtt(f.attObjBytes); att.attStmt.alg = -49;
    await assert.rejects(verify(att), /COSE_Key alg does not match/);
    await assert.rejects(verify(f.attObjBytes, f.metadata, f.clientDataHash, { acceptableAlgs: [-50] }), /not acceptable/);

    // wrong public key in metadata (a different valid key): signature fails
    const other = await mykeyutil.generateKeypair(-48);
    const otherCose = cbor.encodeCanonical(new Map([[1, 7], [3, -48], [-1, Buffer.from((await mykeyutil.getPublicKeyCOSE(-48, other))["-1"])]]));
    let bad = clone(f.metadata); bad.mtcTrustAnchors[0].batchKeys[0].coseKey = otherCose.toString('base64');
    await assert.rejects(verify(f.attObjBytes, bad), /attStmt\.sig is not a valid signature|differs from the key resolved/);

    // non-canonical COSE_Key encoding
    bad = clone(f.metadata);
    bad.mtcTrustAnchors[0].batchKeys[0].coseKey = Buffer.from(cbor.encode(new Map([[-1, f.coseKeyBytes], [3, -48], [1, 7]]))).toString('base64');
    await assert.rejects(verify(f.attObjBytes, bad), /differs from the key resolved/);
    // without the in-band copy of the key the canonical-encoding check is what rejects it
    const nodbg = await makeMtcFixture(-48, null);
    bad = clone(nodbg.metadata);
    bad.mtcTrustAnchors[0].batchKeys[0].coseKey = Buffer.from(cbor.encode(new Map([[-1, nodbg.coseKeyBytes], [3, -48], [1, 7]]))).toString('base64');
    await assert.rejects(fidoutils.verifyMTCAttestation(nodbg.attObjBytes, nodbg.clientDataHash, bad), /canonical CBOR COSE_Key/);

    // forged leaf: committed notBefore changed, so the leaf hash no longer matches the tree
    bad = clone(f.metadata); bad.mtcTrustAnchors[0].batchKeys[0].notBefore = MTC_NOT_BEFORE + 1;
    await assert.rejects(verify(f.attObjBytes, bad), /Merkle inclusion proof/);

    // bad Merkle path
    bad = clone(f.metadata);
    const p = Buffer.from(f.proof); p[0] ^= 1;
    bad.mtcTrustAnchors[0].batchKeys[0].mtcProof = p.toString('base64');
    await assert.rejects(verify(f.attObjBytes, bad), /Merkle inclusion proof/);
    bad.mtcTrustAnchors[0].batchKeys[0].mtcProof = f.proof.subarray(0, 64).toString('base64');
    await assert.rejects(verify(f.attObjBytes, bad), /Merkle inclusion proof/);
    bad.mtcTrustAnchors[0].batchKeys[0].mtcProof = f.proof.subarray(0, 63).toString('base64');
    await assert.rejects(verify(f.attObjBytes, bad), /multiple of 32/);
    delete bad.mtcTrustAnchors[0].batchKeys[0].mtcProof;
    await assert.rejects(verify(f.attObjBytes, bad), /mtcProof is required/);

    // tampered checkpoint: root hash replaced (proof also fails), or only the signature / range tampered
    bad = clone(f.metadata);
    const sig = Buffer.from(bad.mtcTrustAnchors[0].subtrees[0].signature, 'base64'); sig[5] ^= 1;
    bad.mtcTrustAnchors[0].subtrees[0].signature = sig.toString('base64');
    await assert.rejects(verify(f.attObjBytes, bad), /checkpoint signature/);
    bad = clone(f.metadata); bad.mtcTrustAnchors[0].subtrees[0].end = 16;
    await assert.rejects(verify(f.attObjBytes, bad), /Merkle inclusion proof|checkpoint signature/);

    // checkpoint signed by a different root CA
    const rogue = makeMLDSACert('ml-dsa-87');
    bad = clone(f.metadata); bad.attestationRootCertificates = [rogue.certDER.toString('base64')];
    await assert.rejects(verify(f.attObjBytes, bad), /checkpoint signature/);

    // validity window
    await assert.rejects(verify(f.attObjBytes, f.metadata, f.clientDataHash, { now: MTC_NOT_BEFORE - 1 }), /validity period/);
    bad = clone(f.metadata); bad.mtcTrustAnchors[0].batchKeys[0].notAfter = 1000;
    await assert.rejects(verify(f.attObjBytes, bad), /validity period/);

    // revocation
    bad = clone(f.metadata);
    bad.mtcTrustAnchors[0].revokedSerialRanges = [{ start: MTC_SERIAL - 1, end: MTC_SERIAL + 1 }];
    await assert.rejects(verify(f.attObjBytes, bad), /revoked/);
    bad.mtcTrustAnchors[0].revokedSerialRanges = [{ start: MTC_SERIAL + 1, end: MTC_SERIAL + 2 }];
    await verify(f.attObjBytes, bad);
});

test('verifyMTCAttestation: in-band tampering is detected', async (t) => {
    const f = await makeMtcFixture();
    if (f == null) { t.skip('openssl with ML-DSA support is not available'); return; }
    const inband = (att) => fidoutils.verifyMTCAttestation(encodeAtt(att), f.clientDataHash, null, { allowInBand: true });

    // any change to authData breaks the signature, including the extension bytes
    let att = decodeAtt(f.attObjBytes);
    const ad = Buffer.from(att.authData); ad[ad.length - 3] ^= 1; att.authData = ad;
    await assert.rejects(inband(att), /./);

    // altered serial moves the leaf to a different index/entry
    att = decodeAtt(f.attObjBytes); att.attStmt.mtcCert.serial = MTC_SERIAL + 1;
    await assert.rejects(inband(att), /Merkle inclusion proof/);
});

test('verifyMTCAttestation: rejects malformed attestation statements', async (t) => {
    const f = await makeMtcFixture();
    if (f == null) { t.skip('openssl with ML-DSA support is not available'); return; }
    const verify = (att) => fidoutils.verifyMTCAttestation(encodeAtt(att), f.clientDataHash, f.metadata);
    const fresh = () => decodeAtt(f.attObjBytes);

    let att = fresh(); att.fmt = "packed";
    await assert.rejects(verify(att), /fmt is not "mtc"/);
    att = fresh(); att.attStmt.extra = 1;
    await assert.rejects(verify(att), /exactly alg, sig and mtcCert/);
    att = fresh(); delete att.attStmt.sig;
    await assert.rejects(verify(att), /exactly alg, sig and mtcCert/);
    att = fresh(); att.attStmt.alg = "-48";
    await assert.rejects(verify(att), /alg is not an integer/);
    att = fresh(); att.attStmt.sig = "not bytes";
    await assert.rejects(verify(att), /sig is not a byte string/);
    att = fresh(); att.attStmt.mtcCert = { caId: att.attStmt.mtcCert.caId };
    await assert.rejects(verify(att), /exactly caId and serial/);
    att = fresh(); att.attStmt.mtcCert.serial = -1;
    await assert.rejects(verify(att), /serial is not an unsigned 64-bit integer/);
    att = fresh(); att.attStmt.mtcCert.serial = String(MTC_SERIAL);
    await verify(att);   // decimal string serials are tolerated (same value)
    att = fresh(); att.authData = Buffer.alloc(10);
    await assert.rejects(verify(att), /authenticatorData is malformed/);
    await assert.rejects(fidoutils.verifyMTCAttestation(Buffer.from([0xff, 0x00]), f.clientDataHash, f.metadata), /cannot be decoded/);
    await assert.rejects(fidoutils.verifyMTCAttestation(f.attObjBytes, Buffer.alloc(31), f.metadata), /clientDataHash must be 32 bytes/);
});

test('assertNoMTCDebugUnlessMTC: RP rejects mtc-debug output when fmt is not "mtc"', async (t) => {
    const f = await makeMtcFixture();
    if (f == null) { t.skip('openssl with ML-DSA support is not available'); return; }

    // valid: fmt mtc with the extension
    assert.equal(fidoutils.assertNoMTCDebugUnlessMTC(f.attObjBytes, f.res.spkc.getClientExtensionResults), true);

    // fmt is not mtc but authenticatorData carries mtc-debug
    const att = decodeAtt(f.attObjBytes); att.fmt = "none"; att.attStmt = {};
    assert.throws(() => fidoutils.assertNoMTCDebugUnlessMTC(encodeAtt(att), {}), /only allowed with fmt "mtc"/);

    // fmt is not mtc but clientExtensionResults.mtcDebug is present
    const g = await makeMtcFixture(-48, null);
    const none = decodeAtt(g.attObjBytes); none.fmt = "none"; none.attStmt = {};
    assert.equal(fidoutils.assertNoMTCDebugUnlessMTC(encodeAtt(none), {}), true);
    assert.throws(() => fidoutils.assertNoMTCDebugUnlessMTC(encodeAtt(none), { mtcDebug: {} }), /only allowed with fmt "mtc"/);
});

test('verifyMTCAttestation: verifies a registration against the generated certs/fidotest-mtc.json', async (t) => {
    const fs = require('node:fs');
    const path = require('node:path');
    if (!fs.existsSync(path.join(__dirname, '..', 'certs', 'fidotest-mtc.json')) || !fs.existsSync(path.join(__dirname, '..', '.env'))) {
        t.skip('certs/fidotest-mtc.json or .env not present (run certs/generate_attestation_certs.sh)');
        return;
    }
    const envLine = fs.readFileSync(path.join(__dirname, '..', '.env'), 'utf8').split('\n').find((l) => l.startsWith('FIDO2_CLIENT_CONFIG='));
    const config = envLine && JSON.parse(envLine.substring('FIDO2_CLIENT_CONFIG='.length));
    if (!config || !config.mtc) { t.skip('.env has no mtc block'); return; }
    const metadata = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'certs', 'fidotest-mtc.json'), 'utf8'));
    if (config.mtc.aaguid !== metadata.aaguid) { t.skip('.env mtc block does not match certs/fidotest-mtc.json'); return; }

    await fidoutils.init();
    config.origin = "https://localhost:8443";
    fidoutils.setFidoUtilsConfig(config);
    const res = await fidoutils.processCredentialCreationOptions({
        publicKey: {
            rp: { id: "localhost", name: "Test RP" }, user: { id: [1, 2, 3, 4], name: "a", displayName: "A" },
            challenge: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            pubKeyCredParams: [{ alg: -7, type: "public-key" }]
        }
    }, "mtc");
    const clientDataHash = crypto.createHash("sha256").update(mykeyutil.fromBase64Url(res.spkc.response.clientDataJSON)).digest();
    const r = await fidoutils.verifyMTCAttestation(res.spkc.response.attestationObject, clientDataHash, metadata);
    assert.equal(r.trusted, true);
    assert.equal(r.leafIndex, 0n);
    assert.equal(r.subtree.end, 1024n);
});
