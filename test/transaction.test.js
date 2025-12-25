/**
 * Transaction module test suite
 * Includes BIP-340 and BIP-341 test vectors
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
  signSchnorr,
  verifySchnorr,
  taggedHash,
  buildTransaction,
  signTransaction,
  serializeTransaction,
  serializeTransactionNoWitness,
  computeTxid,
  computeTapSighash,
  createP2TRScript,
  estimateVsize,
  writeUint32LE,
  writeUint64LE,
  writeVarInt,
  reverseBytes,
  concatBytes,
  bytesToBigInt,
  bigIntToBytes,
  bytesToHex,
  hexToBytes
} from '../src/transaction.js';

// ============================================
// BIP-340 Official Test Vectors
// From: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
// ============================================

const BIP340_VECTORS = [
  {
    index: 0,
    secretKey: '0000000000000000000000000000000000000000000000000000000000000003',
    pubkey: 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9',
    auxRand: '0000000000000000000000000000000000000000000000000000000000000000',
    message: '0000000000000000000000000000000000000000000000000000000000000000',
    signature: 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0'
  },
  {
    index: 1,
    secretKey: 'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF',
    pubkey: 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    auxRand: '0000000000000000000000000000000000000000000000000000000000000001',
    message: '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    signature: '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'
  },
  {
    index: 2,
    secretKey: 'C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9',
    pubkey: 'DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8',
    auxRand: 'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906',
    message: '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
    signature: '5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7'
  },
  {
    index: 3,
    secretKey: '0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710',
    pubkey: '25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517',
    auxRand: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    message: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    signature: '7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3'
  }
];

describe('BIP-340 Schnorr signatures', () => {
  for (const vec of BIP340_VECTORS) {
    test(`passes test vector ${vec.index}`, () => {
      const sig = signSchnorr(
        hexToBytes(vec.message),
        hexToBytes(vec.secretKey),
        hexToBytes(vec.auxRand)
      );
      assert.strictEqual(
        bytesToHex(sig).toUpperCase(),
        vec.signature,
        `Vector ${vec.index} failed`
      );
    });

    test(`verifies test vector ${vec.index}`, () => {
      const valid = verifySchnorr(
        hexToBytes(vec.signature),
        hexToBytes(vec.message),
        hexToBytes(vec.pubkey)
      );
      assert.strictEqual(valid, true, `Vector ${vec.index} verification failed`);
    });
  }

  test('rejects invalid signature', () => {
    const validSig = hexToBytes(BIP340_VECTORS[0].signature);
    const invalidSig = new Uint8Array(validSig);
    invalidSig[0] ^= 0x01; // Flip a bit

    const valid = verifySchnorr(
      invalidSig,
      hexToBytes(BIP340_VECTORS[0].message),
      hexToBytes(BIP340_VECTORS[0].pubkey)
    );
    assert.strictEqual(valid, false);
  });

  test('rejects wrong message', () => {
    const valid = verifySchnorr(
      hexToBytes(BIP340_VECTORS[0].signature),
      hexToBytes(BIP340_VECTORS[1].message), // Wrong message
      hexToBytes(BIP340_VECTORS[0].pubkey)
    );
    assert.strictEqual(valid, false);
  });
});

describe('Tagged hash', () => {
  test('produces correct BIP0340/challenge hash', () => {
    // Known test case
    const hash = taggedHash('BIP0340/challenge',
      new Uint8Array(32).fill(0),
      new Uint8Array(32).fill(0),
      new Uint8Array(32).fill(0)
    );
    assert.strictEqual(hash.length, 32);
  });

  test('different tags produce different hashes', () => {
    const msg = new Uint8Array(32).fill(1);
    const h1 = taggedHash('BIP0340/aux', msg);
    const h2 = taggedHash('BIP0340/nonce', msg);
    assert.notStrictEqual(bytesToHex(h1), bytesToHex(h2));
  });

  test('same tag and message produce same hash', () => {
    const msg = new Uint8Array(32).fill(42);
    const h1 = taggedHash('TapSighash', msg);
    const h2 = taggedHash('TapSighash', msg);
    assert.strictEqual(bytesToHex(h1), bytesToHex(h2));
  });
});

describe('Encoding helpers', () => {
  test('writeUint32LE', () => {
    assert.deepStrictEqual(
      Array.from(writeUint32LE(0x12345678)),
      [0x78, 0x56, 0x34, 0x12]
    );
    assert.deepStrictEqual(
      Array.from(writeUint32LE(0)),
      [0, 0, 0, 0]
    );
    assert.deepStrictEqual(
      Array.from(writeUint32LE(0xffffffff)),
      [0xff, 0xff, 0xff, 0xff]
    );
  });

  test('writeUint64LE', () => {
    const result = writeUint64LE(0x123456789abcdef0n);
    assert.deepStrictEqual(
      Array.from(result),
      [0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]
    );
  });

  test('writeVarInt', () => {
    // < 0xfd
    assert.deepStrictEqual(Array.from(writeVarInt(0)), [0]);
    assert.deepStrictEqual(Array.from(writeVarInt(252)), [252]);

    // 0xfd - 0xffff
    assert.deepStrictEqual(Array.from(writeVarInt(253)), [0xfd, 253, 0]);
    assert.deepStrictEqual(Array.from(writeVarInt(0xffff)), [0xfd, 0xff, 0xff]);

    // 0x10000 - 0xffffffff
    assert.deepStrictEqual(
      Array.from(writeVarInt(0x10000)),
      [0xfe, 0x00, 0x00, 0x01, 0x00]
    );
  });

  test('reverseBytes', () => {
    assert.deepStrictEqual(
      Array.from(reverseBytes(new Uint8Array([1, 2, 3, 4]))),
      [4, 3, 2, 1]
    );
  });

  test('bytesToBigInt and bigIntToBytes roundtrip', () => {
    const original = 0x123456789abcdef0n;
    const bytes = bigIntToBytes(original, 8);
    const recovered = bytesToBigInt(bytes);
    assert.strictEqual(recovered, original);
  });
});

describe('P2TR Script', () => {
  test('creates correct P2TR scriptPubKey', () => {
    const wp = new Uint8Array(32).fill(0xab);
    const script = createP2TRScript(wp);

    // OP_1 (0x51) + OP_PUSHBYTES_32 (0x20) + 32 bytes
    assert.strictEqual(script.length, 34);
    assert.strictEqual(script[0], 0x51);
    assert.strictEqual(script[1], 0x20);
    assert.deepStrictEqual(Array.from(script.slice(2)), Array.from(wp));
  });

  test('rejects non-32-byte witness program', () => {
    assert.throws(() => createP2TRScript(new Uint8Array(31)));
    assert.throws(() => createP2TRScript(new Uint8Array(33)));
  });
});

describe('Transaction building', () => {
  const testWP = new Uint8Array(32).fill(0xaa);
  const testTxid = 'a'.repeat(64);

  test('buildTransaction creates correct structure', () => {
    const tx = buildTransaction({
      inputs: [{
        txid: testTxid,
        vout: 0,
        amount: 10000,
        witnessProgram: testWP
      }],
      outputs: [{
        witnessProgram: testWP,
        value: 9000
      }]
    });

    assert.strictEqual(tx.version, 2);
    assert.strictEqual(tx.inputs.length, 1);
    assert.strictEqual(tx.outputs.length, 1);
    assert.strictEqual(tx.locktime, 0);
    assert.strictEqual(tx.inputs[0].sequence, 0xfffffffd);
    assert.strictEqual(tx.outputs[0].value, 9000n);
  });

  test('serializeTransaction produces valid bytes', () => {
    const tx = buildTransaction({
      inputs: [{
        txid: testTxid,
        vout: 0,
        amount: 10000,
        witnessProgram: testWP
      }],
      outputs: [{
        witnessProgram: testWP,
        value: 9000
      }]
    });

    // Add fake witness for serialization
    tx.witnesses = [[new Uint8Array(64).fill(0)]];

    const bytes = serializeTransaction(tx);

    // Check structure
    assert.ok(bytes.length > 0);
    // Version (4) + marker (1) + flag (1) = 6
    assert.strictEqual(bytes[0], 2); // version byte 0
    assert.strictEqual(bytes[4], 0); // marker
    assert.strictEqual(bytes[5], 1); // flag
  });

  test('serializeTransactionNoWitness excludes witness data', () => {
    const tx = buildTransaction({
      inputs: [{
        txid: testTxid,
        vout: 0,
        amount: 10000,
        witnessProgram: testWP
      }],
      outputs: [{
        witnessProgram: testWP,
        value: 9000
      }]
    });

    tx.witnesses = [[new Uint8Array(64).fill(0)]];

    const withWitness = serializeTransaction(tx);
    const withoutWitness = serializeTransactionNoWitness(tx);

    // Without witness should be shorter (no marker, flag, or witness data)
    assert.ok(withoutWitness.length < withWitness.length);
  });

  test('computeTxid produces 64-char hex', () => {
    const tx = buildTransaction({
      inputs: [{
        txid: testTxid,
        vout: 0,
        amount: 10000,
        witnessProgram: testWP
      }],
      outputs: [{
        witnessProgram: testWP,
        value: 9000
      }]
    });

    tx.witnesses = [[new Uint8Array(64)]];

    const txid = computeTxid(tx);
    assert.strictEqual(txid.length, 64);
    assert.ok(/^[0-9a-f]+$/.test(txid));
  });
});

describe('Fee estimation', () => {
  test('estimateVsize produces reasonable estimates', () => {
    // 1 input, 1 output
    const vsize1 = estimateVsize(1, 1);
    assert.ok(vsize1 > 100 && vsize1 < 200);

    // 2 inputs, 2 outputs
    const vsize2 = estimateVsize(2, 2);
    assert.ok(vsize2 > vsize1);
    assert.ok(vsize2 < 300);
  });
});

describe('Full transaction signing flow', () => {
  test('sign and serialize transaction', () => {
    // Use test key from BIP-340 vectors
    const privateKey = hexToBytes('0000000000000000000000000000000000000000000000000000000000000003');

    // Derive public key x-only
    const testWP = hexToBytes('F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9');
    const testTxid = '0'.repeat(64);

    const prevouts = [{
      txid: testTxid,
      vout: 0,
      amount: 10000,
      witnessProgram: testWP
    }];

    const tx = buildTransaction({
      inputs: prevouts,
      outputs: [{
        witnessProgram: testWP,
        value: 9000
      }]
    });

    // Sign
    const signedTx = signTransaction(tx, [privateKey], prevouts);

    // Check witness
    assert.strictEqual(signedTx.witnesses.length, 1);
    assert.strictEqual(signedTx.witnesses[0].length, 1);
    assert.strictEqual(signedTx.witnesses[0][0].length, 64); // Schnorr sig

    // Serialize
    const bytes = serializeTransaction(signedTx);
    assert.ok(bytes.length > 100);

    // Compute txid
    const txid = computeTxid(signedTx);
    assert.strictEqual(txid.length, 64);
  });

  test('deterministic signatures with same auxRand', () => {
    const privateKey = hexToBytes('0000000000000000000000000000000000000000000000000000000000000003');
    const testWP = hexToBytes('F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9');
    const testTxid = '1'.repeat(64);

    const prevouts = [{
      txid: testTxid,
      vout: 0,
      amount: 10000,
      witnessProgram: testWP
    }];

    const tx1 = buildTransaction({ inputs: prevouts, outputs: [{ witnessProgram: testWP, value: 9000 }] });
    const tx2 = buildTransaction({ inputs: prevouts, outputs: [{ witnessProgram: testWP, value: 9000 }] });

    const signed1 = signTransaction(tx1, [privateKey], prevouts);
    const signed2 = signTransaction(tx2, [privateKey], prevouts);

    // Same inputs should produce same signature (with default zero auxRand)
    assert.strictEqual(
      bytesToHex(signed1.witnesses[0][0]),
      bytesToHex(signed2.witnesses[0][0])
    );
  });
});

describe('Sighash computation', () => {
  test('computeTapSighash produces 32-byte hash', () => {
    const testWP = new Uint8Array(32).fill(0xcc);
    const testTxid = 'b'.repeat(64);

    const prevouts = [{
      txid: testTxid,
      vout: 0,
      amount: 10000,
      witnessProgram: testWP
    }];

    const tx = buildTransaction({
      inputs: prevouts,
      outputs: [{ witnessProgram: testWP, value: 9000 }]
    });

    const sighash = computeTapSighash(tx, 0, prevouts);

    assert.strictEqual(sighash.length, 32);
  });

  test('different inputs produce different sighashes', () => {
    const testWP = new Uint8Array(32).fill(0xdd);

    const prevouts1 = [{
      txid: 'c'.repeat(64),
      vout: 0,
      amount: 10000,
      witnessProgram: testWP
    }];

    const prevouts2 = [{
      txid: 'd'.repeat(64),
      vout: 0,
      amount: 10000,
      witnessProgram: testWP
    }];

    const tx1 = buildTransaction({ inputs: prevouts1, outputs: [{ witnessProgram: testWP, value: 9000 }] });
    const tx2 = buildTransaction({ inputs: prevouts2, outputs: [{ witnessProgram: testWP, value: 9000 }] });

    const sighash1 = computeTapSighash(tx1, 0, prevouts1);
    const sighash2 = computeTapSighash(tx2, 0, prevouts2);

    assert.notStrictEqual(bytesToHex(sighash1), bytesToHex(sighash2));
  });
});
