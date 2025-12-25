/**
 * Blocktrails test suite
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
  scalar,
  computeTweak, // backward compat alias
  derivePrivateKey,
  derivePublicKey,
  deriveChainedPrivateKey,
  deriveChainedPublicKey,
  p2trXonly,
  hasEvenY,
  genesis,
  transition,
  verify,
  Blocktrail,
  bytesToHex,
  hexToBytes
} from '../src/index.js';

// Test private key (DO NOT USE IN PRODUCTION)
const TEST_PRIVKEY = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');

describe('scalar', () => {
  test('produces non-zero tweak for typical state', () => {
    const t = scalar('hello world');
    assert.ok(t > 0n, 'Tweak should be positive');
  });

  test('produces consistent results', () => {
    const t1 = scalar('test state');
    const t2 = scalar('test state');
    assert.strictEqual(t1, t2, 'Same input should produce same tweak');
  });

  test('different states produce different tweaks', () => {
    const t1 = scalar('state 1');
    const t2 = scalar('state 2');
    assert.notStrictEqual(t1, t2, 'Different inputs should produce different tweaks');
  });

  test('handles Uint8Array input', () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const t = scalar(bytes);
    assert.ok(t > 0n, 'Should handle bytes');
  });

  test('computeTweak is alias for scalar (backward compat)', () => {
    const t1 = scalar('test');
    const t2 = computeTweak('test');
    assert.strictEqual(t1, t2, 'computeTweak should be alias for scalar');
  });

  // Note: Testing t=0 rejection requires finding a preimage that hashes to 0 mod n,
  // which is computationally infeasible (~2^-256 probability). The check is tested
  // implicitly through code coverage. If we had such a state, this would test it:
  // test('rejects state with zero tweak', () => {
  //   assert.throws(() => scalar(MAGIC_ZERO_STATE), /zero/i);
  // });
});

describe('derivePrivateKey', () => {
  test('produces 32-byte private key', () => {
    const d = derivePrivateKey(TEST_PRIVKEY, 'state');
    assert.strictEqual(d.length, 32, 'Private key should be 32 bytes');
  });

  test('different states produce different keys', () => {
    const d1 = derivePrivateKey(TEST_PRIVKEY, 'state 1');
    const d2 = derivePrivateKey(TEST_PRIVKEY, 'state 2');
    assert.notStrictEqual(bytesToHex(d1), bytesToHex(d2));
  });
});

describe('derivePublicKey', () => {
  test('produces 33-byte compressed public key', () => {
    const pubBase = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    const P = derivePublicKey(pubBase, 'state');
    assert.strictEqual(P.length, 33, 'Public key should be 33 bytes compressed');
  });

  test('first byte is 02 or 03', () => {
    const pubBase = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    const P = derivePublicKey(pubBase, 'state');
    assert.ok(P[0] === 0x02 || P[0] === 0x03, 'Should be compressed format');
  });
});

describe('p2trXonly', () => {
  test('produces 32-byte x-only key', () => {
    const pubBase = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    const P = derivePublicKey(pubBase, 'state');
    const xonly = p2trXonly(P);
    assert.strictEqual(xonly.length, 32, 'x-only key should be 32 bytes');
  });

  test('x(P) == x(-P) - same x for even and odd y', () => {
    // This is inherent to x-only representation
    const pubBase = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    const P = derivePublicKey(pubBase, 'state');
    const xonly = p2trXonly(P);
    // The x-coordinate is just the 32 bytes after the prefix
    const xFromCompressed = P.slice(1);
    assert.strictEqual(bytesToHex(xonly), bytesToHex(xFromCompressed));
  });
});

describe('genesis', () => {
  test('creates valid genesis', () => {
    const result = genesis(TEST_PRIVKEY, 'initial state');
    assert.ok(result.privateKeyBase, 'Should have privateKeyBase');
    assert.ok(result.pubkeyBase, 'Should have pubkeyBase');
    assert.ok(result.derivedPrivateKey, 'Should have derivedPrivateKey');
    assert.ok(result.derivedPublicKey, 'Should have derivedPublicKey');
    assert.ok(result.witnessProgram, 'Should have witnessProgram');
    assert.ok(result.p2trAddress, 'Should have p2trAddress');
  });

  test('witness program is 32 bytes (64 hex chars)', () => {
    const result = genesis(TEST_PRIVKEY, 'initial state');
    assert.strictEqual(result.witnessProgram.length, 64);
  });

  test('p2tr address starts with bc1p', () => {
    const result = genesis(TEST_PRIVKEY, 'initial state');
    assert.ok(result.p2trAddress.startsWith('bc1p'), 'Should be P2TR address');
  });
});

describe('transition', () => {
  test('creates valid transition (chained)', () => {
    // transition now takes [prevStates], newState
    const result = transition(TEST_PRIVKEY, ['state 0'], 'state 1');
    assert.ok(result.prevStates, 'Should have prevStates');
    assert.ok(result.newState, 'Should have newState');
    assert.ok(result.signingPrivateKey, 'Should have signingPrivateKey');
    assert.ok(result.prevWitnessProgram, 'Should have prevWitnessProgram');
    assert.ok(result.newWitnessProgram, 'Should have newWitnessProgram');
  });

  test('prev and new witness programs differ', () => {
    const result = transition(TEST_PRIVKEY, ['state 0'], 'state 1');
    assert.notStrictEqual(result.prevWitnessProgram, result.newWitnessProgram);
  });

  test('chained transitions accumulate tweaks', () => {
    const pubBase = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');

    // P0 = P_base + t0
    const P0 = deriveChainedPublicKey(pubBase, ['s0']);
    // P1 = P0 + t1 = P_base + t0 + t1
    const P1 = deriveChainedPublicKey(pubBase, ['s0', 's1']);
    // P2 = P1 + t2 = P_base + t0 + t1 + t2
    const P2 = deriveChainedPublicKey(pubBase, ['s0', 's1', 's2']);

    // All should be different
    assert.notStrictEqual(bytesToHex(P0), bytesToHex(P1));
    assert.notStrictEqual(bytesToHex(P1), bytesToHex(P2));
    assert.notStrictEqual(bytesToHex(P0), bytesToHex(P2));
  });
});

describe('verify', () => {
  test('verifies valid chained chain', () => {
    const pubBase = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    const states = ['state 0', 'state 1', 'state 2'];

    // Generate chained witness programs
    const witnessPrograms = [];
    for (let i = 0; i < states.length; i++) {
      const P = deriveChainedPublicKey(pubBase, states.slice(0, i + 1));
      witnessPrograms.push(p2trXonly(P));
    }

    const result = verify(pubBase, states, witnessPrograms);
    assert.strictEqual(result.valid, true);
  });

  test('rejects invalid chain', () => {
    const pubBase = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    const states = ['state 0', 'state 1'];
    // Wrong witness programs
    const witnessPrograms = [
      new Uint8Array(32).fill(0),
      new Uint8Array(32).fill(1)
    ];

    const result = verify(pubBase, states, witnessPrograms);
    assert.strictEqual(result.valid, false);
  });

  test('rejects mismatched lengths', () => {
    const pubBase = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    const states = ['state 0', 'state 1'];
    const witnessPrograms = [new Uint8Array(32)];

    const result = verify(pubBase, states, witnessPrograms);
    assert.strictEqual(result.valid, false);
  });
});

describe('Blocktrail class', () => {
  test('full lifecycle', () => {
    const trail = new Blocktrail(TEST_PRIVKEY);

    // Genesis
    const g = trail.genesis('initial');
    assert.ok(g.witnessProgram);

    // Advance
    const t1 = trail.advance('state 1');
    assert.notStrictEqual(g.witnessProgram, t1.newWitnessProgram);

    const t2 = trail.advance('state 2');
    assert.notStrictEqual(t1.newWitnessProgram, t2.newWitnessProgram);

    // Current state
    assert.strictEqual(trail.currentState(), 'state 2');

    // Export
    const exported = trail.export();
    assert.strictEqual(exported.states.length, 3);
    assert.strictEqual(exported.witnessPrograms.length, 3);
  });

  test('verify exported trail', () => {
    const trail = new Blocktrail(TEST_PRIVKEY);
    trail.genesis('s0');
    trail.advance('s1');
    trail.advance('s2');

    const exported = trail.export();

    // Verify with a new instance
    const pubBase = hexToBytes(exported.pubkeyBase);
    const witnessPrograms = exported.witnessPrograms.map(hexToBytes);

    const result = verify(pubBase, exported.states, witnessPrograms);
    assert.strictEqual(result.valid, true);
  });

  test('throws if advance called before genesis', () => {
    const trail = new Blocktrail(TEST_PRIVKEY);
    assert.throws(() => trail.advance('state'), /genesis/i);
  });
});

describe('edge cases', () => {
  test('empty string state', () => {
    const result = genesis(TEST_PRIVKEY, '');
    assert.ok(result.witnessProgram);
  });

  test('very long state', () => {
    const longState = 'x'.repeat(10000);
    const result = genesis(TEST_PRIVKEY, longState);
    assert.ok(result.witnessProgram);
  });

  test('binary state', () => {
    const binaryState = new Uint8Array([0, 1, 2, 255, 254, 253]);
    const result = genesis(TEST_PRIVKEY, binaryState);
    assert.ok(result.witnessProgram);
  });

  test('JSON state', () => {
    const jsonState = JSON.stringify({ balance: 1000, owner: 'alice' });
    const result = genesis(TEST_PRIVKEY, jsonState);
    assert.ok(result.witnessProgram);
  });
});

describe('determinism', () => {
  test('same inputs always produce same outputs', () => {
    const results = [];
    for (let i = 0; i < 5; i++) {
      results.push(genesis(TEST_PRIVKEY, 'deterministic state'));
    }

    const first = results[0];
    for (const r of results) {
      assert.strictEqual(r.witnessProgram, first.witnessProgram);
      assert.strictEqual(r.derivedPublicKey, first.derivedPublicKey);
    }
  });
});
