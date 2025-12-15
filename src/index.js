/**
 * Blocktrails - Nostr-native output-key commitment chaining on Bitcoin
 * Reference implementation (v0.2 - chained derivation model)
 *
 * Key change from v0.1: Uses chained tweaking where each state
 * adds to the previous key, not independent derivation from base.
 */

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// secp256k1 curve order
const N = secp.CURVE.n;

/**
 * Compute scalar tweak from state per spec:
 *   h = sha256(serialize(s))
 *   t = int(h, big-endian) mod n
 *   if t == 0: reject state as invalid
 *   return t
 *
 * @param {Uint8Array|string} state - State bytes or string (serialized)
 * @returns {bigint} Tweak value in range [1, n-1]
 * @throws {Error} If tweak is zero (probability ~2^-256)
 */
export function scalar(state) {
  const stateBytes = typeof state === 'string'
    ? new TextEncoder().encode(state)
    : state;
  const hash = sha256(stateBytes);
  const t = bytesToBigInt(hash) % N;

  // Per spec: "Implementations MUST reject states where t = 0"
  if (t === 0n) {
    throw new Error('Invalid state: tweak is zero');
  }

  return t;
}

// Backward compatibility alias
export const computeTweak = scalar;

/**
 * Derive private key for a state: d = d_base + t
 * @param {Uint8Array} privateKeyBase - Base private key (32 bytes)
 * @param {Uint8Array|string} state - State to commit to
 * @returns {Uint8Array} Derived private key (32 bytes)
 * @throws {Error} If scalar(state) is zero
 */
export function derivePrivateKey(privateKeyBase, state) {
  const dBase = bytesToBigInt(privateKeyBase);
  const t = scalar(state); // throws if t == 0
  const d = (dBase + t) % N;
  return bigIntToBytes(d, 32);
}

/**
 * Derive public key for a state: P = P_base + t·G
 * @param {Uint8Array} publicKeyBase - Base public key (33 bytes compressed)
 * @param {Uint8Array|string} state - State to commit to
 * @returns {Uint8Array} Derived public key (33 bytes compressed)
 * @throws {Error} If scalar(state) is zero
 */
export function derivePublicKey(publicKeyBase, state) {
  const t = scalar(state); // throws if t == 0

  // P_base + t·G
  const PBase = secp.ProjectivePoint.fromHex(publicKeyBase);
  const tG = secp.ProjectivePoint.BASE.multiply(t);
  const P = PBase.add(tG);

  return P.toRawBytes(true); // compressed
}

/**
 * Convert public key to P2TR x-only format (32 bytes)
 * If y is odd, negate the point
 * @param {Uint8Array} publicKey - Public key (33 bytes compressed)
 * @returns {Uint8Array} x-only public key (32 bytes)
 */
export function p2trXonly(publicKey) {
  const P = secp.ProjectivePoint.fromHex(publicKey);
  const { x, y } = P.toAffine();

  // If y is odd, we'd negate, but x stays the same
  // So we just return x
  return bigIntToBytes(x, 32);
}

/**
 * Check if public key has even y (for signing)
 * @param {Uint8Array} publicKey - Public key (33 bytes compressed)
 * @returns {boolean} True if y is even
 */
export function hasEvenY(publicKey) {
  // First byte: 02 = even, 03 = odd
  return publicKey[0] === 0x02;
}

/**
 * Negate private key if needed for BIP-340 signing
 * @param {Uint8Array} privateKey - Private key (32 bytes)
 * @param {Uint8Array} publicKey - Corresponding public key (33 bytes)
 * @returns {Uint8Array} Possibly negated private key
 */
export function adjustPrivateKeyForSigning(privateKey, publicKey) {
  if (hasEvenY(publicKey)) {
    return privateKey;
  }
  // Negate: d' = n - d
  const d = bytesToBigInt(privateKey);
  const dNeg = N - d;
  return bigIntToBytes(dNeg, 32);
}

/**
 * Create a genesis commitment
 * @param {Uint8Array} privateKeyBase - Base private key (32 bytes)
 * @param {Uint8Array|string} state - Initial state
 * @returns {Object} Genesis info
 */
export function genesis(privateKeyBase, state) {
  const publicKeyBase = secp.getPublicKey(privateKeyBase, true);
  const d = derivePrivateKey(privateKeyBase, state);
  const P = derivePublicKey(publicKeyBase, state);
  const output = p2trXonly(P);

  return {
    privateKeyBase: bytesToHex(privateKeyBase),
    publicKeyBase: bytesToHex(publicKeyBase),
    state: typeof state === 'string' ? state : bytesToHex(state),
    derivedPrivateKey: bytesToHex(d),
    derivedPublicKey: bytesToHex(P),
    witnessProgram: bytesToHex(output),
    p2trAddress: encodeBech32m('bc', output) // mainnet
  };
}

/**
 * Derive chained public key from all states (P = P_base + t₀·G + t₁·G + ...)
 * @param {Uint8Array} publicKeyBase - Base public key (33 bytes compressed)
 * @param {Array<Uint8Array|string>} states - All states in order
 * @returns {Uint8Array} Derived public key (33 bytes compressed)
 */
export function deriveChainedPublicKey(publicKeyBase, states) {
  let P = secp.ProjectivePoint.fromHex(publicKeyBase);

  for (const state of states) {
    const t = scalar(state);
    const tG = secp.ProjectivePoint.BASE.multiply(t);
    P = P.add(tG);
  }

  return P.toRawBytes(true);
}

/**
 * Derive chained private key from all states (d = d_base + t₀ + t₁ + ...)
 * @param {Uint8Array} privateKeyBase - Base private key (32 bytes)
 * @param {Array<Uint8Array|string>} states - All states in order
 * @returns {Uint8Array} Derived private key (32 bytes)
 */
export function deriveChainedPrivateKey(privateKeyBase, states) {
  let d = bytesToBigInt(privateKeyBase);

  for (const state of states) {
    const t = scalar(state);
    d = (d + t) % N;
  }

  return bigIntToBytes(d, 32);
}

/**
 * Create a state transition (chained model)
 * @param {Uint8Array} privateKeyBase - Base private key (32 bytes)
 * @param {Array<Uint8Array|string>} prevStates - All previous states including genesis
 * @param {Uint8Array|string} newState - New state to transition to
 * @returns {Object} Transition info
 */
export function transition(privateKeyBase, prevStates, newState) {
  const publicKeyBase = secp.getPublicKey(privateKeyBase, true);

  // Previous output (what we're spending) - chained from all previous states
  const prevP = deriveChainedPublicKey(publicKeyBase, prevStates);
  const prevD = deriveChainedPrivateKey(privateKeyBase, prevStates);
  const signingKey = adjustPrivateKeyForSigning(prevD, prevP);

  // New output - chain includes all states
  const allStates = [...prevStates, newState];
  const newP = deriveChainedPublicKey(publicKeyBase, allStates);
  const newOutput = p2trXonly(newP);

  return {
    prevStates: prevStates.map(s => typeof s === 'string' ? s : bytesToHex(s)),
    newState: typeof newState === 'string' ? newState : bytesToHex(newState),
    signingPrivateKey: bytesToHex(signingKey),
    prevWitnessProgram: bytesToHex(p2trXonly(prevP)),
    newWitnessProgram: bytesToHex(newOutput),
    newP2trAddress: encodeBech32m('bc', newOutput)
  };
}

/**
 * Verify a state chain (chained model)
 * @param {Uint8Array} publicKeyBase - Base public key (33 bytes)
 * @param {Array<Uint8Array|string>} states - Array of states
 * @param {Array<Uint8Array>} witnessPrograms - Array of witness programs from chain
 * @returns {Object} Verification result
 */
export function verify(publicKeyBase, states, witnessPrograms) {
  if (states.length !== witnessPrograms.length) {
    return { valid: false, error: 'State count does not match witness program count' };
  }

  // Chain the verification: P = P_base, then P = P + t·G for each state
  let P = secp.ProjectivePoint.fromHex(publicKeyBase);

  for (let i = 0; i < states.length; i++) {
    const state = states[i];
    const expectedWP = witnessPrograms[i];

    try {
      // Add this state's tweak to the running key
      const t = scalar(state);
      const tG = secp.ProjectivePoint.BASE.multiply(t);
      P = P.add(tG);

      const computedWP = p2trXonly(P.toRawBytes(true));

      // Compare x-coordinates
      const expectedHex = bytesToHex(expectedWP);
      const computedHex = bytesToHex(computedWP);

      if (expectedHex !== computedHex) {
        return {
          valid: false,
          error: `Mismatch at index ${i}: expected ${expectedHex}, got ${computedHex}`
        };
      }
    } catch (e) {
      return { valid: false, error: `Error at index ${i}: ${e.message}` };
    }
  }

  return { valid: true };
}

/**
 * Create a Blocktrail instance for easier state management (chained model)
 */
export class Blocktrail {
  constructor(privateKeyBase) {
    this.privateKeyBase = typeof privateKeyBase === 'string'
      ? hexToBytes(privateKeyBase)
      : privateKeyBase;
    this.publicKeyBase = secp.getPublicKey(this.privateKeyBase, true);
    this.states = [];
  }

  /**
   * Initialize with genesis state
   */
  genesis(state) {
    this.states = [state];
    return genesis(this.privateKeyBase, state);
  }

  /**
   * Advance to new state (chained)
   */
  advance(newState) {
    if (this.states.length === 0) {
      throw new Error('Must call genesis() first');
    }
    // Pass all previous states for chained derivation
    const result = transition(this.privateKeyBase, this.states, newState);
    this.states.push(newState);
    return result;
  }

  /**
   * Get current state
   */
  currentState() {
    return this.states[this.states.length - 1];
  }

  /**
   * Get current witness program (chained)
   */
  currentWitnessProgram() {
    const P = deriveChainedPublicKey(this.publicKeyBase, this.states);
    return p2trXonly(P);
  }

  /**
   * Verify this trail matches given witness programs
   */
  verify(witnessPrograms) {
    return verify(this.publicKeyBase, this.states, witnessPrograms);
  }

  /**
   * Export trail data (chained witness programs)
   */
  export() {
    const witnessPrograms = [];
    let P = secp.ProjectivePoint.fromHex(this.publicKeyBase);

    for (const state of this.states) {
      const t = scalar(state);
      const tG = secp.ProjectivePoint.BASE.multiply(t);
      P = P.add(tG);
      witnessPrograms.push(bytesToHex(p2trXonly(P.toRawBytes(true))));
    }

    return {
      publicKeyBase: bytesToHex(this.publicKeyBase),
      states: this.states,
      witnessPrograms
    };
  }
}

// Utility functions

function bytesToBigInt(bytes) {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

function bigIntToBytes(num, length) {
  const bytes = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(num & 0xffn);
    num >>= 8n;
  }
  return bytes;
}

// Simple bech32m encoding for P2TR addresses
const BECH32M_CONST = 0x2bc830a3;
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (const c of hrp) {
    ret.push(c.charCodeAt(0) >> 5);
  }
  ret.push(0);
  for (const c of hrp) {
    ret.push(c.charCodeAt(0) & 31);
  }
  return ret;
}

function bech32CreateChecksum(hrp, data, spec) {
  const values = [...bech32HrpExpand(hrp), ...data];
  const polymod = bech32Polymod([...values, 0, 0, 0, 0, 0, 0]) ^ spec;
  const ret = [];
  for (let i = 0; i < 6; i++) {
    ret.push((polymod >> (5 * (5 - i))) & 31);
  }
  return ret;
}

function convertBits(data, fromBits, toBits, pad) {
  let acc = 0;
  let bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) {
    ret.push((acc << (toBits - bits)) & maxv);
  }
  return ret;
}

function encodeBech32m(hrp, witnessProgram) {
  const version = 1; // P2TR is witness version 1
  const data = [version, ...convertBits(witnessProgram, 8, 5, true)];
  const checksum = bech32CreateChecksum(hrp, data, BECH32M_CONST);
  return hrp + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

// Re-export utilities
export { bytesToHex, hexToBytes };
