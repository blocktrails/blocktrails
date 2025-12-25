/**
 * Bitcoin P2TR Transaction Building and Signing
 *
 * Implements:
 * - BIP-340 Schnorr signatures
 * - BIP-341 Taproot sighash
 * - P2TR transaction serialization
 */

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const N = secp.CURVE.n;

// ============================================
// Byte Utilities
// ============================================

export function concatBytes(...arrays) {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function bytesToBigInt(bytes) {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

export function bigIntToBytes(num, length) {
  const bytes = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(num & 0xffn);
    num >>= 8n;
  }
  return bytes;
}

function xorBytes(a, b) {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

export function reverseBytes(bytes) {
  const result = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    result[i] = bytes[bytes.length - 1 - i];
  }
  return result;
}

// ============================================
// Little-Endian Encoding
// ============================================

export function writeUint32LE(value) {
  const buf = new Uint8Array(4);
  buf[0] = value & 0xff;
  buf[1] = (value >> 8) & 0xff;
  buf[2] = (value >> 16) & 0xff;
  buf[3] = (value >> 24) & 0xff;
  return buf;
}

export function writeUint64LE(value) {
  const buf = new Uint8Array(8);
  let v = BigInt(value);
  for (let i = 0; i < 8; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

export function writeVarInt(n) {
  if (n < 0xfd) {
    return new Uint8Array([n]);
  } else if (n <= 0xffff) {
    return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
  } else if (n <= 0xffffffff) {
    const buf = new Uint8Array(5);
    buf[0] = 0xfe;
    buf.set(writeUint32LE(n), 1);
    return buf;
  } else {
    const buf = new Uint8Array(9);
    buf[0] = 0xff;
    buf.set(writeUint64LE(BigInt(n)), 1);
    return buf;
  }
}

// ============================================
// BIP-340 Tagged Hash
// ============================================

const tagHashCache = new Map();

/**
 * BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || msg)
 */
export function taggedHash(tag, ...msgs) {
  let tagHash = tagHashCache.get(tag);
  if (!tagHash) {
    const tagBytes = new TextEncoder().encode(tag);
    tagHash = sha256(tagBytes);
    tagHashCache.set(tag, tagHash);
  }
  return sha256(concatBytes(tagHash, tagHash, ...msgs));
}

// ============================================
// BIP-340 Schnorr Signatures
// ============================================

/**
 * Get x-only public key (32 bytes) from private key
 */
function getXOnlyPubKey(privateKey) {
  const P = secp.ProjectivePoint.BASE.multiply(bytesToBigInt(privateKey));
  const { x } = P.toAffine();
  return bigIntToBytes(x, 32);
}

/**
 * Check if point has even Y coordinate
 */
function pointHasEvenY(privateKey) {
  const P = secp.ProjectivePoint.BASE.multiply(bytesToBigInt(privateKey));
  const { y } = P.toAffine();
  return y % 2n === 0n;
}

/**
 * BIP-340 Schnorr signature
 *
 * @param {Uint8Array} messageHash - 32-byte message to sign
 * @param {Uint8Array} privateKey - 32-byte private key (already adjusted for even Y)
 * @param {Uint8Array} auxRand - 32-byte auxiliary randomness (optional)
 * @returns {Uint8Array} 64-byte Schnorr signature
 */
export function signSchnorr(messageHash, privateKey, auxRand = new Uint8Array(32)) {
  // Get private key as bigint, negate if pubkey Y is odd
  let d = bytesToBigInt(privateKey);
  if (!pointHasEvenY(privateKey)) {
    d = N - d;
  }
  const dBytes = bigIntToBytes(d, 32);

  // Get x-only public key
  const px = getXOnlyPubKey(privateKey);

  // a = tagged_hash("BIP0340/aux", rand)
  const a = taggedHash('BIP0340/aux', auxRand);

  // t = d XOR a
  const t = xorBytes(dBytes, a);

  // k' = tagged_hash("BIP0340/nonce", t || P.x || m) mod n
  const kPrimeHash = taggedHash('BIP0340/nonce', t, px, messageHash);
  let kPrime = bytesToBigInt(kPrimeHash) % N;

  if (kPrime === 0n) {
    throw new Error('Schnorr signing failed: k is zero');
  }

  // R = k'·G
  const R = secp.ProjectivePoint.BASE.multiply(kPrime).toAffine();

  // If R.y is odd, negate k
  let k = kPrime;
  if (R.y % 2n !== 0n) {
    k = N - kPrime;
  }

  // rx = R.x as 32 bytes
  const rx = bigIntToBytes(R.x, 32);

  // e = tagged_hash("BIP0340/challenge", R.x || P.x || m) mod n
  const eHash = taggedHash('BIP0340/challenge', rx, px, messageHash);
  const e = bytesToBigInt(eHash) % N;

  // s = (k + e*d) mod n
  const s = (k + e * d) % N;

  // sig = R.x || s
  return concatBytes(rx, bigIntToBytes(s, 32));
}

/**
 * Verify BIP-340 Schnorr signature
 */
export function verifySchnorr(signature, messageHash, pubkey) {
  if (signature.length !== 64) return false;
  if (messageHash.length !== 32) return false;
  if (pubkey.length !== 32) return false;

  const rx = bytesToBigInt(signature.slice(0, 32));
  const s = bytesToBigInt(signature.slice(32));

  if (rx >= secp.CURVE.p || s >= N) return false;

  // e = tagged_hash("BIP0340/challenge", R.x || P.x || m) mod n
  const eHash = taggedHash('BIP0340/challenge', signature.slice(0, 32), pubkey, messageHash);
  const e = bytesToBigInt(eHash) % N;

  // R' = s·G - e·P
  try {
    const P = secp.ProjectivePoint.fromHex(concatBytes(new Uint8Array([0x02]), pubkey));
    const sG = secp.ProjectivePoint.BASE.multiply(s);
    const eP = P.multiply(e);
    const R = sG.add(eP.negate()).toAffine();

    // Verify R.y is even and R.x matches
    if (R.y % 2n !== 0n) return false;
    if (R.x !== rx) return false;

    return true;
  } catch {
    return false;
  }
}

// ============================================
// P2TR Script
// ============================================

/**
 * Create P2TR scriptPubKey from witness program
 * OP_1 (0x51) + OP_PUSHBYTES_32 (0x20) + 32-byte witness program
 */
export function createP2TRScript(witnessProgram) {
  if (witnessProgram.length !== 32) {
    throw new Error('Witness program must be 32 bytes');
  }
  return concatBytes(new Uint8Array([0x51, 0x20]), witnessProgram);
}

// ============================================
// Transaction Building
// ============================================

/**
 * Build unsigned P2TR transaction
 *
 * @param {Object} params
 * @param {Array} params.inputs - [{txid, vout, witnessProgram, amount}]
 * @param {Array} params.outputs - [{witnessProgram, value}] or [{address, value}]
 * @returns {Object} Unsigned transaction
 */
export function buildTransaction({ inputs, outputs }) {
  return {
    version: 2,
    inputs: inputs.map(inp => ({
      txid: inp.txid,
      vout: inp.vout,
      witnessProgram: inp.witnessProgram,
      amount: BigInt(inp.amount),
      sequence: 0xfffffffd // RBF enabled
    })),
    outputs: outputs.map(out => ({
      scriptPubKey: out.scriptPubKey || createP2TRScript(out.witnessProgram),
      value: BigInt(out.value)
    })),
    locktime: 0,
    witnesses: []
  };
}

// ============================================
// BIP-341 Sighash
// ============================================

/**
 * Compute BIP-341 sighash for P2TR key-path spend (SIGHASH_DEFAULT)
 *
 * @param {Object} tx - Transaction object
 * @param {number} inputIndex - Index of input being signed
 * @param {Array} prevouts - Previous outputs [{txid, vout, witnessProgram, amount}]
 * @returns {Uint8Array} 32-byte sighash
 */
export function computeTapSighash(tx, inputIndex, prevouts) {
  // Common elements
  const epoch = new Uint8Array([0x00]);
  const hashType = new Uint8Array([0x00]); // SIGHASH_DEFAULT
  const nVersion = writeUint32LE(tx.version);
  const nLockTime = writeUint32LE(tx.locktime);

  // sha_prevouts: sha256 of all (txid || vout)
  const prevoutsData = concatBytes(...prevouts.map(p =>
    concatBytes(
      reverseBytes(typeof p.txid === 'string' ? hexToBytes(p.txid) : p.txid),
      writeUint32LE(p.vout)
    )
  ));
  const shaPrevouts = sha256(prevoutsData);

  // sha_amounts: sha256 of all amounts (8 bytes LE each)
  const amountsData = concatBytes(...prevouts.map(p => writeUint64LE(p.amount)));
  const shaAmounts = sha256(amountsData);

  // sha_scriptpubkeys: sha256 of all scriptPubKeys (with length prefix)
  const scriptsData = concatBytes(...prevouts.map(p => {
    const script = createP2TRScript(
      typeof p.witnessProgram === 'string' ? hexToBytes(p.witnessProgram) : p.witnessProgram
    );
    return concatBytes(writeVarInt(script.length), script);
  }));
  const shaScriptPubKeys = sha256(scriptsData);

  // sha_sequences: sha256 of all sequences
  const sequencesData = concatBytes(...tx.inputs.map(inp => writeUint32LE(inp.sequence)));
  const shaSequences = sha256(sequencesData);

  // sha_outputs: sha256 of all outputs
  const outputsData = concatBytes(...tx.outputs.map(out =>
    concatBytes(
      writeUint64LE(out.value),
      writeVarInt(out.scriptPubKey.length),
      out.scriptPubKey
    )
  ));
  const shaOutputs = sha256(outputsData);

  // spend_type: 0x00 for key-path spend, no annex
  const spendType = new Uint8Array([0x00]);

  // input_index (4 bytes LE)
  const inputIndexBytes = writeUint32LE(inputIndex);

  // Compute TapSighash
  return taggedHash('TapSighash',
    epoch,
    hashType,
    nVersion,
    nLockTime,
    shaPrevouts,
    shaAmounts,
    shaScriptPubKeys,
    shaSequences,
    shaOutputs,
    spendType,
    inputIndexBytes
  );
}

// ============================================
// Transaction Signing
// ============================================

/**
 * Sign all inputs of a P2TR transaction
 *
 * @param {Object} tx - Transaction from buildTransaction()
 * @param {Array} signingKeys - Array of 32-byte private keys (one per input)
 * @param {Array} prevouts - Previous outputs for sighash computation
 * @returns {Object} Signed transaction with witnesses
 */
export function signTransaction(tx, signingKeys, prevouts) {
  const witnesses = [];

  for (let i = 0; i < tx.inputs.length; i++) {
    const sighash = computeTapSighash(tx, i, prevouts);
    const signature = signSchnorr(sighash, signingKeys[i]);
    // For SIGHASH_DEFAULT, no hash type byte appended
    witnesses.push([signature]);
  }

  return { ...tx, witnesses };
}

// ============================================
// Transaction Serialization
// ============================================

/**
 * Serialize signed transaction to bytes (SegWit format)
 */
export function serializeTransaction(tx) {
  const parts = [];

  // Version (4 bytes LE)
  parts.push(writeUint32LE(tx.version));

  // Marker (0x00) + Flag (0x01) for SegWit
  parts.push(new Uint8Array([0x00, 0x01]));

  // Input count
  parts.push(writeVarInt(tx.inputs.length));

  // Inputs
  for (const input of tx.inputs) {
    // txid (32 bytes, reversed)
    const txidBytes = typeof input.txid === 'string' ? hexToBytes(input.txid) : input.txid;
    parts.push(reverseBytes(txidBytes));
    // vout (4 bytes LE)
    parts.push(writeUint32LE(input.vout));
    // scriptSig (empty for SegWit)
    parts.push(new Uint8Array([0x00]));
    // sequence (4 bytes LE)
    parts.push(writeUint32LE(input.sequence));
  }

  // Output count
  parts.push(writeVarInt(tx.outputs.length));

  // Outputs
  for (const output of tx.outputs) {
    // value (8 bytes LE)
    parts.push(writeUint64LE(output.value));
    // scriptPubKey length + scriptPubKey
    parts.push(writeVarInt(output.scriptPubKey.length));
    parts.push(output.scriptPubKey);
  }

  // Witness data
  for (const witness of tx.witnesses) {
    // Number of witness items
    parts.push(writeVarInt(witness.length));
    for (const item of witness) {
      // Item length + item data
      parts.push(writeVarInt(item.length));
      parts.push(item);
    }
  }

  // Locktime (4 bytes LE)
  parts.push(writeUint32LE(tx.locktime));

  return concatBytes(...parts);
}

/**
 * Serialize transaction without witness (for txid computation)
 */
export function serializeTransactionNoWitness(tx) {
  const parts = [];

  // Version
  parts.push(writeUint32LE(tx.version));

  // Input count
  parts.push(writeVarInt(tx.inputs.length));

  // Inputs
  for (const input of tx.inputs) {
    const txidBytes = typeof input.txid === 'string' ? hexToBytes(input.txid) : input.txid;
    parts.push(reverseBytes(txidBytes));
    parts.push(writeUint32LE(input.vout));
    parts.push(new Uint8Array([0x00]));
    parts.push(writeUint32LE(input.sequence));
  }

  // Output count
  parts.push(writeVarInt(tx.outputs.length));

  // Outputs
  for (const output of tx.outputs) {
    parts.push(writeUint64LE(output.value));
    parts.push(writeVarInt(output.scriptPubKey.length));
    parts.push(output.scriptPubKey);
  }

  // Locktime
  parts.push(writeUint32LE(tx.locktime));

  return concatBytes(...parts);
}

/**
 * Compute transaction ID (double sha256 of non-witness serialization, reversed)
 */
export function computeTxid(tx) {
  const serialized = serializeTransactionNoWitness(tx);
  const hash1 = sha256(serialized);
  const hash2 = sha256(hash1);
  return bytesToHex(reverseBytes(hash2));
}

// ============================================
// Fee Estimation
// ============================================

/**
 * Estimate virtual size of a P2TR transaction
 *
 * P2TR key-path spend:
 * - Base: 10.5 vbytes (header overhead)
 * - Per input: 57.5 vbytes (41 non-witness + 66/4 witness)
 * - Per P2TR output: 43 vbytes
 */
export function estimateVsize(inputCount, outputCount) {
  const baseSize = 10.5;
  const inputSize = 57.5;
  const outputSize = 43;
  return Math.ceil(baseSize + (inputCount * inputSize) + (outputCount * outputSize));
}

// Re-export utilities
export { bytesToHex, hexToBytes };
