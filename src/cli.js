#!/usr/bin/env node
/**
 * Blocktrails CLI
 * Nostr-native output-key commitment chaining on Bitcoin
 */

import WebSocket from 'ws';
globalThis.WebSocket = WebSocket;

import { execSync } from 'child_process';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import * as secp from '@noble/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { finalizeEvent, Relay } from 'nostr-tools';
import {
  Blocktrail,
  verify,
  p2trXonly,
  deriveChainedPublicKey,
  deriveChainedPrivateKey,
  scalar,
  buildTransaction,
  signTransaction,
  serializeTransaction,
  computeTxid,
  createP2TRScript,
  estimateVsize,
  getUtxos,
  getAddressTxs,
  broadcast as broadcastTx,
  getFeeRates,
  getCacheDir,
  getCacheStats,
  clearCache
} from './index.js';

const DEFAULT_FILE = '.blocktrail.json';

// ============================================
// Key Management
// ============================================

/**
 * Get private key from various sources
 * Priority: --key flag > git config nostr.privkey > null
 */
function getPrivateKey(options) {
  // 1. Explicit --key flag
  if (options.key) {
    return options.key;
  }

  // 2. git config nostr.privkey
  try {
    const gitKey = execSync('git config nostr.privkey', { encoding: 'utf8' }).trim();
    if (gitKey && /^[0-9a-fA-F]{64}$/.test(gitKey)) {
      return gitKey;
    }
  } catch {
    // git config not found, continue
  }

  return null;
}

/**
 * Generate a new random private key
 */
function generatePrivateKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Parse state argument - try JSON first, fall back to string
 * This ensures numbers, booleans, objects, arrays are handled correctly
 */
function parseState(input) {
  try {
    // Try to parse as JSON
    const parsed = JSON.parse(input);
    // Re-stringify to get canonical form
    return JSON.stringify(parsed);
  } catch {
    // Not valid JSON, treat as plain string
    return input;
  }
}

// ============================================
// Trail File Management
// ============================================

function getTrailPath(options) {
  return resolve(options.file || DEFAULT_FILE);
}

function loadTrail(options) {
  const path = getTrailPath(options);
  if (!existsSync(path)) {
    return null;
  }
  try {
    const data = JSON.parse(readFileSync(path, 'utf8'));
    return data;
  } catch (e) {
    console.error(`Error reading trail file: ${e.message}`);
    process.exit(1);
  }
}

function saveTrail(trail, options) {
  const path = getTrailPath(options);
  const data = {
    version: 1,
    publicKeyBase: bytesToHex(trail.publicKeyBase),
    states: trail.states,
    network: options.network || 'tbtc4'
  };
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
  return path;
}

// ============================================
// Address Encoding
// ============================================

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
  for (const c of hrp) ret.push(c.charCodeAt(0) >> 5);
  ret.push(0);
  for (const c of hrp) ret.push(c.charCodeAt(0) & 31);
  return ret;
}

function convertBits(data, fromBits, toBits, pad) {
  let acc = 0, bits = 0;
  const ret = [], maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  return ret;
}

function encodeBech32m(hrp, witnessProgram) {
  const version = 1;
  const data = [version, ...convertBits(witnessProgram, 8, 5, true)];
  const polymod = bech32Polymod([...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

function getHrp(network) {
  return network === 'mainnet' ? 'bc' : 'tb'; // tbtc4 uses 'tb' prefix
}

/**
 * Decode a bech32m address to witness program
 * @param {string} address - Bech32m address (bc1p... or tb1p...)
 * @returns {{ hrp: string, version: number, witnessProgram: Uint8Array }} Decoded address
 */
function decodeBech32m(address) {
  const addr = address.toLowerCase();
  const sepIndex = addr.lastIndexOf('1');
  if (sepIndex < 1 || sepIndex + 7 > addr.length) {
    throw new Error('Invalid bech32m address: missing separator');
  }

  const hrp = addr.slice(0, sepIndex);
  const dataChars = addr.slice(sepIndex + 1);

  // Decode characters to 5-bit values
  const data = [];
  for (const c of dataChars) {
    const idx = CHARSET.indexOf(c);
    if (idx === -1) {
      throw new Error(`Invalid bech32m character: ${c}`);
    }
    data.push(idx);
  }

  // Verify checksum
  const polymod = bech32Polymod([...bech32HrpExpand(hrp), ...data]);
  if (polymod !== BECH32M_CONST) {
    throw new Error('Invalid bech32m checksum');
  }

  // Remove checksum (last 6 values) and extract version
  const values = data.slice(0, -6);
  const version = values[0];

  if (version !== 1) {
    throw new Error(`Unsupported witness version: ${version} (expected 1 for P2TR)`);
  }

  // Convert remaining 5-bit values to 8-bit
  const payload = values.slice(1);
  const witnessProgram = convertBitsBack(payload, 5, 8);

  if (witnessProgram.length !== 32) {
    throw new Error(`Invalid witness program length: ${witnessProgram.length} (expected 32)`);
  }

  return { hrp, version, witnessProgram: new Uint8Array(witnessProgram) };
}

/**
 * Convert bits back (5-bit to 8-bit, no padding)
 */
function convertBitsBack(data, fromBits, toBits) {
  let acc = 0, bits = 0;
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

  // Check for invalid padding
  if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    // Ignore padding bits
  }

  return ret;
}

// ============================================
// Commands
// ============================================

function cmdInit(options) {
  const existingPath = getTrailPath(options);
  if (existsSync(existingPath) && !options.force) {
    console.error(`Trail file already exists: ${existingPath}`);
    console.error('Use --force to overwrite');
    process.exit(1);
  }

  let privateKey = getPrivateKey(options);
  let keySource = 'provided';

  if (!privateKey) {
    // Try git config
    try {
      privateKey = execSync('git config nostr.privkey', { encoding: 'utf8' }).trim();
      if (privateKey && /^[0-9a-fA-F]{64}$/.test(privateKey)) {
        keySource = 'git config nostr.privkey';
      } else {
        privateKey = null;
      }
    } catch {
      privateKey = null;
    }
  }

  if (!privateKey) {
    privateKey = generatePrivateKey();
    keySource = 'generated';
  }

  const publicKey = secp.getPublicKey(hexToBytes(privateKey), true);
  const publicKeyHex = bytesToHex(publicKey);

  // Create minimal trail file (no states yet)
  const data = {
    version: 1,
    publicKeyBase: publicKeyHex,
    states: [],
    network: options.network || 'tbtc4'
  };

  writeFileSync(existingPath, JSON.stringify(data, null, 2) + '\n');

  console.log(`Initialized new trail: ${existingPath}`);
  console.log(`Key source: ${keySource}`);
  console.log(`Public key: ${publicKeyHex}`);

  if (keySource === 'generated') {
    console.log('');
    console.log('IMPORTANT: Save your private key securely:');
    console.log(`  ${privateKey}`);
    console.log('');
    console.log('Or set it in git config for future use:');
    console.log(`  git config nostr.privkey ${privateKey}`);
  }
}

function cmdGenesis(stateArg, options) {
  const existingTrail = loadTrail(options);

  if (existingTrail && existingTrail.states.length > 0) {
    console.error('Trail already has genesis. Use "advance" to add states.');
    process.exit(1);
  }

  const privateKey = getPrivateKey(options);
  if (!privateKey) {
    console.error('No private key found. Use --key or set git config nostr.privkey');
    process.exit(1);
  }

  const state = parseState(stateArg);
  const trail = new Blocktrail(privateKey);
  const result = trail.genesis(state);

  const path = saveTrail(trail, options);
  const hrp = getHrp(options.network || 'tbtc4');
  const address = encodeBech32m(hrp, hexToBytes(result.witnessProgram));

  console.log(`Genesis created`);
  console.log(`State: ${state}`);
  console.log(`Address: ${address}`);
  console.log(`Saved: ${path}`);
}

function cmdAdvance(stateArg, options) {
  const existingTrail = loadTrail(options);

  if (!existingTrail || existingTrail.states.length === 0) {
    console.error('No trail found. Run "genesis" first.');
    process.exit(1);
  }

  const privateKey = getPrivateKey(options);
  if (!privateKey) {
    console.error('No private key found. Use --key or set git config nostr.privkey');
    process.exit(1);
  }

  // Reconstruct trail
  const trail = new Blocktrail(privateKey);
  trail.states = existingTrail.states;
  trail.publicKeyBase = secp.getPublicKey(hexToBytes(privateKey), true);

  // Verify public key matches
  if (bytesToHex(trail.publicKeyBase) !== existingTrail.publicKeyBase) {
    console.error('Private key does not match trail public key');
    process.exit(1);
  }

  const state = parseState(stateArg);
  const result = trail.advance(state);

  const path = saveTrail(trail, { ...options, network: existingTrail.network });
  const hrp = getHrp(existingTrail.network || 'tbtc4');
  const address = encodeBech32m(hrp, hexToBytes(result.newWitnessProgram));

  console.log(`State ${trail.states.length - 1} -> ${trail.states.length}`);
  console.log(`State: ${state}`);
  console.log(`Address: ${address}`);
  console.log(`Saved: ${path}`);
}

async function cmdShow(options) {
  const trail = loadTrail(options);

  if (!trail) {
    console.error('No trail found. Run "init" or "genesis" first.');
    process.exit(1);
  }

  const network = trail.network || 'tbtc4';
  const hrp = getHrp(network);
  const publicKeyBase = hexToBytes(trail.publicKeyBase);

  console.log(`Trail: ${getTrailPath(options)}`);
  console.log(`Network: ${network}`);
  console.log(`Public key: ${trail.publicKeyBase}`);
  console.log(`States: ${trail.states.length}`);
  console.log('');

  // Show base key address
  const baseWP = p2trXonly(publicKeyBase);
  const baseAddress = encodeBech32m(hrp, baseWP);
  console.log(`Base address: ${baseAddress}`);

  if (options.online) {
    try {
      const [baseUtxos, baseTxs] = await Promise.all([
        getUtxos(baseAddress, network),
        getAddressTxs(baseAddress, network)
      ]);
      if (baseTxs.length === 0) {
        console.log(`Base status: never funded`);
      } else if (baseUtxos.length === 0) {
        console.log(`Base status: SPENT (${baseTxs.length} tx)`);
      } else {
        const total = baseUtxos.reduce((s, u) => s + u.amount, 0);
        console.log(`Base status: ${total} sats (${baseUtxos.length} UTXO, ${baseTxs.length} tx)`);
      }
    } catch (e) {
      console.log(`Base status: (error fetching)`);
    }
  }
  console.log('');

  if (trail.states.length === 0) {
    console.log('No states yet. Run "genesis" to create initial state.');
    return;
  }

  // Collect addresses first
  const addresses = [];
  let P = secp.ProjectivePoint.fromHex(publicKeyBase);

  for (let i = 0; i < trail.states.length; i++) {
    const state = trail.states[i];
    const t = scalar(state);
    const tG = secp.ProjectivePoint.BASE.multiply(t);
    P = P.add(tG);

    const wp = p2trXonly(P.toRawBytes(true));
    const address = encodeBech32m(hrp, wp);
    addresses.push({ state, address, index: i });
  }

  // Fetch on-chain status if --online flag
  let statusMap = new Map();
  if (options.online) {
    console.log('Fetching on-chain status...');
    console.log('');
    for (const { address, index } of addresses) {
      try {
        const [utxos, txs] = await Promise.all([
          getUtxos(address, network),
          getAddressTxs(address, network)
        ]);
        statusMap.set(index, { utxos, txs });
      } catch (e) {
        statusMap.set(index, null); // Error fetching
      }
    }
  }

  // Display states
  for (let i = 0; i < addresses.length; i++) {
    const { state, address } = addresses[i];
    const label = i === 0 ? 'GENESIS' : i === addresses.length - 1 ? 'HEAD' : `State ${i}`;
    const statePreview = state.length > 50 ? state.slice(0, 47) + '...' : state;

    console.log(`[${i}] ${label}`);
    console.log(`    State: ${statePreview}`);
    console.log(`    Address: ${address}`);

    // Show on-chain status if available
    if (options.online) {
      const status = statusMap.get(i);
      if (status === null) {
        console.log(`    Status: (error fetching)`);
      } else {
        const { utxos, txs } = status;
        if (txs.length === 0) {
          console.log(`    Status: never funded`);
        } else if (utxos.length === 0) {
          console.log(`    Status: SPENT (${txs.length} tx)`);
        } else {
          const total = utxos.reduce((s, u) => s + u.amount, 0);
          const confirmed = utxos.filter(u => u.confirmed).length;
          console.log(`    Status: ${total} sats (${utxos.length} UTXO, ${confirmed} confirmed, ${txs.length} tx)`);
        }
      }
    }

    if (i < addresses.length - 1) console.log('    ↓');
  }
}

function cmdExport(options) {
  const trail = loadTrail(options);

  if (!trail) {
    console.error('No trail found.');
    process.exit(1);
  }

  if (trail.states.length === 0) {
    console.error('Trail has no states.');
    process.exit(1);
  }

  const publicKeyBase = hexToBytes(trail.publicKeyBase);

  // Generate witness programs
  const witnessPrograms = [];
  let P = secp.ProjectivePoint.fromHex(publicKeyBase);

  for (const state of trail.states) {
    const t = scalar(state);
    const tG = secp.ProjectivePoint.BASE.multiply(t);
    P = P.add(tG);
    witnessPrograms.push(bytesToHex(p2trXonly(P.toRawBytes(true))));
  }

  const exportData = {
    version: 1,
    publicKeyBase: trail.publicKeyBase,
    network: trail.network || 'tbtc4',
    states: trail.states,
    witnessPrograms
  };

  if (options.output) {
    writeFileSync(options.output, JSON.stringify(exportData, null, 2) + '\n');
    console.log(`Exported to: ${options.output}`);
  } else {
    console.log(JSON.stringify(exportData, null, 2));
  }
}

function cmdVerify(file, options) {
  let data;

  if (file) {
    if (!existsSync(file)) {
      console.error(`File not found: ${file}`);
      process.exit(1);
    }
    data = JSON.parse(readFileSync(file, 'utf8'));
  } else {
    data = loadTrail(options);
    if (!data) {
      console.error('No trail found.');
      process.exit(1);
    }
  }

  if (!data.states || data.states.length === 0) {
    console.error('No states to verify.');
    process.exit(1);
  }

  // If no witness programs, generate them for self-consistency check
  if (!data.witnessPrograms) {
    console.log('No witness programs in file, generating...');
    const publicKeyBase = hexToBytes(data.publicKeyBase);
    data.witnessPrograms = [];
    let P = secp.ProjectivePoint.fromHex(publicKeyBase);

    for (const state of data.states) {
      const t = scalar(state);
      const tG = secp.ProjectivePoint.BASE.multiply(t);
      P = P.add(tG);
      data.witnessPrograms.push(bytesToHex(p2trXonly(P.toRawBytes(true))));
    }
  }

  const publicKeyBase = hexToBytes(data.publicKeyBase);
  const witnessPrograms = data.witnessPrograms.map(wp =>
    typeof wp === 'string' ? hexToBytes(wp) : wp
  );

  const result = verify(publicKeyBase, data.states, witnessPrograms);

  if (result.valid) {
    console.log(`✓ Trail verified: ${data.states.length} states`);
    console.log(`  Public key: ${data.publicKeyBase.slice(0, 16)}...`);
    console.log(`  Network: ${data.network || 'unknown'}`);
  } else {
    console.error(`✗ Verification failed: ${result.error}`);
    process.exit(1);
  }
}

async function cmdFund(options) {
  // Load trail
  const trail = loadTrail(options);
  if (!trail || trail.states.length === 0) {
    console.error('No trail found. Run "genesis" first to create a state.');
    process.exit(1);
  }

  // Get private key
  const privateKey = getPrivateKey(options);
  if (!privateKey) {
    console.error('No private key found. Use --key or set git config nostr.privkey');
    process.exit(1);
  }

  // Verify private key matches trail
  const publicKey = secp.getPublicKey(hexToBytes(privateKey), true);
  if (bytesToHex(publicKey) !== trail.publicKeyBase) {
    console.error('Private key does not match trail public key');
    process.exit(1);
  }

  const network = trail.network || 'tbtc4';
  const hrp = getHrp(network);
  const publicKeyBase = hexToBytes(trail.publicKeyBase);

  // Base address (untweaked)
  const baseWP = p2trXonly(publicKeyBase);
  const baseAddress = encodeBech32m(hrp, baseWP);

  // GENESIS address (first state)
  const genesisP = deriveChainedPublicKey(publicKeyBase, [trail.states[0]]);
  const genesisWP = p2trXonly(genesisP);
  const genesisAddress = encodeBech32m(hrp, genesisWP);

  console.log(`Base address: ${baseAddress}`);
  console.log(`GENESIS address: ${genesisAddress}`);

  // Fetch UTXOs from base
  console.log('');
  console.log('Fetching UTXOs from base...');
  let utxos;
  try {
    utxos = await getUtxos(baseAddress, network);
    if (utxos.length === 0) {
      console.error('No UTXOs at base address.');
      console.error(`Send funds to: ${baseAddress}`);
      process.exit(1);
    }
    utxos = utxos.map(u => ({ ...u, witnessProgram: baseWP }));
    console.log(`Found ${utxos.length} UTXO(s), total: ${utxos.reduce((s, u) => s + u.amount, 0)} sats`);
  } catch (e) {
    console.error(`Failed to fetch UTXOs: ${e.message}`);
    process.exit(1);
  }

  // Calculate fee
  let feeRate = options.feeRate;
  if (!feeRate) {
    try {
      const rates = await getFeeRates(network);
      feeRate = rates.halfHour;
      console.log(`Using fee rate: ${feeRate} sat/vB`);
    } catch {
      feeRate = 1;
      console.log(`Using default fee rate: ${feeRate} sat/vB`);
    }
  }

  const vsize = estimateVsize(utxos.length, 1);
  const fee = Math.ceil(vsize * feeRate);
  const totalIn = utxos.reduce((sum, u) => sum + u.amount, 0);
  const outputAmount = totalIn - fee;

  if (outputAmount <= 546) {
    console.error(`Insufficient funds: ${totalIn} sats, fee ${fee} sats`);
    process.exit(1);
  }

  // Build transaction: base → GENESIS
  const tx = buildTransaction({
    inputs: utxos.map(u => ({
      txid: u.txid,
      vout: u.vout,
      amount: u.amount,
      witnessProgram: u.witnessProgram
    })),
    outputs: [{
      witnessProgram: genesisWP,
      value: outputAmount
    }]
  });

  // Sign with BASE key (not derived)
  const signingKeys = utxos.map(() => hexToBytes(privateKey));
  const signedTx = signTransaction(tx, signingKeys, utxos);

  // Serialize
  const txBytes = serializeTransaction(signedTx);
  const txHex = bytesToHex(txBytes);
  const txid = computeTxid(signedTx);

  console.log('');
  console.log('Transaction built (base → GENESIS):');
  console.log(`  TXID: ${txid}`);
  console.log(`  Fee: ${fee} sats (${feeRate} sat/vB)`);
  console.log(`  Output: ${outputAmount} sats → GENESIS`);

  if (options.showRaw) {
    console.log('');
    console.log('Raw transaction:');
    console.log(txHex);
  }

  // Broadcast if requested
  if (options.broadcast) {
    console.log('');
    console.log('Broadcasting...');
    try {
      const broadcastTxid = await broadcastTx(txHex, network);
      console.log(`✓ Broadcast successful!`);
      console.log(`  TXID: ${broadcastTxid}`);
    } catch (e) {
      console.error(`✗ Broadcast failed: ${e.message}`);
      process.exit(1);
    }
  } else {
    console.log('');
    console.log('Dry run. Use --broadcast to send.');
  }
}

async function cmdSpend(newState, options) {
  // Load trail
  const trail = loadTrail(options);
  if (!trail || trail.states.length === 0) {
    console.error('No trail found. Run "genesis" first.');
    process.exit(1);
  }

  // Get private key
  const privateKey = getPrivateKey(options);
  if (!privateKey) {
    console.error('No private key found. Use --key or set git config nostr.privkey');
    process.exit(1);
  }

  // Verify private key matches trail
  const publicKey = secp.getPublicKey(hexToBytes(privateKey), true);
  if (bytesToHex(publicKey) !== trail.publicKeyBase) {
    console.error('Private key does not match trail public key');
    process.exit(1);
  }

  const network = trail.network || 'tbtc4';
  const hrp = getHrp(network);
  const publicKeyBase = hexToBytes(trail.publicKeyBase);

  // Build list of all state addresses
  const stateAddresses = [];
  for (let i = 0; i < trail.states.length; i++) {
    const statesUpTo = trail.states.slice(0, i + 1);
    const P = deriveChainedPublicKey(publicKeyBase, statesUpTo);
    const wp = p2trXonly(P);
    const address = encodeBech32m(hrp, wp);
    stateAddresses.push({ index: i, states: statesUpTo, wp, address });
  }

  // Find which address has UTXOs
  console.log('Scanning for UTXOs...');
  let sourceIndex = -1;
  let utxos = [];

  for (let i = 0; i < stateAddresses.length; i++) {
    const { address, index } = stateAddresses[i];
    try {
      const found = await getUtxos(address, network);
      if (found.length > 0) {
        sourceIndex = index;
        utxos = found.map(u => ({ ...u, witnessProgram: stateAddresses[i].wp }));
        const label = index === 0 ? 'GENESIS' : index === trail.states.length - 1 ? 'HEAD' : `State ${index}`;
        console.log(`Found ${utxos.length} UTXO(s) at [${index}] ${label}: ${utxos.reduce((s, u) => s + u.amount, 0)} sats`);
        break;
      }
    } catch (e) {
      console.error(`Error checking state ${i}: ${e.message}`);
    }
  }

  if (sourceIndex === -1) {
    console.error('No UTXOs found at any state address.');
    console.error('Run "fund" first to move funds from base → GENESIS.');
    process.exit(1);
  }

  // Determine destination
  let destIndex;
  let destStates;
  let addNewState = false;

  if (newState) {
    // Adding new state - must be at HEAD
    if (sourceIndex !== trail.states.length - 1) {
      console.error(`Cannot add new state: funds are at state ${sourceIndex}, not HEAD (${trail.states.length - 1}).`);
      console.error('Run "spend" without arguments to advance to HEAD first.');
      process.exit(1);
    }
    destStates = [...trail.states, newState];
    destIndex = trail.states.length;
    addNewState = true;
  } else {
    // Advancing to next existing state
    if (sourceIndex >= trail.states.length - 1) {
      console.error('Already at HEAD. Provide a new state to advance further.');
      console.error('Usage: blocktrails spend <new-state>');
      process.exit(1);
    }
    destIndex = sourceIndex + 1;
    destStates = trail.states.slice(0, destIndex + 1);
  }

  const destP = deriveChainedPublicKey(publicKeyBase, destStates);
  const destWP = p2trXonly(destP);
  const destAddress = encodeBech32m(hrp, destWP);
  const destLabel = addNewState ? 'NEW' : (destIndex === 0 ? 'GENESIS' : destIndex === trail.states.length - 1 ? 'HEAD' : `State ${destIndex}`);

  console.log(`Destination: [${destIndex}] ${destLabel} → ${destAddress}`);

  // Calculate fee
  let feeRate = options.feeRate;
  if (!feeRate) {
    try {
      const rates = await getFeeRates(network);
      feeRate = rates.halfHour;
      console.log(`Using fee rate: ${feeRate} sat/vB`);
    } catch {
      feeRate = 1;
      console.log(`Using default fee rate: ${feeRate} sat/vB`);
    }
  }

  const vsize = estimateVsize(utxos.length, 1);
  const fee = Math.ceil(vsize * feeRate);
  const totalIn = utxos.reduce((sum, u) => sum + u.amount, 0);
  const outputAmount = totalIn - fee;

  if (outputAmount <= 546) {
    console.error(`Insufficient funds: ${totalIn} sats, fee ${fee} sats`);
    process.exit(1);
  }

  // Get signing key for source state
  const sourceStates = trail.states.slice(0, sourceIndex + 1);
  const signingKey = deriveChainedPrivateKey(hexToBytes(privateKey), sourceStates);

  // Build transaction
  const tx = buildTransaction({
    inputs: utxos.map(u => ({
      txid: u.txid,
      vout: u.vout,
      amount: u.amount,
      witnessProgram: u.witnessProgram
    })),
    outputs: [{
      witnessProgram: destWP,
      value: outputAmount
    }]
  });

  // Sign transaction
  const signingKeys = utxos.map(() => signingKey);
  const signedTx = signTransaction(tx, signingKeys, utxos);

  // Serialize
  const txBytes = serializeTransaction(signedTx);
  const txHex = bytesToHex(txBytes);
  const txid = computeTxid(signedTx);

  console.log('');
  console.log(`Transaction: [${sourceIndex}] → [${destIndex}] ${destLabel}`);
  console.log(`  TXID: ${txid}`);
  console.log(`  Fee: ${fee} sats (${feeRate} sat/vB)`);
  console.log(`  Output: ${outputAmount} sats → ${destAddress}`);
  if (addNewState) {
    const statePreview = newState.length > 40 ? newState.slice(0, 37) + '...' : newState;
    console.log(`  New state: ${statePreview}`);
  }

  if (options.showRaw) {
    console.log('');
    console.log('Raw transaction:');
    console.log(txHex);
  }

  // Broadcast if requested
  if (options.broadcast) {
    console.log('');
    console.log('Broadcasting...');
    try {
      const broadcastTxid = await broadcastTx(txHex, network);
      console.log(`✓ Broadcast successful!`);
      console.log(`  TXID: ${broadcastTxid}`);

      // Update trail file only if adding new state
      if (addNewState) {
        trail.states.push(newState);
        const path = getTrailPath(options);
        writeFileSync(path, JSON.stringify(trail, null, 2) + '\n');
        console.log(`  Trail updated: ${path}`);
      }
    } catch (e) {
      console.error(`✗ Broadcast failed: ${e.message}`);
      process.exit(1);
    }
  } else {
    console.log('');
    console.log('Dry run complete. Use --broadcast to send transaction.');
  }
}

async function cmdExodus(destAddress, options) {
  // Validate destination address
  let destWP;
  try {
    const decoded = decodeBech32m(destAddress);
    destWP = decoded.witnessProgram;
  } catch (e) {
    console.error(`Invalid destination address: ${e.message}`);
    process.exit(1);
  }

  // Load trail
  const trail = loadTrail(options);
  if (!trail || trail.states.length === 0) {
    console.error('No trail found. Run "genesis" first.');
    process.exit(1);
  }

  // Get private key
  const privateKey = getPrivateKey(options);
  if (!privateKey) {
    console.error('No private key found. Use --key or set git config nostr.privkey');
    process.exit(1);
  }

  // Verify private key matches trail
  const publicKey = secp.getPublicKey(hexToBytes(privateKey), true);
  if (bytesToHex(publicKey) !== trail.publicKeyBase) {
    console.error('Private key does not match trail public key');
    process.exit(1);
  }

  const network = trail.network || 'tbtc4';
  const hrp = getHrp(network);
  const publicKeyBase = hexToBytes(trail.publicKeyBase);

  // Build list of all state addresses
  const stateAddresses = [];
  for (let i = 0; i < trail.states.length; i++) {
    const statesUpTo = trail.states.slice(0, i + 1);
    const P = deriveChainedPublicKey(publicKeyBase, statesUpTo);
    const wp = p2trXonly(P);
    const address = encodeBech32m(hrp, wp);
    stateAddresses.push({ index: i, states: statesUpTo, wp, address });
  }

  // Find which address has UTXOs
  console.log('Scanning for UTXOs...');
  let sourceIndex = -1;
  let utxos = [];

  for (let i = 0; i < stateAddresses.length; i++) {
    const { address, index } = stateAddresses[i];
    try {
      const found = await getUtxos(address, network);
      if (found.length > 0) {
        sourceIndex = index;
        utxos = found.map(u => ({ ...u, witnessProgram: stateAddresses[i].wp }));
        const label = index === 0 ? 'GENESIS' : index === trail.states.length - 1 ? 'HEAD' : `State ${index}`;
        console.log(`Found ${utxos.length} UTXO(s) at [${index}] ${label}: ${utxos.reduce((s, u) => s + u.amount, 0)} sats`);
        break;
      }
    } catch (e) {
      console.error(`Error checking state ${i}: ${e.message}`);
    }
  }

  if (sourceIndex === -1) {
    console.error('No UTXOs found at any state address.');
    console.error('Nothing to exodus.');
    process.exit(1);
  }

  console.log(`Destination: ${destAddress}`);

  // Calculate fee
  let feeRate = options.feeRate;
  if (!feeRate) {
    try {
      const rates = await getFeeRates(network);
      feeRate = rates.halfHour;
      console.log(`Using fee rate: ${feeRate} sat/vB`);
    } catch {
      feeRate = 1;
      console.log(`Using default fee rate: ${feeRate} sat/vB`);
    }
  }

  const vsize = estimateVsize(utxos.length, 1);
  const fee = Math.ceil(vsize * feeRate);
  const totalIn = utxos.reduce((sum, u) => sum + u.amount, 0);
  const outputAmount = totalIn - fee;

  if (outputAmount <= 546) {
    console.error(`Insufficient funds: ${totalIn} sats, fee ${fee} sats`);
    process.exit(1);
  }

  // Get signing key for source state
  const sourceStates = trail.states.slice(0, sourceIndex + 1);
  const signingKey = deriveChainedPrivateKey(hexToBytes(privateKey), sourceStates);

  // Build transaction
  const tx = buildTransaction({
    inputs: utxos.map(u => ({
      txid: u.txid,
      vout: u.vout,
      amount: u.amount,
      witnessProgram: u.witnessProgram
    })),
    outputs: [{
      witnessProgram: destWP,
      value: outputAmount
    }]
  });

  // Sign transaction
  const signingKeys = utxos.map(() => signingKey);
  const signedTx = signTransaction(tx, signingKeys, utxos);

  // Serialize
  const txBytes = serializeTransaction(signedTx);
  const txHex = bytesToHex(txBytes);
  const txid = computeTxid(signedTx);

  const sourceLabel = sourceIndex === 0 ? 'GENESIS' : sourceIndex === trail.states.length - 1 ? 'HEAD' : `State ${sourceIndex}`;

  console.log('');
  console.log(`Exodus transaction: [${sourceIndex}] ${sourceLabel} → external`);
  console.log(`  TXID: ${txid}`);
  console.log(`  Fee: ${fee} sats (${feeRate} sat/vB)`);
  console.log(`  Output: ${outputAmount} sats → ${destAddress}`);

  if (options.showRaw) {
    console.log('');
    console.log('Raw transaction:');
    console.log(txHex);
  }

  // Broadcast if requested
  if (options.broadcast) {
    console.log('');
    console.log('Broadcasting...');
    try {
      const broadcastTxid = await broadcastTx(txHex, network);
      console.log(`✓ Broadcast successful!`);
      console.log(`  TXID: ${broadcastTxid}`);
      console.log('');
      console.log('Note: Trail file unchanged. Funds have exited the trail.');
    } catch (e) {
      console.error(`✗ Broadcast failed: ${e.message}`);
      process.exit(1);
    }
  } else {
    console.log('');
    console.log('Dry run complete. Use --broadcast to send transaction.');
  }
}

// ============================================
// Cache Management
// ============================================

function cmdCache(subcommand, options) {
  const network = options.network || 'tbtc4';

  if (subcommand === 'clear') {
    clearCache(network);
    console.log(`Cache cleared for ${network}`);
    return;
  }

  if (subcommand === 'path') {
    console.log(getCacheDir(network));
    return;
  }

  // Default: show stats
  const stats = getCacheStats(network);
  console.log(`Cache: ${getCacheDir(network)}`);
  console.log(`Network: ${network}`);
  console.log(`Transactions: ${stats.count}`);
  console.log(`Size: ${stats.sizeHuman}`);
}

// ============================================
// Nostr Publishing
// ============================================

const DEFAULT_RELAY = 'wss://relay.damus.io';

async function cmdPublish(options) {
  // Load trail
  const trail = loadTrail(options);
  if (!trail) {
    console.error('No trail found. Run "init" or "genesis" first.');
    process.exit(1);
  }

  // Get private key
  const privateKey = getPrivateKey(options);
  if (!privateKey) {
    console.error('No private key found. Use --key or set git config nostr.privkey');
    process.exit(1);
  }

  // Verify private key matches trail
  const publicKey = secp.getPublicKey(hexToBytes(privateKey), true);
  if (bytesToHex(publicKey) !== trail.publicKeyBase) {
    console.error('Private key does not match trail public key');
    process.exit(1);
  }

  // Get x-only pubkey (32 bytes) for Nostr
  const xOnlyPubkey = bytesToHex(publicKey.slice(1)); // Remove prefix byte

  const relay = options.relay || DEFAULT_RELAY;

  // Create Nostr event (kind 30333 - parameterized replaceable)
  const eventTemplate = {
    kind: 30333,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['d', xOnlyPubkey], // d-tag = pubkey for uniqueness
      ['t', 'blocktrail'],
      ['n', trail.network || 'tbtc4'],
      ['tip', String(trail.states.length)]
    ],
    content: JSON.stringify(trail)
  };

  // Sign the event with nostr-tools
  const signedEvent = finalizeEvent(eventTemplate, hexToBytes(privateKey));

  console.log(`Publishing trail to ${relay}`);
  console.log(`  Pubkey: ${xOnlyPubkey}`);
  console.log(`  States: ${trail.states.length}`);
  console.log(`  Event ID: ${signedEvent.id}`);

  // Connect and publish
  let relayConn;
  try {
    relayConn = await Relay.connect(relay);
    console.log(`  Connected to ${relay}`);

    await relayConn.publish(signedEvent);
    console.log(`✓ Published successfully`);
  } catch (e) {
    console.error(`✗ Publish failed: ${e.message}`);
    process.exit(1);
  } finally {
    if (relayConn) {
      relayConn.close();
    }
  }
}

// ============================================
// Argument Parsing
// ============================================

function parseArgs(args) {
  const options = { utxo: [] };
  const positional = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--key' || arg === '-k') {
      options.key = args[++i];
    } else if (arg === '--file' || arg === '-f') {
      options.file = args[++i];
    } else if (arg === '--network' || arg === '-n') {
      options.network = args[++i];
    } else if (arg === '--output' || arg === '-o') {
      options.output = args[++i];
    } else if (arg === '--force') {
      options.force = true;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--version' || arg === '-v') {
      options.version = true;
    } else if (arg === '--utxo' || arg === '-u') {
      options.utxo.push(args[++i]);
    } else if (arg === '--fee-rate' || arg === '--fee') {
      options.feeRate = parseFloat(args[++i]);
    } else if (arg === '--broadcast' || arg === '-b') {
      options.broadcast = true;
    } else if (arg === '--raw' || arg === '-r') {
      options.showRaw = true;
    } else if (arg === '--online') {
      options.online = true;
    } else if (arg === '--relay') {
      options.relay = args[++i];
    } else if (!arg.startsWith('-')) {
      positional.push(arg);
    }
  }

  return { options, positional };
}

function showHelp() {
  console.log(`
blocktrails - Nostr-native state on Bitcoin

Usage:
  blocktrails <command> [options]

Commands:
  init                    Create new trail (uses git config nostr.privkey if available)
  genesis <state>         Create genesis state (off-chain)
  advance <state>         Advance to new state (off-chain)
  fund                    Move funds from base address to GENESIS (on-chain)
  spend [state]           Advance on-chain (to next state, or new state if provided)
  exodus <address>        Send funds to external address (exit trail)
  show                    Show trail status (add --online for on-chain status)
  export                  Export trail with witness programs
  verify [file]           Verify a trail
  cache [clear|path]      Show cache stats, clear cache, or show cache path
  publish                 Publish trail to Nostr relay

Options:
  -k, --key <hex>         Private key (hex)
  -f, --file <path>       Trail file (default: .blocktrail.json)
  -n, --network <net>     Network: mainnet or tbtc4 (default: tbtc4)
  -o, --output <path>     Output file for export
  --force                 Overwrite existing files
  -h, --help              Show this help
  -v, --version           Show version

Spend Options:
  -u, --utxo <txid:vout:amount>   UTXO to spend (repeatable, or auto-fetch)
  --fee-rate <sat/vB>             Fee rate (default: auto-fetch)
  -b, --broadcast                 Broadcast transaction
  -r, --raw                       Show raw transaction hex

Nostr Options:
  --relay <url>                   Relay URL (default: wss://relay.damus.io)

Key Sources (in priority order):
  1. --key flag
  2. git config nostr.privkey
  3. Generated (for init only)

Examples:
  blocktrails init
  blocktrails genesis '{"counter": 0}'
  blocktrails advance '{"counter": 1}'
  blocktrails fund --broadcast              # base → GENESIS
  blocktrails spend --broadcast             # GENESIS → State 1
  blocktrails spend '{"counter": 2}' -b     # HEAD → new state
  blocktrails exodus tb1p... --broadcast    # exit trail to external address
  blocktrails show --online
  blocktrails export -o trail.json
  blocktrails verify trail.json
  blocktrails publish                       # publish to Nostr relay
`);
}

function showVersion() {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  console.log(`blocktrails v${pkg.version}`);
}

// ============================================
// Main
// ============================================

async function main() {
  const { options, positional } = parseArgs(process.argv.slice(2));

  if (options.version) {
    showVersion();
    process.exit(0);
  }

  if (options.help || positional.length === 0) {
    showHelp();
    process.exit(options.help ? 0 : 1);
  }

  const command = positional[0];

  try {
    switch (command) {
      case 'init':
        cmdInit(options);
        break;

      case 'genesis':
        if (!positional[1]) {
          console.error('Usage: blocktrails genesis <state>');
          process.exit(1);
        }
        cmdGenesis(positional[1], options);
        break;

      case 'advance':
        if (!positional[1]) {
          console.error('Usage: blocktrails advance <state>');
          process.exit(1);
        }
        cmdAdvance(positional[1], options);
        break;

      case 'show':
        await cmdShow(options);
        break;

      case 'export':
        cmdExport(options);
        break;

      case 'verify':
        cmdVerify(positional[1], options);
        break;

      case 'fund':
        await cmdFund(options);
        break;

      case 'spend':
        await cmdSpend(positional[1], options); // positional[1] may be undefined
        break;

      case 'exodus':
        if (!positional[1]) {
          console.error('Usage: blocktrails exodus <destination-address>');
          process.exit(1);
        }
        await cmdExodus(positional[1], options);
        break;

      case 'cache':
        cmdCache(positional[1], options); // subcommand: clear, path, or undefined
        break;

      case 'publish':
        await cmdPublish(options);
        break;

      default:
        console.error(`Unknown command: ${command}`);
        showHelp();
        process.exit(1);
    }
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
}

main();
