#!/usr/bin/env node
/**
 * Blocktrails CLI
 * Nostr-native output-key commitment chaining on Bitcoin
 */

import { execSync } from 'child_process';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import * as secp from '@noble/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { Blocktrail, verify, p2trXonly, deriveChainedPublicKey, scalar } from './index.js';

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

function cmdGenesis(state, options) {
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

function cmdAdvance(state, options) {
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

  const result = trail.advance(state);

  const path = saveTrail(trail, { ...options, network: existingTrail.network });
  const hrp = getHrp(existingTrail.network || 'tbtc4');
  const address = encodeBech32m(hrp, hexToBytes(result.newWitnessProgram));

  console.log(`State ${trail.states.length - 1} -> ${trail.states.length}`);
  console.log(`State: ${state}`);
  console.log(`Address: ${address}`);
  console.log(`Saved: ${path}`);
}

function cmdShow(options) {
  const trail = loadTrail(options);

  if (!trail) {
    console.error('No trail found. Run "init" or "genesis" first.');
    process.exit(1);
  }

  const hrp = getHrp(trail.network || 'tbtc4');
  const publicKeyBase = hexToBytes(trail.publicKeyBase);

  console.log(`Trail: ${getTrailPath(options)}`);
  console.log(`Network: ${trail.network || 'tbtc4'}`);
  console.log(`Public key: ${trail.publicKeyBase}`);
  console.log(`States: ${trail.states.length}`);
  console.log('');

  if (trail.states.length === 0) {
    console.log('No states yet. Run "genesis" to create initial state.');
    return;
  }

  // Show each state with its address
  let P = secp.ProjectivePoint.fromHex(publicKeyBase);

  for (let i = 0; i < trail.states.length; i++) {
    const state = trail.states[i];
    const t = scalar(state);
    const tG = secp.ProjectivePoint.BASE.multiply(t);
    P = P.add(tG);

    const wp = p2trXonly(P.toRawBytes(true));
    const address = encodeBech32m(hrp, wp);

    const label = i === 0 ? 'GENESIS' : i === trail.states.length - 1 ? 'HEAD' : `State ${i}`;
    const statePreview = state.length > 50 ? state.slice(0, 47) + '...' : state;

    console.log(`[${i}] ${label}`);
    console.log(`    State: ${statePreview}`);
    console.log(`    Address: ${address}`);
    if (i < trail.states.length - 1) console.log('    ↓');
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

// ============================================
// Argument Parsing
// ============================================

function parseArgs(args) {
  const options = {};
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
  genesis <state>         Create genesis state
  advance <state>         Advance to new state
  show                    Show current trail status
  export                  Export trail with witness programs
  verify [file]           Verify a trail

Options:
  -k, --key <hex>         Private key (hex)
  -f, --file <path>       Trail file (default: .blocktrail.json)
  -n, --network <net>     Network: mainnet or tbtc4 (default: tbtc4)
  -o, --output <path>     Output file for export
  --force                 Overwrite existing files
  -h, --help              Show this help
  -v, --version           Show version

Key Sources (in priority order):
  1. --key flag
  2. git config nostr.privkey
  3. Generated (for init only)

Examples:
  blocktrails init
  blocktrails genesis '{"counter": 0}'
  blocktrails advance '{"counter": 1}'
  blocktrails show
  blocktrails export -o trail.json
  blocktrails verify trail.json
`);
}

function showVersion() {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  console.log(`blocktrails v${pkg.version}`);
}

// ============================================
// Main
// ============================================

function main() {
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
        cmdShow(options);
        break;

      case 'export':
        cmdExport(options);
        break;

      case 'verify':
        cmdVerify(positional[1], options);
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
