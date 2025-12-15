/**
 * Blocktrails Demo
 *
 * This demo shows how to:
 * 1. Create a new Blocktrail
 * 2. Advance through state transitions
 * 3. Verify the trail
 */

import { Blocktrail, verify, hexToBytes, bytesToHex } from '../src/index.js';
import { randomBytes } from 'crypto';

console.log('═══════════════════════════════════════════════════════════');
console.log('                    BLOCKTRAILS DEMO');
console.log('      Nostr-native output-key commitment chaining');
console.log('═══════════════════════════════════════════════════════════\n');

// Generate a random private key (in production, use secure key management!)
const privateKey = randomBytes(32);
console.log('Generated base private key (keep secret!)');
console.log(`  d_base: ${bytesToHex(privateKey).slice(0, 16)}...`);
console.log();

// Create a new Blocktrail
const trail = new Blocktrail(privateKey);

// Define initial state (could be any application data)
const initialState = JSON.stringify({
  type: 'token_ledger',
  version: 1,
  balances: {
    'npub1abc...': 1000000,
    'npub1def...': 500000
  }
});

console.log('─────────────────────────────────────────────────────────────');
console.log('GENESIS');
console.log('─────────────────────────────────────────────────────────────');
const genesis = trail.genesis(initialState);
console.log(`State: ${initialState.slice(0, 50)}...`);
console.log(`Witness Program: ${genesis.witnessProgram}`);
console.log(`P2TR Address: ${genesis.p2trAddress}`);
console.log();

// Simulate some state transitions
const transitions = [
  {
    description: 'Transfer 100000 from abc to def',
    state: JSON.stringify({
      type: 'token_ledger',
      version: 1,
      balances: {
        'npub1abc...': 900000,
        'npub1def...': 600000
      }
    })
  },
  {
    description: 'Transfer 50000 from def to ghi',
    state: JSON.stringify({
      type: 'token_ledger',
      version: 1,
      balances: {
        'npub1abc...': 900000,
        'npub1def...': 550000,
        'npub1ghi...': 50000
      }
    })
  },
  {
    description: 'Mint 100000 to abc (issuer action)',
    state: JSON.stringify({
      type: 'token_ledger',
      version: 1,
      balances: {
        'npub1abc...': 1000000,
        'npub1def...': 550000,
        'npub1ghi...': 50000
      }
    })
  }
];

for (let i = 0; i < transitions.length; i++) {
  const { description, state } = transitions[i];
  console.log('─────────────────────────────────────────────────────────────');
  console.log(`TRANSITION ${i + 1}: ${description}`);
  console.log('─────────────────────────────────────────────────────────────');

  const result = trail.advance(state);
  console.log(`New Witness Program: ${result.newWitnessProgram}`);
  console.log(`P2TR Address: ${result.newP2trAddress}`);
  console.log(`Signing Key (for spending prev): ${result.signingPrivateKey.slice(0, 16)}...`);
  console.log();
}

// Export and verify
console.log('═══════════════════════════════════════════════════════════');
console.log('VERIFICATION');
console.log('═══════════════════════════════════════════════════════════\n');

const exported = trail.export();
console.log(`Trail has ${exported.states.length} states`);
console.log(`Public key base: ${exported.publicKeyBase}`);
console.log();

// Verify the trail
const witnessPrograms = exported.witnessPrograms.map(hexToBytes);
const result = verify(hexToBytes(exported.publicKeyBase), exported.states, witnessPrograms);

if (result.valid) {
  console.log('✓ Trail verification: PASSED');
} else {
  console.log(`✗ Trail verification: FAILED - ${result.error}`);
}

console.log();
console.log('─────────────────────────────────────────────────────────────');
console.log('WITNESS PROGRAM CHAIN');
console.log('─────────────────────────────────────────────────────────────');
for (let i = 0; i < exported.witnessPrograms.length; i++) {
  const wp = exported.witnessPrograms[i];
  console.log(`  [${i}] ${wp.slice(0, 32)}...`);
  if (i < exported.witnessPrograms.length - 1) {
    console.log('       ↓ spend');
  }
}

console.log();
console.log('═══════════════════════════════════════════════════════════');
console.log('                    DEMO COMPLETE');
console.log('═══════════════════════════════════════════════════════════');
console.log();
console.log('In a real application:');
console.log('  • Each witness program becomes a P2TR output on Bitcoin');
console.log('  • Spending requires signing with the derived private key');
console.log('  • Anyone with state history + base pubkey can verify');
console.log('  • State itself lives off-chain (git, IPFS, Nostr relays)');
console.log();
