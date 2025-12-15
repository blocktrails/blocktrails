# blocktrails-js

Reference implementation of [Blocktrails](https://blocktrails.github.io) — Nostr-native output-key commitment chaining on Bitcoin.

## Install

```bash
npm install blocktrails
```

## Quick Start

```javascript
import { Blocktrail } from 'blocktrails';

// Create a trail with your private key
const trail = new Blocktrail(privateKey);

// Genesis - first state
const genesis = trail.genesis(JSON.stringify({ balance: 1000 }));
console.log(genesis.p2trAddress); // bc1p...

// Advance - state transition
const tx = trail.advance(JSON.stringify({ balance: 900 }));
console.log(tx.newP2trAddress); // bc1p... (different)

// Export for verification
const exported = trail.export();
```

## API

### `genesis(privateKey, state)`

Create initial commitment.

```javascript
import { genesis } from 'blocktrails';

const result = genesis(privateKeyBytes, 'initial state');
// {
//   witnessProgram: '...',  // 32-byte x-only pubkey (hex)
//   p2trAddress: 'bc1p...', // P2TR address
//   derivedPrivateKey: '...', // Key for signing
//   derivedPublicKey: '...',  // Full public key
// }
```

### `transition(privateKey, prevState, newState)`

Create state transition.

```javascript
import { transition } from 'blocktrails';

const result = transition(privateKeyBytes, 'state 0', 'state 1');
// {
//   signingPrivateKey: '...',   // Sign prev output with this
//   prevWitnessProgram: '...',  // What we're spending
//   newWitnessProgram: '...',   // New output
//   newP2trAddress: 'bc1p...',
// }
```

### `verify(publicKeyBase, states, witnessPrograms)`

Verify a state chain.

```javascript
import { verify } from 'blocktrails';

const result = verify(publicKeyBase, states, witnessPrograms);
// { valid: true } or { valid: false, error: '...' }
```

### `Blocktrail` class

Stateful helper for managing a trail.

```javascript
import { Blocktrail } from 'blocktrails';

const trail = new Blocktrail(privateKey);
trail.genesis('state 0');
trail.advance('state 1');
trail.advance('state 2');

trail.currentState();           // 'state 2'
trail.currentWitnessProgram();  // Uint8Array
trail.export();                 // { publicKeyBase, states, witnessPrograms }
```

## Low-level Functions

```javascript
import {
  computeTweak,      // H(state) mod n
  derivePrivateKey,  // d_base + t
  derivePublicKey,   // P_base + t·G
  p2trXonly,         // 33-byte → 32-byte x-only
  hasEvenY,          // Check parity
  adjustPrivateKeyForSigning, // Negate if odd y
} from 'blocktrails';
```

## Run Tests

```bash
npm test
```

## Run Demo

```bash
npm run demo
```

## Spec

See the full specification at [blocktrails.github.io/spec](https://blocktrails.github.io/spec/).

## License

MIT
