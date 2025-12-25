# blocktrails

Reference implementation of [Blocktrails](https://blocktrails.org) — Nostr-native state anchoring on Bitcoin.

**[Live Demo](https://blocktrails.org/demo/)** · **[Specification](https://blocktrails.org/spec/)** · **[Profiles (MRC20)](https://blocktrails.org/spec/profiles.html)** · **[NATEOS Viewer](https://play-grounds.github.io/blocktrails/)**

## What is this?

Blocktrails lets you anchor off-chain state to Bitcoin using Taproot. Each state produces a unique P2TR address. Spending from that address proves a state transition. The chain of spends *is* the state history — immutably ordered by Bitcoin.

```
base_key + sha256(state) = derived_key → P2TR address
```

Use cases: token ledgers, audit trails, Nostr identity anchoring, verifiable logs.

## Install

```bash
npm install blocktrails
```

## Quick Start

```javascript
import { Blocktrail } from 'blocktrails';

// Create a trail with your Nostr-compatible private key
const trail = new Blocktrail(privateKey);

// Genesis — commit first state to a P2TR address
const genesis = trail.genesis(JSON.stringify({ balance: 1000 }));
console.log(genesis.p2trAddress); // bc1p...

// Advance — each state gets a new address
const next = trail.advance(JSON.stringify({ balance: 900 }));
console.log(next.newP2trAddress); // bc1p... (different!)

// Verify — anyone with pubkey + states can verify
const { valid } = trail.verify(witnessPrograms);
```

## How It Works

```
┌─────────────┐    scalar()    ┌─────────────┐    P2TR    ┌─────────────┐
│   State 0   │ ────────────▶  │  Address 0  │ ─────────▶ │   UTXO 0    │
└─────────────┘                └─────────────┘    fund    └──────┬──────┘
                                                                 │ spend
┌─────────────┐    scalar()    ┌─────────────┐    P2TR    ┌──────▼──────┐
│   State 1   │ ────────────▶  │  Address 1  │ ◀───────── │   UTXO 1    │
└─────────────┘                └─────────────┘            └──────┬──────┘
                                                                 │ spend
                                    ...                          ▼
```

Each state transition is a Bitcoin transaction. No special opcodes, just key tweaking.

## API

### Blocktrail Class

```javascript
import { Blocktrail } from 'blocktrails';

const trail = new Blocktrail(privateKey);

trail.genesis('state 0');           // Initialize
trail.advance('state 1');           // Transition
trail.advance('state 2');           // Transition

trail.currentState();               // 'state 2'
trail.currentWitnessProgram();      // Uint8Array (32 bytes)
trail.export();                     // { pubkeyBase, states, witnessPrograms }
```

### Standalone Functions

```javascript
import { genesis, transition, verify } from 'blocktrails';

// Create genesis
const g = genesis(privateKeyBytes, 'initial state');
// → { witnessProgram, p2trAddress, derivedPrivkey, derivedPubkey }

// Create transition
const t = transition(privateKeyBytes, 'state 0', 'state 1');
// → { signingPrivkey, prevWitnessProgram, newWitnessProgram, newP2trAddress }

// Verify chain
const result = verify(pubkeyBase, states, witnessPrograms);
// → { valid: true } or { valid: false, error: '...' }
```

### Low-Level Primitives

```javascript
import {
  scalar,            // sha256(state) mod n — the core tweak function
  derivePrivateKey,  // d_base + t
  derivePublicKey,   // P_base + t·G
  p2trXonly,         // Compress to 32-byte x-only
  adjustPrivateKeyForSigning, // BIP-340 parity adjustment
} from 'blocktrails';

// Example: derive address from state
const t = scalar(JSON.stringify({ counter: 42 }));
const P = derivePublicKey(pubkeyBase, state);
const witnessProgram = p2trXonly(P);
```

## CLI

```bash
# Install globally
npm install -g blocktrails

# Initialize a new trail
blocktrails init

# Mark state (unified command - broadcasts by default)
blocktrails mark '{"balance": 1000}'     # genesis + fund
blocktrails mark '{"balance": 900}'      # advance + spend
blocktrails mark '{"balance": 800}' --dry  # dry run (no broadcast)

# Or use separate commands
blocktrails genesis '{"balance": 1000}'  # off-chain only
blocktrails advance '{"balance": 900}'   # off-chain only
blocktrails fund --broadcast             # base → GENESIS
blocktrails spend --broadcast            # GENESIS → State 1

# Exit trail - send funds to external address
blocktrails exodus tb1p... --broadcast

# Publish to Nostr (NATEOS)
blocktrails publish --relay wss://relay.damus.io

# View trail with on-chain status
blocktrails show --online
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `init` | Create new trail (generates key or uses `git config nostr.privkey`) |
| `mark <state>` | **Unified command** — add state and broadcast (use `--dry` for dry run) |
| `genesis <state>` | Create genesis state (off-chain only) |
| `advance <state>` | Advance to new state (off-chain only) |
| `fund` | Move funds from base address to GENESIS (on-chain) |
| `spend [state]` | Advance on-chain (to next state, or new state if provided) |
| `exodus <address>` | Send funds to external address (exit trail) |
| `publish` | Publish trail to Nostr relay (NATEOS) |
| `show` | Show trail status (add `--online` for on-chain status) |
| `export` | Export trail with witness programs |
| `verify [file]` | Verify a trail |
| `cache [clear\|path]` | Show cache stats, clear cache, or show path |

### Supported Networks

Use `--network` or `-n` to specify: `btc`, `tbtc3`, `tbtc4` (default), `ltc`

## Transaction API

```javascript
import {
  buildTransaction,
  signTransaction,
  serializeTransaction,
  broadcast,
  getUtxos,
  getFeeRates
} from 'blocktrails';

// Fetch UTXOs and fee rate
const utxos = await getUtxos(address, 'tbtc4');
const { halfHour } = await getFeeRates('tbtc4');

// Build and sign P2TR transaction
const tx = buildTransaction({
  inputs: utxos.map(u => ({ ...u, witnessProgram })),
  outputs: [{ witnessProgram: newWP, value: amount }]
});
const signed = signTransaction(tx, [signingKey], utxos);
const txHex = bytesToHex(serializeTransaction(signed));

// Broadcast
const txid = await broadcast(txHex, 'tbtc4');
```

## Local Cache

Transaction data is cached locally in `~/.spv/{network}/tx/` to reduce API calls and enable offline access to previously fetched data.

```bash
# View cache stats
blocktrails cache

# Clear cache
blocktrails cache clear

# Show cache directory
blocktrails cache path
```

```javascript
import {
  getCachedTx,
  cacheTx,
  getCacheStats,
  clearCache
} from 'blocktrails';

// getTransaction() automatically uses cache
const tx = await getTransaction(txid, 'tbtc4');

// Manual cache access
const cached = getCachedTx(txid, 'tbtc4');
const stats = getCacheStats('tbtc4');  // { count, size, sizeHuman }
```

## Run Demo

```bash
npm run demo
```

Or try the [live interactive demo](https://blocktrails.org/demo/) on testnet4.

## Run Tests

```bash
npm test  # 107 tests
```

## Specification

- **[Core Spec](https://blocktrails.org/spec/)** — The primitive: key tweaking, state commitment, verification
- **[Profiles](https://blocktrails.org/spec/profiles.html)** — Application schemas: Monochrome (generic), MRC20 (fungible tokens)

## License

MIT
