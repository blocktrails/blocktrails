/**
 * Blocktrails Browser Bundle
 *
 * Re-exports everything except Node.js-specific cache module.
 * Use: import * as blocktrails from 'blocktrails/browser'
 */

// Core key derivation and verification
export {
  scalar,
  computeTweak,
  derivePrivateKey,
  derivePublicKey,
  derivePrivkey,
  derivePubkey,
  deriveChainedPrivateKey,
  deriveChainedPublicKey,
  deriveChainedPrivkey,
  deriveChainedPubkey,
  p2trXonly,
  hasEvenY,
  adjustPrivateKeyForSigning,
  adjustPrivkeyForSigning,
  genesis,
  transition,
  verify,
  Blocktrail,
  bytesToHex,
  hexToBytes
} from './index.js';

// Transaction building and signing
export {
  signSchnorr,
  verifySchnorr,
  buildTransaction,
  signTransaction,
  serializeTransaction,
  computeTxid,
  computeTapSighash,
  createP2TRScript,
  estimateVsize,
  taggedHash,
  concatBytes,
  reverseBytes,
  writeUint32LE,
  writeUint64LE,
  writeVarInt
} from './transaction.js';

// Network broadcasting (browser-compatible, no cache)
const ENDPOINTS = {
  btc: 'https://mempool.guide/api',
  tbtc3: 'https://mempool.guide/testnet/api',
  tbtc4: 'https://mempool.guide/testnet4/api',
  ltc: 'https://litecoinspace.org/api'
};

/**
 * Get UTXOs for a Bitcoin address
 */
export async function getUtxos(address, network = 'tbtc4') {
  const base = ENDPOINTS[network];
  if (!base) throw new Error(`Unknown network: ${network}`);

  const response = await fetch(`${base}/address/${address}/utxo`);
  if (!response.ok) throw new Error(`API error: ${response.status}`);

  const utxos = await response.json();
  return utxos.map(u => ({
    txid: u.txid,
    vout: u.vout,
    amount: u.value,
    confirmed: u.status?.confirmed ?? false,
    blockHeight: u.status?.block_height ?? null
  }));
}

/**
 * Broadcast a raw transaction
 */
export async function broadcast(txHex, network = 'tbtc4') {
  const base = ENDPOINTS[network];
  if (!base) throw new Error(`Unknown network: ${network}`);

  const response = await fetch(`${base}/tx`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: txHex
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Broadcast failed: ${text}`);
  }

  return response.text();
}

/**
 * Get recommended fee rates
 */
export async function getFeeRates(network = 'tbtc4') {
  const base = ENDPOINTS[network];
  if (!base) throw new Error(`Unknown network: ${network}`);

  const response = await fetch(`${base}/v1/fees/recommended`);
  if (!response.ok) throw new Error(`API error: ${response.status}`);

  const fees = await response.json();
  return {
    fastest: fees.fastestFee || 1,
    halfHour: fees.halfHourFee || 1,
    hour: fees.hourFee || 1,
    economy: fees.economyFee || 1,
    minimum: fees.minimumFee || 1
  };
}

/**
 * Get transaction details
 */
export async function getTransaction(txid, network = 'tbtc4') {
  const base = ENDPOINTS[network];
  if (!base) throw new Error(`Unknown network: ${network}`);

  const response = await fetch(`${base}/tx/${txid}`);
  if (!response.ok) throw new Error(`API error: ${response.status}`);

  return response.json();
}

/**
 * Get address transaction history
 */
export async function getAddressTxs(address, network = 'tbtc4') {
  const base = ENDPOINTS[network];
  if (!base) throw new Error(`Unknown network: ${network}`);

  const response = await fetch(`${base}/address/${address}/txs`);
  if (!response.ok) throw new Error(`API error: ${response.status}`);

  return response.json();
}
