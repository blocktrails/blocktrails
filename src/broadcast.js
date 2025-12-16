/**
 * Bitcoin Network Broadcasting via Esplora API
 */

import { getCachedTx, cacheTx } from './cache.js';

const ENDPOINTS = {
  mainnet: 'https://blockstream.info/api',
  tbtc4: 'https://mempool.space/testnet4/api'
};

/**
 * Fetch wrapper with error handling
 */
async function fetchApi(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      'User-Agent': 'blocktrails',
      ...options.headers
    }
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API error ${response.status}: ${text}`);
  }

  return response;
}

/**
 * Get UTXOs for a Bitcoin address
 *
 * @param {string} address - Bitcoin address (bc1p... or tb1p...)
 * @param {string} network - 'mainnet' or 'tbtc4'
 * @returns {Promise<Array>} Array of UTXOs
 */
export async function getUtxos(address, network = 'tbtc4') {
  const base = ENDPOINTS[network];
  if (!base) {
    throw new Error(`Unknown network: ${network}`);
  }

  const response = await fetchApi(`${base}/address/${address}/utxo`);
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
 * Get transaction details (with caching)
 *
 * @param {string} txid - Transaction ID
 * @param {string} network - 'mainnet' or 'tbtc4'
 * @param {Object} options - Options
 * @param {boolean} options.skipCache - Skip cache lookup
 * @param {boolean} options.noCache - Don't write to cache
 * @returns {Promise<Object>} Transaction details
 */
export async function getTransaction(txid, network = 'tbtc4', options = {}) {
  const base = ENDPOINTS[network];
  if (!base) {
    throw new Error(`Unknown network: ${network}`);
  }

  // Check cache first (unless skipCache or tx was unconfirmed)
  if (!options.skipCache) {
    const cached = getCachedTx(txid, network);
    if (cached?.confirmed) {
      // Confirmed tx won't change, return cached
      return {
        txid: cached.txid,
        version: cached.version,
        locktime: cached.locktime,
        vin: cached.vin,
        vout: cached.vout,
        fee: cached.fee,
        status: {
          confirmed: cached.confirmed,
          block_hash: cached.blockHash,
          block_height: cached.blockHeight,
          block_time: cached.blockTime
        }
      };
    }
  }

  // Fetch from API
  const response = await fetchApi(`${base}/tx/${txid}`);
  const txData = await response.json();

  // Cache if confirmed (or always cache, will update on next fetch if unconfirmed)
  if (!options.noCache) {
    cacheTx(txid, txData, network);
  }

  return txData;
}

/**
 * Get transaction history for an address
 *
 * @param {string} address - Bitcoin address
 * @param {string} network - 'mainnet' or 'tbtc4'
 * @returns {Promise<Array>} Array of transactions
 */
export async function getAddressTxs(address, network = 'tbtc4') {
  const base = ENDPOINTS[network];
  if (!base) {
    throw new Error(`Unknown network: ${network}`);
  }

  const response = await fetchApi(`${base}/address/${address}/txs`);
  return response.json();
}

/**
 * Broadcast a raw transaction
 *
 * @param {string} txHex - Raw transaction hex
 * @param {string} network - 'mainnet' or 'tbtc4'
 * @returns {Promise<string>} Transaction ID
 */
export async function broadcast(txHex, network = 'tbtc4') {
  const base = ENDPOINTS[network];
  if (!base) {
    throw new Error(`Unknown network: ${network}`);
  }

  const response = await fetchApi(`${base}/tx`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: txHex
  });

  return response.text(); // Returns txid
}

/**
 * Get recommended fee rates
 *
 * @param {string} network - 'mainnet' or 'tbtc4'
 * @returns {Promise<Object>} Fee rates { fastest, halfHour, hour, economy, minimum }
 */
export async function getFeeRates(network = 'tbtc4') {
  const base = ENDPOINTS[network];
  if (!base) {
    throw new Error(`Unknown network: ${network}`);
  }

  const response = await fetchApi(`${base}/v1/fees/recommended`);
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
 * Wait for transaction confirmation
 *
 * @param {string} txid - Transaction ID
 * @param {string} network - 'mainnet' or 'tbtc4'
 * @param {number} timeout - Timeout in milliseconds
 * @param {number} interval - Polling interval in milliseconds
 * @returns {Promise<Object>} Transaction details when confirmed
 */
export async function waitForConfirmation(txid, network = 'tbtc4', timeout = 600000, interval = 10000) {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    try {
      const tx = await getTransaction(txid, network);
      if (tx.status?.confirmed) {
        return tx;
      }
    } catch (e) {
      // Transaction might not be indexed yet
    }

    await new Promise(resolve => setTimeout(resolve, interval));
  }

  throw new Error(`Transaction ${txid} not confirmed within timeout`);
}
