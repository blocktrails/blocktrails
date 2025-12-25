/**
 * Local SPV Cache - Transaction data storage
 *
 * Caches transaction data in ~/.spv/{network}/tx/{txid}.json
 * Reduces API calls and enables offline access to previously fetched data.
 *
 * Schema designed to allow future extension with merkle proofs.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, statSync, unlinkSync, rmdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

/**
 * Get cache directory for a network
 * @param {string} network - 'btc', 'tbtc3', 'tbtc4', or 'ltc'
 * @returns {string} Cache directory path
 */
export function getCacheDir(network = 'tbtc4') {
  const dir = join(homedir(), '.spv', network, 'tx');
  return dir;
}

/**
 * Ensure cache directory exists
 * @param {string} network - 'btc', 'tbtc3', 'tbtc4', or 'ltc'
 */
function ensureCacheDir(network) {
  const dir = getCacheDir(network);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

/**
 * Get cached transaction
 * @param {string} txid - Transaction ID
 * @param {string} network - 'btc', 'tbtc3', 'tbtc4', or 'ltc'
 * @returns {Object|null} Cached transaction data or null if not cached
 */
export function getCachedTx(txid, network = 'tbtc4') {
  const file = join(getCacheDir(network), `${txid}.json`);

  if (!existsSync(file)) {
    return null;
  }

  try {
    const data = readFileSync(file, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    // Corrupted cache file, ignore
    return null;
  }
}

/**
 * Cache a transaction
 * @param {string} txid - Transaction ID
 * @param {Object} txData - Transaction data from API
 * @param {string} network - 'btc', 'tbtc3', 'tbtc4', or 'ltc'
 */
export function cacheTx(txid, txData, network = 'tbtc4') {
  ensureCacheDir(network);

  const cached = {
    // Core data
    txid: txData.txid,
    version: txData.version,
    locktime: txData.locktime,

    // Inputs/outputs
    vin: txData.vin,
    vout: txData.vout,

    // Block info (if confirmed)
    confirmed: txData.status?.confirmed ?? false,
    blockHash: txData.status?.block_hash ?? null,
    blockHeight: txData.status?.block_height ?? null,
    blockTime: txData.status?.block_time ?? null,

    // Fee info
    fee: txData.fee ?? null,

    // Metadata
    cachedAt: Date.now(),

    // Reserved for future SPV proofs
    // merkleProof: null,
    // merkleIndex: null,
    // blockHeader: null
  };

  const file = join(getCacheDir(network), `${txid}.json`);
  writeFileSync(file, JSON.stringify(cached, null, 2));
}

/**
 * Check if transaction is cached and confirmed
 * @param {string} txid - Transaction ID
 * @param {string} network - 'btc', 'tbtc3', 'tbtc4', or 'ltc'
 * @returns {boolean} True if cached and confirmed
 */
export function isCachedAndConfirmed(txid, network = 'tbtc4') {
  const cached = getCachedTx(txid, network);
  return cached?.confirmed === true;
}

/**
 * Clear cache for a network
 * @param {string} network - 'btc', 'tbtc3', 'tbtc4', or 'ltc'
 * @param {boolean} removeDir - Also remove the directory
 */
export function clearCache(network = 'tbtc4', removeDir = false) {
  const dir = getCacheDir(network);
  if (existsSync(dir)) {
    for (const file of readdirSync(dir)) {
      unlinkSync(join(dir, file));
    }
    if (removeDir) {
      rmdirSync(dir);
      // Also try to remove parent dirs if empty
      const networkDir = join(homedir(), '.spv', network);
      try { rmdirSync(networkDir); } catch { /* not empty */ }
    }
  }
}

/**
 * Get cache stats
 * @param {string} network - 'btc', 'tbtc3', 'tbtc4', or 'ltc'
 * @returns {Object} Cache statistics
 */
export function getCacheStats(network = 'tbtc4') {
  const dir = getCacheDir(network);

  if (!existsSync(dir)) {
    return { count: 0, size: 0, sizeHuman: '0B' };
  }

  const files = readdirSync(dir).filter(f => f.endsWith('.json'));
  let size = 0;

  for (const file of files) {
    try {
      size += statSync(join(dir, file)).size;
    } catch (e) {
      // Ignore errors
    }
  }

  return {
    count: files.length,
    size,
    sizeHuman: size < 1024 ? `${size}B` :
               size < 1024 * 1024 ? `${(size / 1024).toFixed(1)}KB` :
               `${(size / 1024 / 1024).toFixed(1)}MB`
  };
}
