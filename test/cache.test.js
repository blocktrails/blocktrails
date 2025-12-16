/**
 * Cache module tests
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { tmpdir, homedir } from 'os';

// We need to mock homedir for tests
// For now, test the core functions directly

import {
  getCacheDir,
  getCachedTx,
  cacheTx,
  isCachedAndConfirmed,
  clearCache,
  getCacheStats
} from '../src/cache.js';

describe('Cache module', () => {
  const testNetwork = 'test-network-' + Date.now();

  afterEach(() => {
    // Clean up test cache including directories
    try {
      clearCache(testNetwork, true);
    } catch (e) {
      // Ignore
    }
  });

  describe('getCacheDir', () => {
    it('returns path under ~/.spv', () => {
      const dir = getCacheDir('tbtc4');
      assert.ok(dir.includes('.spv'));
      assert.ok(dir.includes('tbtc4'));
      assert.ok(dir.includes('tx'));
    });

    it('different networks have different dirs', () => {
      const mainnet = getCacheDir('mainnet');
      const tbtc4 = getCacheDir('tbtc4');
      assert.notStrictEqual(mainnet, tbtc4);
    });
  });

  describe('cacheTx and getCachedTx', () => {
    const testTxData = {
      txid: 'abc123def456',
      version: 2,
      locktime: 0,
      vin: [{ txid: 'prev', vout: 0 }],
      vout: [{ value: 1000, scriptpubkey: '0014...' }],
      fee: 141,
      status: {
        confirmed: true,
        block_hash: 'blockhash123',
        block_height: 100000,
        block_time: 1700000000
      }
    };

    it('caches and retrieves transaction', () => {
      cacheTx('test-tx-1', testTxData, testNetwork);
      const cached = getCachedTx('test-tx-1', testNetwork);

      assert.strictEqual(cached.txid, testTxData.txid);
      assert.strictEqual(cached.confirmed, true);
      assert.strictEqual(cached.blockHeight, 100000);
      assert.ok(cached.cachedAt > 0);
    });

    it('returns null for uncached tx', () => {
      const cached = getCachedTx('nonexistent', testNetwork);
      assert.strictEqual(cached, null);
    });

    it('caches unconfirmed transaction', () => {
      const unconfirmedTx = {
        ...testTxData,
        txid: 'unconfirmed-tx',
        status: { confirmed: false }
      };

      cacheTx('unconfirmed-tx', unconfirmedTx, testNetwork);
      const cached = getCachedTx('unconfirmed-tx', testNetwork);

      assert.strictEqual(cached.confirmed, false);
      assert.strictEqual(cached.blockHash, null);
    });
  });

  describe('isCachedAndConfirmed', () => {
    it('returns true for confirmed cached tx', () => {
      cacheTx('confirmed-tx', {
        txid: 'confirmed-tx',
        status: { confirmed: true, block_height: 123 }
      }, testNetwork);

      assert.strictEqual(isCachedAndConfirmed('confirmed-tx', testNetwork), true);
    });

    it('returns false for unconfirmed cached tx', () => {
      cacheTx('unconfirmed-tx', {
        txid: 'unconfirmed-tx',
        status: { confirmed: false }
      }, testNetwork);

      assert.strictEqual(isCachedAndConfirmed('unconfirmed-tx', testNetwork), false);
    });

    it('returns false for uncached tx', () => {
      assert.strictEqual(isCachedAndConfirmed('not-cached', testNetwork), false);
    });
  });

  describe('getCacheStats', () => {
    it('returns zero stats for empty cache', () => {
      const emptyNetwork = 'empty-network-' + Date.now();
      const stats = getCacheStats(emptyNetwork);

      assert.strictEqual(stats.count, 0);
      assert.strictEqual(stats.size, 0);
    });

    it('counts cached transactions', () => {
      cacheTx('tx1', { txid: 'tx1', status: {} }, testNetwork);
      cacheTx('tx2', { txid: 'tx2', status: {} }, testNetwork);

      const stats = getCacheStats(testNetwork);
      assert.strictEqual(stats.count, 2);
      assert.ok(stats.size > 0);
      assert.ok(stats.sizeHuman);
    });
  });

  describe('clearCache', () => {
    it('clears all cached transactions', () => {
      cacheTx('tx1', { txid: 'tx1', status: {} }, testNetwork);
      cacheTx('tx2', { txid: 'tx2', status: {} }, testNetwork);

      assert.strictEqual(getCacheStats(testNetwork).count, 2);

      clearCache(testNetwork);

      assert.strictEqual(getCacheStats(testNetwork).count, 0);
    });
  });
});
