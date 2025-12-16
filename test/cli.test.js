/**
 * CLI test suite
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { execSync, spawn } from 'child_process';
import { readFileSync, writeFileSync, unlinkSync, existsSync, mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const CLI_PATH = new URL('../src/cli.js', import.meta.url).pathname;

// Test private key (DO NOT USE IN PRODUCTION)
const TEST_PRIVKEY = '0000000000000000000000000000000000000000000000000000000000000001';

function runCli(args, options = {}) {
  const cmd = `node ${CLI_PATH} ${args}`;
  try {
    const result = execSync(cmd, {
      encoding: 'utf8',
      cwd: options.cwd || process.cwd(),
      env: { ...process.env, ...options.env }
    });
    return { stdout: result, exitCode: 0 };
  } catch (e) {
    return { stdout: e.stdout || '', stderr: e.stderr || '', exitCode: e.status };
  }
}

describe('CLI', () => {
  let tempDir;
  let trailFile;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'blocktrails-test-'));
    trailFile = join(tempDir, '.blocktrail.json');
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  describe('--help', () => {
    test('shows help message', () => {
      const { stdout, exitCode } = runCli('--help');
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('blocktrails'), 'Should show tool name');
      assert.ok(stdout.includes('Commands:'), 'Should show commands section');
      assert.ok(stdout.includes('init'), 'Should list init command');
      assert.ok(stdout.includes('genesis'), 'Should list genesis command');
      assert.ok(stdout.includes('advance'), 'Should list advance command');
      assert.ok(stdout.includes('show'), 'Should list show command');
      assert.ok(stdout.includes('export'), 'Should list export command');
      assert.ok(stdout.includes('verify'), 'Should list verify command');
    });

    test('shows tbtc4 as default network in help', () => {
      const { stdout } = runCli('--help');
      assert.ok(stdout.includes('tbtc4'), 'Should mention tbtc4');
      assert.ok(stdout.includes('default: tbtc4'), 'Should show tbtc4 as default');
    });
  });

  describe('--version', () => {
    test('shows version', () => {
      const { stdout, exitCode } = runCli('--version');
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('blocktrails v'), 'Should show version');
    });
  });

  describe('init', () => {
    test('creates trail file with generated key', () => {
      const { stdout, exitCode } = runCli(`init -f ${trailFile}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('Initialized'), 'Should confirm initialization');
      assert.ok(stdout.includes('Key source: generated'), 'Should indicate key was generated');
      assert.ok(existsSync(trailFile), 'Trail file should exist');

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      assert.strictEqual(data.version, 1);
      assert.strictEqual(data.network, 'tbtc4');
      assert.strictEqual(data.states.length, 0);
      assert.ok(data.publicKeyBase, 'Should have public key');
    });

    test('creates trail file with provided key', () => {
      const { stdout, exitCode } = runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('Key source: provided'), 'Should indicate key was provided');

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      // Public key for private key 1 is the generator point
      assert.ok(data.publicKeyBase.startsWith('02'), 'Should be compressed public key');
    });

    test('respects --network mainnet option', () => {
      const { exitCode } = runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY} --network mainnet`);
      assert.strictEqual(exitCode, 0);

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      assert.strictEqual(data.network, 'mainnet');
    });

    test('fails if file exists without --force', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stderr, exitCode } = runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('already exists'), 'Should warn about existing file');
    });

    test('overwrites with --force', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { exitCode } = runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY} --force`);
      assert.strictEqual(exitCode, 0);
    });
  });

  describe('genesis', () => {
    test('creates genesis state', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stdout, exitCode } = runCli(`genesis "initial state" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('Genesis created'), 'Should confirm genesis');
      assert.ok(stdout.includes('State: initial state'), 'Should show state');
      assert.ok(stdout.includes('Address: tb1p'), 'Should show testnet address');

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      assert.strictEqual(data.states.length, 1);
      assert.strictEqual(data.states[0], 'initial state');
    });

    test('fails without private key', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stderr, exitCode } = runCli(`genesis "state" -f ${trailFile}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('No private key'), 'Should require private key');
    });

    test('fails if genesis already exists', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "first" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stderr, exitCode } = runCli(`genesis "second" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('already has genesis'), 'Should reject second genesis');
    });

    test('fails without state argument', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stderr, exitCode } = runCli(`genesis -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('Usage:'), 'Should show usage');
    });

    test('uses mainnet address prefix for mainnet', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY} --network mainnet`);
      const { stdout } = runCli(`genesis "state" -f ${trailFile} --key ${TEST_PRIVKEY} --network mainnet`);
      assert.ok(stdout.includes('Address: bc1p'), 'Should show mainnet address');
    });
  });

  describe('advance', () => {
    test('advances to new state', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "state 0" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stdout, exitCode } = runCli(`advance "state 1" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('State 1 -> 2'), 'Should show transition');
      assert.ok(stdout.includes('State: state 1'), 'Should show new state');

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      assert.strictEqual(data.states.length, 2);
      assert.strictEqual(data.states[1], 'state 1');
    });

    test('fails without genesis', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stderr, exitCode } = runCli(`advance "state" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('genesis'), 'Should require genesis first');
    });

    test('fails with wrong private key', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "state" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const wrongKey = '0000000000000000000000000000000000000000000000000000000000000002';
      const { stderr, exitCode } = runCli(`advance "next" -f ${trailFile} --key ${wrongKey}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('does not match'), 'Should reject wrong key');
    });

    test('multiple advances work correctly', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "s0" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`advance "s1" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`advance "s2" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { exitCode } = runCli(`advance "s3" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      assert.strictEqual(data.states.length, 4);
      assert.deepStrictEqual(data.states, ['s0', 's1', 's2', 's3']);
    });
  });

  describe('show', () => {
    test('shows empty trail', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stdout, exitCode } = runCli(`show -f ${trailFile}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('States: 0'), 'Should show zero states');
      assert.ok(stdout.includes('No states yet'), 'Should indicate no states');
    });

    test('shows trail with states', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "initial" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`advance "next" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stdout, exitCode } = runCli(`show -f ${trailFile}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('States: 2'), 'Should show state count');
      assert.ok(stdout.includes('GENESIS'), 'Should label genesis');
      assert.ok(stdout.includes('HEAD'), 'Should label head');
      assert.ok(stdout.includes('initial'), 'Should show genesis state');
      assert.ok(stdout.includes('next'), 'Should show head state');
    });

    test('shows network', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stdout } = runCli(`show -f ${trailFile}`);
      assert.ok(stdout.includes('Network: tbtc4'), 'Should show network');
    });

    test('fails without trail file', () => {
      const { stderr, exitCode } = runCli(`show -f ${trailFile}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('No trail found'), 'Should indicate missing trail');
    });
  });

  describe('export', () => {
    test('exports to stdout', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "s0" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`advance "s1" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stdout, exitCode } = runCli(`export -f ${trailFile}`);
      assert.strictEqual(exitCode, 0);

      const exported = JSON.parse(stdout);
      assert.strictEqual(exported.version, 1);
      assert.strictEqual(exported.network, 'tbtc4');
      assert.deepStrictEqual(exported.states, ['s0', 's1']);
      assert.strictEqual(exported.witnessPrograms.length, 2);
    });

    test('exports to file', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "s0" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const outputFile = join(tempDir, 'export.json');
      const { stdout, exitCode } = runCli(`export -f ${trailFile} -o ${outputFile}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('Exported to:'), 'Should confirm export');
      assert.ok(existsSync(outputFile), 'Export file should exist');

      const exported = JSON.parse(readFileSync(outputFile, 'utf8'));
      assert.deepStrictEqual(exported.states, ['s0']);
    });

    test('fails with empty trail', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stderr, exitCode } = runCli(`export -f ${trailFile}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('no states'), 'Should require states');
    });
  });

  describe('verify', () => {
    test('verifies valid trail file', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "s0" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`advance "s1" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stdout, exitCode } = runCli(`verify -f ${trailFile}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('✓'), 'Should show success checkmark');
      assert.ok(stdout.includes('verified'), 'Should confirm verification');
      assert.ok(stdout.includes('2 states'), 'Should show state count');
    });

    test('verifies exported file with witness programs', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "s0" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`advance "s1" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const exportFile = join(tempDir, 'export.json');
      runCli(`export -f ${trailFile} -o ${exportFile}`);
      const { stdout, exitCode } = runCli(`verify ${exportFile}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('✓'), 'Should verify exported file');
    });

    test('fails with tampered states', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "s0" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const exportFile = join(tempDir, 'export.json');
      runCli(`export -f ${trailFile} -o ${exportFile}`);

      // Tamper with the state
      const data = JSON.parse(readFileSync(exportFile, 'utf8'));
      data.states[0] = 'tampered';
      writeFileSync(exportFile, JSON.stringify(data));

      const { stderr, exitCode } = runCli(`verify ${exportFile}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('✗') || stderr.includes('failed'), 'Should detect tampering');
    });

    test('generates witness programs if missing', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      runCli(`genesis "s0" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      // Trail file doesn't have witnessPrograms
      const { stdout, exitCode } = runCli(`verify -f ${trailFile}`);
      assert.strictEqual(exitCode, 0);
      assert.ok(stdout.includes('generating') || stdout.includes('✓'), 'Should handle missing witness programs');
    });

    test('fails without trail', () => {
      const { stderr, exitCode } = runCli(`verify -f ${trailFile}`);
      assert.strictEqual(exitCode, 1);
    });

    test('fails with nonexistent file argument', () => {
      const { stderr, exitCode } = runCli(`verify ${join(tempDir, 'nonexistent.json')}`);
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('not found'), 'Should report file not found');
    });
  });

  describe('unknown command', () => {
    test('shows error for unknown command', () => {
      const { stderr, exitCode } = runCli('unknowncmd');
      assert.strictEqual(exitCode, 1);
      assert.ok(stderr.includes('Unknown command'), 'Should report unknown command');
    });
  });

  describe('no command', () => {
    test('shows help when no command given', () => {
      const { stdout, exitCode } = runCli('');
      assert.strictEqual(exitCode, 1);
      assert.ok(stdout.includes('Commands:'), 'Should show help');
    });
  });

  describe('JSON state handling', () => {
    test('handles JSON state strings', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const jsonState = '{"counter":0}';
      const { exitCode } = runCli(`genesis '${jsonState}' -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      assert.strictEqual(data.states[0], jsonState);
    });

    test('handles numeric state correctly', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      // Pass number as argument - should be parsed as JSON number
      const { exitCode } = runCli(`genesis 42 -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      // Should be stored as "42" (JSON stringified number)
      assert.strictEqual(data.states[0], '42');
    });

    test('handles boolean state correctly', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { exitCode } = runCli(`genesis true -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      assert.strictEqual(data.states[0], 'true');
    });

    test('handles null state correctly', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { exitCode } = runCli(`genesis null -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      assert.strictEqual(data.states[0], 'null');
    });

    test('handles array state correctly', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { exitCode } = runCli(`genesis '[1,2,3]' -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      assert.strictEqual(data.states[0], '[1,2,3]');
    });

    test('plain string without quotes stays as string', () => {
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { exitCode } = runCli(`genesis hello -f ${trailFile} --key ${TEST_PRIVKEY}`);
      assert.strictEqual(exitCode, 0);

      const data = JSON.parse(readFileSync(trailFile, 'utf8'));
      // "hello" is not valid JSON, so stays as plain string
      assert.strictEqual(data.states[0], 'hello');
    });
  });

  describe('address determinism', () => {
    test('same inputs produce same address', () => {
      // First run
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stdout: stdout1 } = runCli(`genesis "state" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const address1 = stdout1.match(/Address: (tb1p\w+)/)?.[1];

      // Second run
      rmSync(trailFile);
      runCli(`init -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const { stdout: stdout2 } = runCli(`genesis "state" -f ${trailFile} --key ${TEST_PRIVKEY}`);
      const address2 = stdout2.match(/Address: (tb1p\w+)/)?.[1];

      assert.strictEqual(address1, address2, 'Same inputs should produce same address');
    });
  });
});
