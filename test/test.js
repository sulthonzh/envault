'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');
const {
  encrypt, decrypt, encryptEnv, decryptEnv,
  parseEnv, diffEnv, mergeEnv, rotatePassphrase,
} = require('../src/index');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
  }
}

console.log('envault tests\n');

// --- encrypt / decrypt roundtrip ---
test('encrypt/decrypt roundtrip', () => {
  const plain = 'DATABASE_URL=postgres://localhost:5432/mydb\nAPI_KEY=abc123';
  const blob = encrypt(plain, 'my-secret');
  const result = decrypt(blob, 'my-secret');
  assert.strictEqual(result, plain);
});

test('wrong passphrase throws', () => {
  const blob = encrypt('secret', 'correct');
  assert.throws(() => decrypt(blob, 'wrong'), /Decryption failed/);
});

test('empty passphrase throws', () => {
  assert.throws(() => encrypt('test', ''), /non-empty/);
  assert.throws(() => encrypt('test', ''), /non-empty/);
});

test('corrupted data throws', () => {
  assert.throws(() => decrypt('aGk=', 'pass'), /too short|Decryption failed/);
});

test('encrypted output is base64', () => {
  const blob = encrypt('hello world', 'pass');
  assert.ok(/^[A-Za-z0-9+/]+=*$/.test(blob));
});

// --- encryptEnv / decryptEnv ---
test('encryptEnv returns metadata', () => {
  const result = encryptEnv('KEY=val\nKEY2=val2', 'pass');
  assert.strictEqual(result.lineCount, 2);
  assert.ok(result.byteSize > 0);
  assert.ok(result.encrypted);
});

test('decryptEnv returns metadata', () => {
  const enc = encryptEnv('A=1', 'pass');
  const dec = decryptEnv(enc.encrypted, 'pass');
  assert.strictEqual(dec.content, 'A=1');
  assert.strictEqual(dec.lineCount, 1);
});

// --- parseEnv ---
test('parseEnv basic key=value', () => {
  const result = parseEnv('KEY=value\nKEY2=value2');
  assert.strictEqual(result.length, 2);
  assert.strictEqual(result[0].key, 'KEY');
  assert.strictEqual(result[0].value, 'value');
});

test('parseEnv skips comments and blanks', () => {
  const result = parseEnv('# comment\n\nKEY=val\n  # another');
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].key, 'KEY');
});

test('parseEnv strips export keyword', () => {
  const result = parseEnv('export KEY=val');
  assert.strictEqual(result[0].key, 'KEY');
});

test('parseEnv handles quoted values', () => {
  const result = parseEnv('KEY="hello world"\nKEY2=\'single quoted\'');
  assert.strictEqual(result[0].value, 'hello world');
  assert.strictEqual(result[1].value, 'single quoted');
});

test('parseEnv handles inline comments', () => {
  const result = parseEnv('KEY=val # this is a comment');
  assert.strictEqual(result[0].value, 'val');
});

test('parseEnv handles empty values', () => {
  const result = parseEnv('KEY=');
  assert.strictEqual(result[0].value, '');
});

// --- diffEnv ---
test('diffEnv detects added keys', () => {
  const d = diffEnv(
    [{ key: 'A', value: '1' }],
    [{ key: 'A', value: '1' }, { key: 'B', value: '2' }]
  );
  assert.strictEqual(d.added.length, 1);
  assert.strictEqual(d.added[0].key, 'B');
  assert.strictEqual(d.removed.length, 0);
  assert.strictEqual(d.changed.length, 0);
});

test('diffEnv detects removed keys', () => {
  const d = diffEnv(
    [{ key: 'A', value: '1' }, { key: 'B', value: '2' }],
    [{ key: 'A', value: '1' }]
  );
  assert.strictEqual(d.removed.length, 1);
  assert.strictEqual(d.removed[0].key, 'B');
});

test('diffEnv detects changed values', () => {
  const d = diffEnv(
    [{ key: 'A', value: 'old' }],
    [{ key: 'A', value: 'new' }]
  );
  assert.strictEqual(d.changed.length, 1);
  assert.strictEqual(d.changed[0].from, 'old');
  assert.strictEqual(d.changed[0].to, 'new');
});

test('diffEnv no differences', () => {
  const d = diffEnv(
    [{ key: 'A', value: '1' }],
    [{ key: 'A', value: '1' }]
  );
  assert.strictEqual(d.added.length, 0);
  assert.strictEqual(d.removed.length, 0);
  assert.strictEqual(d.changed.length, 0);
});

// --- mergeEnv ---
test('mergeEnv ours strategy', () => {
  const result = mergeEnv('A=1\nB=2', 'B=3\nC=4', 'ours');
  const parsed = parseEnv(result);
  const map = new Map(parsed.map(p => [p.key, p.value]));
  assert.strictEqual(map.get('A'), '1');
  assert.strictEqual(map.get('B'), '2'); // ours wins
  assert.strictEqual(map.get('C'), '4');
});

test('mergeEnv theirs strategy', () => {
  const result = mergeEnv('A=1\nB=2', 'B=3\nC=4', 'theirs');
  const parsed = parseEnv(result);
  const map = new Map(parsed.map(p => [p.key, p.value]));
  assert.strictEqual(map.get('B'), '3'); // theirs wins
});

test('mergeEnv union strategy', () => {
  const result = mergeEnv('A=1', 'B=2', 'union');
  const parsed = parseEnv(result);
  assert.strictEqual(parsed.length, 2);
});

// --- rotatePassphrase ---
test('rotatePassphrase works', () => {
  const blob = encrypt('secret content', 'old-pass');
  const newBlob = rotatePassphrase(blob, 'old-pass', 'new-pass');
  const result = decrypt(newBlob, 'new-pass');
  assert.strictEqual(result, 'secret content');
});

test('old passphrase fails after rotation', () => {
  const blob = encrypt('secret', 'old');
  const newBlob = rotatePassphrase(blob, 'old', 'new');
  assert.throws(() => decrypt(newBlob, 'old'), /Decryption failed/);
});

// --- unique ciphertext ---
test('same input produces different ciphertext', () => {
  const b1 = encrypt('same content', 'same');
  const b2 = encrypt('same content', 'same');
  assert.notStrictEqual(b1, b2); // random IV/salt each time
});

// --- large content ---
test('handles large content', () => {
  const lines = Array.from({ length: 500 }, (_, i) => `KEY_${i}=${'x'.repeat(100)}`);
  const content = lines.join('\n');
  const blob = encrypt(content, 'pass');
  const result = decrypt(blob, 'pass');
  assert.strictEqual(result, content);
});

// --- unicode ---
test('handles unicode values', () => {
  const content = 'GREETING=Halo dunia 🌍\nNAME=Sulthon';
  const blob = encrypt(content, 'pass');
  const result = decrypt(blob, 'pass');
  assert.strictEqual(result, content);
});

// --- CLI tests ---
test('CLI help runs', () => {
  const out = execSync('node cli.js help', { cwd: path.join(__dirname, '..') });
  assert.ok(out.toString().includes('envault'));
});

test('CLI encrypt/decrypt roundtrip', () => {
  const testDir = path.join(__dirname, 'tmp_cli');
  fs.mkdirSync(testDir, { recursive: true });
  fs.writeFileSync(path.join(testDir, '.env'), 'DB_HOST=localhost\nDB_PORT=5432');

  const encFile = path.join(testDir, '.env.enc');
  const decFile = path.join(testDir, '.env.dec');

  execSync(`node cli.js encrypt ${path.join(testDir, '.env')} --out ${encFile} --passphrase=test123`, {
    cwd: path.join(__dirname, '..'),
  });
  assert.ok(fs.existsSync(encFile));

  execSync(`node cli.js decrypt ${encFile} --out ${decFile} --passphrase=test123`, {
    cwd: path.join(__dirname, '..'),
  });
  const content = fs.readFileSync(decFile, 'utf8');
  assert.ok(content.includes('DB_HOST=localhost'));
  assert.ok(content.includes('DB_PORT=5432'));

  // cleanup
  fs.rmSync(testDir, { recursive: true });
});

test('CLI encrypt outputs JSON', () => {
  const testDir = path.join(__dirname, 'tmp_json');
  fs.mkdirSync(testDir, { recursive: true });
  fs.writeFileSync(path.join(testDir, '.env'), 'X=1');

  const out = execSync(
    `node cli.js encrypt ${path.join(testDir, '.env')} --passphrase=test --json`,
    { cwd: path.join(__dirname, '..') }
  );
  const json = JSON.parse(out.toString());
  assert.ok(json.encrypted);
  assert.strictEqual(json.lineCount, 1);

  fs.rmSync(testDir, { recursive: true });
});

test('CLI keys command', () => {
  const testDir = path.join(__dirname, 'tmp_keys');
  fs.mkdirSync(testDir, { recursive: true });
  fs.writeFileSync(path.join(testDir, '.env'), 'A=1\nB=2\nC=3');

  const encFile = path.join(testDir, '.env.enc');
  execSync(`node cli.js encrypt ${path.join(testDir, '.env')} --out ${encFile} --passphrase=test`, {
    cwd: path.join(__dirname, '..'),
  });

  const out = execSync(`node cli.js keys ${encFile} --passphrase=test --json`, {
    cwd: path.join(__dirname, '..'),
  });
  const json = JSON.parse(out.toString());
  assert.deepStrictEqual(json.keys, ['A', 'B', 'C']);

  fs.rmSync(testDir, { recursive: true });
});

// --- results ---
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
