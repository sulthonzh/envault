'use strict';

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const KEY_LEN = 32;
const IV_LEN = 16;
const TAG_LEN = 16;
const SALT_LEN = 32;
const ITERATIONS = 100000;

function deriveKey(passphrase, salt) {
  return crypto.pbkdf2Sync(passphrase, salt, ITERATIONS, KEY_LEN, 'sha256');
}

/**
 * Encrypt plaintext string with a passphrase.
 * Returns format: salt(32) + iv(16) + tag(16) + ciphertext
 * All concatenated as a single buffer, then base64-encoded.
 */
function encrypt(plaintext, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('Passphrase must be a non-empty string');
  }
  const salt = crypto.randomBytes(SALT_LEN);
  const key = deriveKey(passphrase, salt);
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGO, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

function decrypt(blob, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('Passphrase must be a non-empty string');
  }
  const raw = Buffer.from(blob, 'base64');

  if (raw.length < SALT_LEN + IV_LEN + TAG_LEN) {
    throw new Error('Invalid encrypted data: too short');
  }

  const salt = raw.subarray(0, SALT_LEN);
  const iv = raw.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const tag = raw.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const ciphertext = raw.subarray(SALT_LEN + IV_LEN + TAG_LEN);

  const key = deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);

  try {
    return decipher.update(ciphertext) + decipher.final('utf8');
  } catch (err) {
    throw new Error('Decryption failed — wrong passphrase or corrupted data');
  }
}

/**
 * Encrypt a .env file's contents.
 * Returns { encrypted: string, lineCount: number, byteSize: number }
 */
function encryptEnv(content, passphrase) {
  const trimmed = content.trimEnd();
  return {
    encrypted: encrypt(trimmed, passphrase),
    lineCount: trimmed.split('\n').length,
    byteSize: Buffer.byteLength(trimmed, 'utf8'),
  };
}

/**
 * Decrypt an encrypted .env blob back to its original content.
 * Returns { content: string, lineCount: number, byteSize: number }
 */
function decryptEnv(blob, passphrase) {
  const content = decrypt(blob, passphrase);
  return {
    content,
    lineCount: content.split('\n').length,
    byteSize: Buffer.byteLength(content, 'utf8'),
  };
}

/**
 * Parse .env content into key-value pairs.
 * Handles comments, quoted values, multiline, and exports.
 */
function parseEnv(content) {
  const lines = content.split('\n');
  const result = [];
  let current = null;

  for (const line of lines) {
    // Continuation of multiline value
    if (current && current.multiline) {
      current.raw += '\n' + line;
      const closing = line.endsWith(current.quote);
      if (closing) {
        current.multiline = false;
        current.value = current.raw.slice(0, -1);
      }
      continue;
    }

    // Skip comments and empty lines
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      if (current) {
        result.push(current);
        current = null;
      }
      continue;
    }

    // Flush previous
    if (current) {
      result.push(current);
      current = null;
    }

    const stripped = trimmed.startsWith('export ') ? trimmed.slice(7) : trimmed;

    const eqIdx = stripped.indexOf('=');
    if (eqIdx === -1) continue;

    const key = stripped.slice(0, eqIdx).trim();
    let val = stripped.slice(eqIdx + 1);

    if ((val.startsWith('"') || val.startsWith("'")) && !val.endsWith(val[0])) {
      current = { key, quote: val[0], multiline: true, raw: val.slice(1) };
      continue;
    }

    // Simple quoted value
    if ((val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }

    if (!val.startsWith('"') && !val.startsWith("'")) {
      const commentIdx = val.indexOf(' #');
      if (commentIdx !== -1) val = val.slice(0, commentIdx);
    }

    result.push({ key, value: val.trim(), multiline: false });
  }

  if (current) result.push(current);
  return result;
}

function diffEnv(parsed1, parsed2) {
  const map1 = new Map(parsed1.filter(v => !v.multiline).map(v => [v.key, v.value]));
  const map2 = new Map(parsed2.filter(v => !v.multiline).map(v => [v.key, v.value]));

  const added = [];
  const removed = [];
  const changed = [];

  for (const [key, value] of map2) {
    if (!map1.has(key)) {
      added.push({ key, value });
    } else if (map1.get(key) !== value) {
      changed.push({ key, from: map1.get(key), to: value });
    }
  }

  for (const [key, value] of map1) {
    if (!map2.has(key)) {
      removed.push({ key, value });
    }
  }

  return { added, removed, changed };
}

/**
 * Merge two env contents. Strategy: 'ours' | 'theirs' | 'union'
 * - ours: keep our values for conflicts
 * - theirs: take their values for conflicts
 * - union: keep both (theirs wins for same key)
 */
function mergeEnv(content1, content2, strategy = 'ours') {
  const parsed1 = parseEnv(content1);
  const parsed2 = parseEnv(content2);

  const map1 = new Map(parsed1.filter(v => !v.multiline).map(v => [v.key, v.value]));
  const map2 = new Map(parsed2.filter(v => !v.multiline).map(v => [v.key, v.value]));

  const result = new Map();

  // Start with all keys from content1
  for (const [key, value] of map1) {
    result.set(key, value);
  }

  // Merge content2
  for (const [key, value] of map2) {
    if (result.has(key)) {
      if (strategy === 'theirs' || strategy === 'union') {
        result.set(key, value);
      }
      // 'ours' keeps existing
    } else {
      result.set(key, value);
    }
  }

  const lines = [];
  for (const [key, value] of result) {
    const needsQuote = value.includes(' ') || value.includes('#') || value.includes('"');
    lines.push(needsQuote ? `${key}="${value}"` : `${key}=${value}`);
  }
  return lines.join('\n');
}

function rotatePassphrase(blob, oldPassphrase, newPassphrase) {
  const content = decrypt(blob, oldPassphrase);
  return encrypt(content, newPassphrase);
}

module.exports = {
  encrypt,
  decrypt,
  encryptEnv,
  decryptEnv,
  parseEnv,
  diffEnv,
  mergeEnv,
  rotatePassphrase,
  ALGO,
  ITERATIONS,
};
