# envault

Zero-dep .env file encryption for teams. Encrypt, decrypt, diff, merge, and rotate secrets with a passphrase.

## Why?

You're committing `.env` files to... somewhere. Maybe a shared drive, maybe a private repo, maybe Slack (please stop). **envault** gives you a dead-simple way to encrypt `.env` files so you can safely share them without leaking secrets.

No vault server. No cloud dependency. No runtime deps. Just a passphrase and AES-256-GCM.

## Install

```bash
npm install -g envault
```

Or use without installing:

```bash
npx envault encrypt .env --out .env.encrypted --passphrase=my-secret
```

## Usage

### Encrypt

```bash
# Encrypt .env → prints encrypted blob to stdout
envault encrypt .env --passphrase my-secret

# Encrypt to file
envault encrypt .env --out .env.encrypted --passphrase my-secret

# Pipe stdin
echo "DATABASE_URL=postgres://localhost/db" | envault encrypt --passphrase my-secret
```

### Decrypt

```bash
# Decrypt to stdout
envault decrypt .env.encrypted --passphrase my-secret

# Decrypt to file
envault decrypt .env.encrypted --out .env --passphrase my-secret
```

### View keys & values

```bash
# Show key=value pairs
envault view .env.encrypted --passphrase my-secret

# List just the keys
envault keys .env.encrypted --passphrase my-secret

# JSON output (good for scripting)
envault keys .env.encrypted --passphrase my-secret --json
```

### Diff two encrypted files

```bash
# See what changed between staging and prod
envault diff .env.staging.enc .env.prod.enc --passphrase my-secret
```

Output:
```
Added:
  + NEW_FEATURE_FLAG=true
Changed:
  ~ LOG_LEVEL: debug → info
Removed:
  - DEPRECATED_KEY=old-value
```

### Merge encrypted files

```bash
# Merge with strategy: ours | theirs | union (default: ours)
envault merge .env.base.enc .env.override.enc --strategy theirs --passphrase my-secret
```

### Rotate passphrase

```bash
envault rotate .env.encrypted
# Prompts for old + new passphrase
```

### Environment variable

Set `ENVAULT_PASSPHRASE` to avoid typing it every time (useful in CI):

```bash
export ENVAULT_PASSPHRASE=my-secret
envault encrypt .env --out .env.enc
envault decrypt .env.enc --out .env
```

## Programmatic API

```js
const { encrypt, decrypt, encryptEnv, decryptEnv, parseEnv, diffEnv, mergeEnv, rotatePassphrase } = require('envault');

// Basic encrypt/decrypt
const blob = encrypt('secret content', 'my-passphrase');
const plain = decrypt(blob, 'my-passphrase');

// Env-specific with metadata
const result = encryptEnv('DB_HOST=localhost\nDB_PORT=5432', 'passphrase');
// → { encrypted: '...', lineCount: 2, byteSize: 32 }

// Parse .env content
const parsed = parseEnv('KEY=value\n# comment\nKEY2="quoted value"');
// → [{ key: 'KEY', value: 'value' }, { key: 'KEY2', value: 'quoted value' }]

// Diff two parsed env arrays
const diff = diffEnv(parsed1, parsed2);
// → { added: [...], removed: [...], changed: [...] }

// Merge with strategy
const merged = mergeEnv(content1, content2, 'ours'); // ours | theirs | union

// Rotate passphrase
const newBlob = rotatePassphrase(oldBlob, oldPass, newPass);
```

## How It Works

1. **Key derivation**: PBKDF2 with SHA-256, 100k iterations, random 32-byte salt
2. **Encryption**: AES-256-GCM with random 16-byte IV
3. **Format**: `base64(salt + iv + authTag + ciphertext)`
4. **Deterministic?** No. Same input + passphrase → different ciphertext every time (random salt + IV)

## Security Notes

- This is **file-level encryption** for sharing secrets, not a replacement for a proper secrets manager
- Passphrase strength matters — use long, random passphrases
- The encrypted blob contains the salt and IV (that's fine, they're not secrets)
- AES-256-GCM provides authenticated encryption (integrity + confidentiality)
- No password is ever stored — if you forget it, your data is gone

## CLI Reference

```
envault encrypt <file> [--out <file>] [--passphrase <pw>] [--json]
envault decrypt <file> [--out <file>] [--passphrase <pw>] [--json]
envault view <file> [--passphrase <pw>] [--json]
envault keys <file> [--passphrase <pw>] [--json]
envault diff <file1> <file2> [--passphrase <pw>] [--json]
envault merge <f1> <f2> [--strategy ours|theirs|union] [--passphrase <pw>] [--out <file>]
envault rotate <file> [--out <file>]
```

Flags:
- `--out, -o` — output file path
- `--passphrase` — passphrase (or set `ENVAULT_PASSPHRASE`)
- `--json` — JSON output
- `--pretty` — pretty-print JSON
- `--strategy` — merge strategy: `ours`, `theirs`, `union`

## License

MIT
