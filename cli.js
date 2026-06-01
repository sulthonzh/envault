#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const {
  encrypt, decrypt, encryptEnv, decryptEnv,
  parseEnv, diffEnv, mergeEnv, rotatePassphrase,
} = require('./src/index');

const args = process.argv.slice(2);
const command = args[0];

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve(null);
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    setTimeout(() => resolve(data || null), 100);
  });
}

function getPassphrase(prompt) {
  const p = args.find(a => a.startsWith('--passphrase='))?.split('=')[1]
    || args[args.indexOf('--passphrase') + 1]
    || process.env.ENVAULT_PASSPHRASE;

  if (p) return p;

  // Interactive prompt
  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt || 'Enter passphrase: ', (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function getFlag(name) {
  const idx = args.indexOf(name);
  if (idx === -1) return null;
  if (args[idx + 1] && !args[idx + 1].startsWith('-')) return args[idx + 1];
  return true;
}

function outputJson(data) {
  const pretty = args.includes('--pretty');
  console.log(JSON.stringify(data, null, pretty ? 2 : 0));
}

function resolveFile(p) {
  if (!p) return null;
  return path.resolve(p);
}

async function run() {
  switch (command) {
    case 'encrypt': {
      const file = args[1];
      const outFile = getFlag('--out') || getFlag('-o');
      const content = file
        ? fs.readFileSync(resolveFile(file), 'utf8')
        : await readStdin();

      if (!content) {
        console.error('Error: no input. Provide a file or pipe stdin.');
        process.exit(1);
      }

      const passphrase = await getPassphrase('Passphrase to encrypt: ');
      const result = encryptEnv(content, passphrase);

      if (args.includes('--json')) {
        outputJson({
          encrypted: result.encrypted,
          lineCount: result.lineCount,
          byteSize: result.byteSize,
        });
      } else {
        const output = result.encrypted;
        if (outFile) {
          fs.writeFileSync(resolveFile(outFile), output);
          console.error(`Encrypted ${result.lineCount} lines (${result.byteSize} bytes) → ${outFile}`);
        } else {
          console.log(output);
        }
      }
      break;
    }

    case 'decrypt': {
      const file = args[1];
      const outFile = getFlag('--out') || getFlag('-o');
      const blob = file
        ? fs.readFileSync(resolveFile(file), 'utf8').trim()
        : (await readStdin())?.trim();

      if (!blob) {
        console.error('Error: no input. Provide a file or pipe stdin.');
        process.exit(1);
      }

      const passphrase = await getPassphrase('Passphrase to decrypt: ');
      try {
        const result = decryptEnv(blob, passphrase);

        if (args.includes('--json')) {
          outputJson({
            content: result.content,
            lineCount: result.lineCount,
            byteSize: result.byteSize,
          });
        } else if (outFile) {
          fs.writeFileSync(resolveFile(outFile), result.content);
          console.error(`Decrypted ${result.lineCount} lines (${result.byteSize} bytes) → ${outFile}`);
        } else {
          console.log(result.content);
        }
      } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      break;
    }

    case 'diff': {
      const file1 = args[1];
      const file2 = args[2];

      if (!file1 || !file2) {
        console.error('Usage: envault diff <encrypted1> <encrypted2>');
        process.exit(1);
      }

      const passphrase = await getPassphrase('Passphrase: ');
      const blob1 = fs.readFileSync(resolveFile(file1), 'utf8').trim();
      const blob2 = fs.readFileSync(resolveFile(file2), 'utf8').trim();

      try {
        const content1 = decrypt(blob1, passphrase);
        const content2 = decrypt(blob2, passphrase);
        const parsed1 = parseEnv(content1);
        const parsed2 = parseEnv(content2);
        const diff = diffEnv(parsed1, parsed2);

        if (args.includes('--json')) {
          outputJson(diff);
        } else {
          if (diff.added.length) {
            console.log('Added:');
            diff.added.forEach(({ key, value }) => console.log(`  + ${key}=${value}`));
          }
          if (diff.removed.length) {
            console.log('Removed:');
            diff.removed.forEach(({ key, value }) => console.log(`  - ${key}=${value}`));
          }
          if (diff.changed.length) {
            console.log('Changed:');
            diff.changed.forEach(({ key, from, to }) => console.log(`  ~ ${key}: ${from} → ${to}`));
          }
          if (!diff.added.length && !diff.removed.length && !diff.changed.length) {
            console.log('No differences found.');
          }
        }
      } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      break;
    }

    case 'merge': {
      const file1 = args[1];
      const file2 = args[2];
      const strategy = getFlag('--strategy') || 'ours';
      const outFile = getFlag('--out') || getFlag('-o');

      if (!file1 || !file2) {
        console.error('Usage: envault merge <encrypted1> <encrypted2> [--strategy ours|theirs|union]');
        process.exit(1);
      }

      const passphrase = await getPassphrase('Passphrase: ');
      const blob1 = fs.readFileSync(resolveFile(file1), 'utf8').trim();
      const blob2 = fs.readFileSync(resolveFile(file2), 'utf8').trim();

      try {
        const content1 = decrypt(blob1, passphrase);
        const content2 = decrypt(blob2, passphrase);
        const merged = mergeEnv(content1, content2, strategy);

        if (outFile) {
          const outBlob = encrypt(merged, passphrase);
          fs.writeFileSync(resolveFile(outFile), outBlob);
          console.error(`Merged (${strategy}) → ${outFile}`);
        } else {
          console.log(merged);
        }
      } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      break;
    }

    case 'rotate': {
      const file = args[1];
      const outFile = getFlag('--out') || getFlag('-o') || file;

      if (!file) {
        console.error('Usage: envault rotate <encrypted-file>');
        process.exit(1);
      }

      const oldPass = await getPassphrase('Current passphrase: ');
      const newPass = await getPassphrase('New passphrase: ');

      const blob = fs.readFileSync(resolveFile(file), 'utf8').trim();

      try {
        const newBlob = rotatePassphrase(blob, oldPass, newPass);
        fs.writeFileSync(resolveFile(outFile), newBlob);
        console.error(`Passphrase rotated → ${outFile}`);
      } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      break;
    }

    case 'view': {
      const file = args[1];
      if (!file) {
        console.error('Usage: envault view <encrypted-file>');
        process.exit(1);
      }

      const passphrase = await getPassphrase('Passphrase: ');
      const blob = fs.readFileSync(resolveFile(file), 'utf8').trim();

      try {
        const content = decrypt(blob, passphrase);
        const parsed = parseEnv(content);

        if (args.includes('--json')) {
          outputJson(parsed.filter(v => !v.multiline).map(({ key, value }) => ({ key, value })));
        } else {
          parsed.forEach(({ key, value, multiline }) => {
            if (!multiline) {
              console.log(`${key}=${value}`);
            }
          });
        }
      } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      break;
    }

    case 'keys': {
      const file = args[1];
      if (!file) {
        console.error('Usage: envault keys <encrypted-file>');
        process.exit(1);
      }

      const passphrase = await getPassphrase('Passphrase: ');
      const blob = fs.readFileSync(resolveFile(file), 'utf8').trim();

      try {
        const content = decrypt(blob, passphrase);
        const parsed = parseEnv(content);
        const keys = parsed.filter(v => !v.multiline).map(v => v.key);

        if (args.includes('--json')) {
          outputJson({ keys, count: keys.length });
        } else {
          keys.forEach(k => console.log(k));
          console.error(`${keys.length} keys`);
        }
      } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      break;
    }

    case 'help':
    case '--help':
    case undefined: {
      console.log(`envault — .env file encryption for teams

Usage:
  envault encrypt <file> [--out <file>] [--passphrase <pw>]  Encrypt .env file
  envault decrypt <file> [--out <file>] [--passphrase <pw>]  Decrypt encrypted file
  envault view <file> [--passphrase <pw>] [--json]           View decrypted key=value pairs
  envault keys <file> [--passphrase <pw>] [--json]           List keys only
  envault diff <file1> <file2> [--passphrase <pw>]           Diff two encrypted files
  envault merge <f1> <f2> [--strategy ours|theirs|union]     Merge encrypted files
  envault rotate <file>                                       Change passphrase

Options:
  --out, -o <file>      Output file path
  --passphrase <pw>     Passphrase (or set ENVAULT_PASSPHRASE)
  --strategy <s>        Merge strategy: ours (default), theirs, union
  --json                JSON output
  --pretty              Pretty-print JSON

Encryption: AES-256-GCM with PBKDF2 key derivation (100k iterations)

Examples:
  envault encrypt .env --out .env.encrypted
  envault decrypt .env.encrypted --out .env
  envault diff .env.staging.encrypted .env.prod.encrypted
  echo "SECRET=value" | envault encrypt`);
      break;
    }

    default:
      console.error(`Unknown command: ${command}. Run 'envault help' for usage.`);
      process.exit(1);
  }
}

run().catch(err => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
