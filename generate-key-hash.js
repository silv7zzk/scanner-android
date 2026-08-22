#!/usr/bin/env node
const crypto = require('crypto');

const key = process.argv[2];
if (!key) {
    console.error('Uso: node generate-key-hash.js "SUA_KEY"');
    process.exit(1);
}
const normalized = key.trim().toUpperCase();
console.log(JSON.stringify({
    key: normalized,
    hash: crypto.createHash('sha256').update(normalized, 'utf8').digest('hex')
}, null, 2));
