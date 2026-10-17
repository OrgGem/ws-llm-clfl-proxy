#!/usr/bin/env node
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile, chmod } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const statePath = resolve(root, '.local/setup.json');
await mkdir(dirname(statePath), { recursive: true, mode: 0o700 });
await chmod(dirname(statePath), 0o700);
let state;
try {
  state = JSON.parse(await readFile(statePath, 'utf8'));
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kid = `local-${randomBytes(8).toString('hex')}`;
  state = {
    privateJwk: { ...privateKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' },
    publicJwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' },
    envelopeKeys: { current: kid, keys: { [kid]: randomBytes(32).toString('base64url') } },
  };
  await writeFile(statePath, JSON.stringify(state, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
await chmod(statePath, 0o600);
if (!state.privateJwk?.d || !state.publicJwk?.kid || !state.envelopeKeys?.current) {
  throw new Error('Existing local state is invalid; inspect the local setup privately before proceeding.');
}
const envValue = (value) => JSON.stringify(typeof value === 'string' ? value : JSON.stringify(value));
const issuer = 'http://localhost:8787';
const shared = `MACHINE_ISSUER=${envValue(issuer)}\nMACHINE_JWT_PUBLIC_JWKS=${envValue({ keys: [state.publicJwk] })}\nENVELOPE_KEYS=${envValue(state.envelopeKeys)}\n`;
const identity = shared + `MACHINE_JWT_PRIVATE_JWK=${envValue(state.privateJwk)}\nOIDC_PROVIDERS="[]"\nBOOTSTRAP_ADMIN_EMAILS=""\n`;
for (const [app, contents] of [['identity', identity], ['gateway', shared]]) {
  const path = resolve(root, `apps/${app}/.dev.vars`);
  await mkdir(dirname(path), { recursive: true });
  try {
    await writeFile(path, contents, { flag: 'wx', mode: 0o600 });
    console.log(`Created apps/${app}/.dev.vars (owner-only; local use).`);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    console.log(`Kept existing apps/${app}/.dev.vars.`);
  }
  await chmod(path, 0o600);
}
console.log('Local key material stays in ignored .local/setup.json. No secret values were printed.');
console.log('Configure OIDC and bootstrap admin locally before login; use separate secrets on staging.');
