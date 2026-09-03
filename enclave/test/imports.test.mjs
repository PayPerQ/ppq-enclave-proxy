// Every named import in src/ must actually exist in the module it comes from.
//
// WHY THIS TEST EXISTS
// --------------------
// `node --check` is a SYNTAX check. It happily passes a file that imports a
// binding the target module does not export, or that uses a symbol with no
// import at all -- ESM resolution errors surface only when the module is really
// loaded. In this repo that means the first production request after a cutover,
// which is the most expensive place to find out.
//
// I introduced three of these in one day while adding receipt signing and the
// ACME hooks (`cryptoSign`/`constants`, `createPrivateKey`, `createSecureContext`),
// and `node --check` passed on all three. This turns that class of mistake into
// a failing test instead of a rotation.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const SRC = new URL('../src/', import.meta.url);
const files = readdirSync(SRC).filter((f) => f.endsWith('.mjs'));

// server.mjs is the entrypoint: importing it runs start(), which reads
// /app/tls/cert.pem and calls process.exit(1) when absent -- so it cannot be
// loaded outside the enclave, and attempting to kills the test runner. The
// static check below covers it instead, which is why both tests exist.
const loadable = files.filter((f) => f !== 'server.mjs');

test('every src/*.mjs loads for real, not just parses', async () => {
  for (const f of loadable) {
    await assert.doesNotReject(
      () => import(new URL(f, SRC).href),
      `${f} failed to load`,
    );
  }
});

test('every named import resolves to an actual export', async () => {
  // Covers server.mjs too, which the loader test above cannot reach cheaply:
  // importing it starts listeners and expects an init blob over vsock.
  const problems = [];
  for (const f of files) {
    const src = readFileSync(new URL(f, SRC), 'utf8');
    const stmts = [...src.matchAll(/^import\s+\{([^}]+)\}\s+from\s+'([^']+)';/gm)];
    for (const [, names, spec] of stmts) {
      if (!spec.startsWith('.') && !spec.startsWith('node:')) continue; // 3rd-party: leave to npm
      const target = spec.startsWith('.') ? new URL(spec, new URL(f, SRC)).href : spec;
      let mod;
      try {
        mod = await import(target);
      } catch (e) {
        problems.push(`${f}: cannot load ${spec} (${e.message})`);
        continue;
      }
      for (const raw of names.split(',')) {
        const name = raw.trim().split(/\s+as\s+/)[0].replace(/^type\s+/, '').trim();
        if (!name) continue;
        if (!(name in mod)) problems.push(`${f}: '${name}' is not exported by ${spec}`);
      }
    }
  }
  assert.deepEqual(problems, [], `unresolved imports:\n  ${problems.join('\n  ')}`);
});

// The failure mode the two tests above do NOT catch: a symbol USED with no
// import at all. There is no import statement to validate, and loading the
// module does not fail either -- a reference inside a callback only throws when
// that callback runs, which for a TLS hook means during a real handshake.
//
// All three of the mistakes I made in one day were this shape. Restricted to
// distinctive builtin names that are implausible as local identifiers, so it
// stays a guard rather than a source of false positives.
const BUILTIN_SYMBOLS = [
  'createSecureContext', 'createPrivateKey', 'createPublicKey', 'createHash',
  'createHmac', 'generateKeyPairSync', 'randomBytes', 'X509Certificate',
  'readFileSync', 'writeFileSync', 'mkdtempSync', 'execFileSync', 'execFile',
];

test('no distinctive builtin symbol is used without being imported', () => {
  const problems = [];
  for (const f of files) {
    const src = readFileSync(new URL(f, SRC), 'utf8');
    // Names brought in by ANY import statement in this file.
    const imported = new Set();
    for (const [, names] of src.matchAll(/^import\s+\{([^}]+)\}\s+from\s+'[^']+';/gm)) {
      for (const raw of names.split(',')) {
        const parts = raw.trim().split(/\s+as\s+/);
        imported.add((parts[1] || parts[0]).trim());
      }
    }
    // Default/namespace imports, e.g. `import https from ...`.
    for (const [, name] of src.matchAll(/^import\s+(?:\*\s+as\s+)?(\w+)\s+from\s+'[^']+';/gm)) {
      imported.add(name);
    }
    // Locally defined names of the same spelling are legitimate.
    const declared = new Set(
      [...src.matchAll(/\b(?:const|let|var|function|class)\s+(\w+)/g)].map((m) => m[1]),
    );
    const body = src.replace(/^import\s[\s\S]*?;$/gm, '');
    for (const sym of BUILTIN_SYMBOLS) {
      if (imported.has(sym) || declared.has(sym)) continue;
      // Word-boundary, and not as a property access (foo.createHash is fine).
      if (new RegExp(`(?<![.\\w])${sym}\\s*\\(`).test(body)) {
        problems.push(`${f}: uses ${sym}() with no import`);
      }
    }
  }
  assert.deepEqual(problems, [], `missing imports:\n  ${problems.join('\n  ')}`);
});
