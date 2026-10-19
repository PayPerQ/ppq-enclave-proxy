// The measured build context (Oct 17-19 security batch: "the CI sync has no
// git clean and the Dockerfile copies whole directories").
//
// Three things must agree, or a stray file on the build box can be measured
// into PCR0 without anyone noticing:
//   1. the Dockerfile's COPY sources (what the image is built from),
//   2. enclave/.dockerignore's whitelist (what docker is allowed to see),
//   3. scripts/check-build-context.sh's MEASURED_CONTEXT (what must be clean).
// The first block pins them to each other. The second runs the script against
// throwaway git repositories to prove it refuses exactly the dirty trees that
// would change the measurement, and passes the ones that would not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, cpSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');
const SCRIPT = join(repoRoot, 'scripts', 'check-build-context.sh');

/** `COPY <src>... <dest>` lines that read from the build context (no --from). */
function dockerfileContextCopies() {
  const lines = readFileSync(join(repoRoot, 'enclave', 'Dockerfile'), 'utf8').split('\n');
  const out = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (!/^(COPY|ADD)\b/.test(line) || /--from=/.test(line)) continue;
    const parts = line.split(/\s+/).slice(1).filter((p) => !p.startsWith('--'));
    out.push(...parts.slice(0, -1)); // last token is the destination
  }
  return out;
}

test('the Dockerfile never COPYs the whole context, so .dockerignore is not itself measured', () => {
  for (const src of dockerfileContextCopies()) {
    assert.notEqual(src, '.', `COPY ${src}: a whole-context copy would measure .dockerignore and every stray file`);
    assert.notEqual(src, './');
  }
});

test('every Dockerfile COPY source is re-included by the .dockerignore whitelist', () => {
  const ignore = readFileSync(join(repoRoot, 'enclave', '.dockerignore'), 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  assert.equal(ignore[0], '*', 'the whitelist must start by excluding everything');
  const allowed = new Set(ignore.slice(1).map((l) => l.replace(/^!/, '').replace(/\/$/, '')));
  for (const l of ignore.slice(1)) assert.ok(l.startsWith('!'), `unexpected non-exception rule: ${l}`);
  for (const src of dockerfileContextCopies()) {
    const top = src.replace(/^\.\//, '').split('/')[0];
    assert.ok(allowed.has(top), `COPY ${src} is excluded by .dockerignore (top-level ${top} not re-included)`);
  }
});

test("the script's MEASURED_CONTEXT covers every COPY source, the Dockerfile and the .dockerignore", () => {
  const listed = execFileSync('bash', [SCRIPT, '--list'], { encoding: 'utf8' }).trim().split('\n');
  const set = new Set(listed);
  for (const src of dockerfileContextCopies()) {
    const top = 'enclave/' + src.replace(/^\.\//, '').split('/')[0];
    assert.ok(set.has(top), `${top} (from COPY ${src}) is not in MEASURED_CONTEXT`);
  }
  assert.ok(set.has('enclave/Dockerfile'));
  assert.ok(set.has('enclave/.dockerignore'));
  for (const p of listed) assert.ok(existsSync(join(repoRoot, p)), `${p} listed but missing`);
});

// ---------------------------------------------------------------------------
// Behaviour against a throwaway repository shaped like this one.

function git(cwd, ...args) {
  return execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', ...args], { cwd, encoding: 'utf8' });
}

function makeRepo() {
  const dir = mkdtempSync(join(tmpdir(), 'ppq-build-ctx-'));
  mkdirSync(join(dir, 'scripts'));
  cpSync(SCRIPT, join(dir, 'scripts', 'check-build-context.sh'));
  for (const d of ['enclave/attest', 'enclave/kmstool', 'enclave/src']) mkdirSync(join(dir, d), { recursive: true });
  writeFileSync(join(dir, 'enclave/attest/main.go'), 'package main\n');
  writeFileSync(join(dir, 'enclave/kmstool/nsm-api-v0.4.0.Cargo.lock'), '# lock\n');
  writeFileSync(join(dir, 'enclave/src/server.mjs'), 'export {};\n');
  writeFileSync(join(dir, 'enclave/boot.sh'), '#!/bin/sh\n');
  writeFileSync(join(dir, 'enclave/package.json'), '{}\n');
  writeFileSync(join(dir, 'enclave/package-lock.json'), '{}\n');
  writeFileSync(join(dir, 'enclave/Dockerfile'), 'FROM scratch\n');
  writeFileSync(join(dir, 'enclave/.dockerignore'), '*\n!src\n');
  // The real repo ignores these; a stray IGNORED file under src/ is just as
  // measured as an untracked one.
  writeFileSync(join(dir, '.gitignore'), '*.log\nnode_modules/\nbuild/\n');
  git(dir, 'init', '-q');
  git(dir, 'add', '.');
  git(dir, 'commit', '-qm', 'base');
  return dir;
}

function run(dir, args = [], env = {}) {
  const r = spawnSync('bash', [join(dir, 'scripts', 'check-build-context.sh'), ...args], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  return { status: r.status, out: r.stdout + r.stderr };
}

test('a clean checkout passes', () => {
  const dir = makeRepo();
  try {
    const r = run(dir);
    assert.equal(r.status, 0, r.out);
    assert.match(r.out, /measured build context is clean/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an untracked file under enclave/src fails and is named', () => {
  const dir = makeRepo();
  try {
    writeFileSync(join(dir, 'enclave/src/stray.mjs'), '// left on the build box\n');
    const r = run(dir);
    assert.equal(r.status, 1);
    assert.match(r.out, /enclave\/src\/stray\.mjs/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an IGNORED file under enclave/attest fails too (git clean without -x would keep it)', () => {
  const dir = makeRepo();
  try {
    writeFileSync(join(dir, 'enclave/attest/debug.log'), 'x\n');
    const r = run(dir);
    assert.equal(r.status, 1);
    assert.match(r.out, /enclave\/attest\/debug\.log/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a modified tracked file fails: that tree is not the published commit', () => {
  const dir = makeRepo();
  try {
    writeFileSync(join(dir, 'enclave/boot.sh'), '#!/bin/sh\necho patched\n');
    const r = run(dir);
    assert.equal(r.status, 1);
    assert.match(r.out, /enclave\/boot\.sh/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('files outside the measured context (enclave/node_modules, enclave/test, build/) do not fail the check', () => {
  const dir = makeRepo();
  try {
    mkdirSync(join(dir, 'enclave/node_modules/x'), { recursive: true });
    writeFileSync(join(dir, 'enclave/node_modules/x/index.js'), '');
    mkdirSync(join(dir, 'enclave/test'));
    writeFileSync(join(dir, 'enclave/test/new.test.mjs'), '');
    mkdirSync(join(dir, 'build'));
    writeFileSync(join(dir, 'build/ppq-enclave-proxy.eif'), 'previous image');
    const r = run(dir);
    assert.equal(r.status, 0, r.out);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--clean removes the stray files from the measured paths only, then passes', () => {
  const dir = makeRepo();
  try {
    writeFileSync(join(dir, 'enclave/src/stray.mjs'), '');
    writeFileSync(join(dir, 'enclave/attest/debug.log'), '');
    mkdirSync(join(dir, 'build'));
    writeFileSync(join(dir, 'build/ppq-enclave-proxy.eif'), 'previous image');
    const r = run(dir, ['--clean']);
    assert.equal(r.status, 0, r.out);
    assert.ok(!existsSync(join(dir, 'enclave/src/stray.mjs')));
    assert.ok(!existsSync(join(dir, 'enclave/attest/debug.log')));
    // The EIF the cutover and fleet-refresh workflows read from the checkout
    // survives: it is outside the measured context.
    assert.ok(existsSync(join(dir, 'build/ppq-enclave-proxy.eif')));
    assert.equal(run(dir).status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ALLOW_DIRTY_BUILD_CONTEXT=1 downgrades the refusal to a warning', () => {
  const dir = makeRepo();
  try {
    writeFileSync(join(dir, 'enclave/src/stray.mjs'), '');
    const r = run(dir, [], { ALLOW_DIRTY_BUILD_CONTEXT: '1' });
    assert.equal(r.status, 0, r.out);
    assert.match(r.out, /do NOT publish/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an unknown flag is a usage error', () => {
  const dir = makeRepo();
  try {
    assert.equal(run(dir, ['--nuke']).status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
