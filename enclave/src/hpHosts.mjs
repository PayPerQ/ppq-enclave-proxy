// The horse-power hostnames this image will talk to — a MEASURED allowlist.
//
// WHY THIS EXISTS (Oct 17-19 security reports: Threepujia, roolzer)
// -------------------------------------------------------------------
// The enclave validates TLS to horse-power "against the real hostname" — but
// until this file the hostname itself came from the parent, in the init blob
// (`settle_host`, `passthrough_host`; boot.sh reads both from /tmp/init.json).
// Every provider host is pinned by UPSTREAM_PORTS and upstreamBinding.mjs; the
// one host that receives the CLIENT'S CREDENTIALS was not. A parent that named
// a host it holds a valid certificate for, and pointed the 9444 tunnel there,
// would have received every `/enclave/authorize` call: the caller's
// `x-api-key` / `x-credit-id` / `Authorization`, the `x-enclave-secret`, and
// the power to answer `authorized`, `resolved_model`, `max_tokens_cap` and the
// candidate list however it liked. The passthrough arm forwards whole requests
// (headers and bodies of the non-chat routes) to the same kind of name.
//
// That is not content exposure — authorize carries no message text — but it is
// the parent reaching past the one boundary the README says it cannot: the
// threat model allows PayPerQ to SEE credit ids, not an arbitrary host chosen
// by a compromised box to COLLECT them. So the set of names is fixed here, in
// code the attestation measures. The parent still chooses WHICH of these names
// (production vs the dev backend), and still owns the tunnel that carries the
// bytes; it can deny service, as it always could. It can no longer redirect.
//
// WHY EXACT NAMES AND NOT A SUFFIX
// --------------------------------
// `*.ppq.ai` would be the obvious rule, and it is wrong: the parent already
// HOLDS a certificate for a ppq.ai name (README "Known gaps" 3, the nginx
// rollback arm's certbot certificate), and any box that DNS points at can
// obtain one over HTTP-01. A suffix rule would let `settle_host: enclave.ppq.ai`
// aimed at the box's own nginx pass TLS validation. Exact names only.
//
// WHY THE DEV BACKEND IS IN A PRODUCTION IMAGE
// --------------------------------------------
// The dev enclave (DEV-ENCLAVE.md) runs the SAME image from the same commit —
// "never a forked copy, or you are testing the wrong thing" — against
// `ppq-backend-dev`. A dev-only build flag would make the measured image a
// different one from the one tested. Naming the dev backend here costs one
// residual: a hostile parent could aim a production enclave at PayPerQ's own
// dev backend. That backend is operated by PayPerQ in the same subscription;
// it is not a host the parent controls. Acceptable, and stated.
//
// If `ppq-backend-dev` is recreated its default hostname changes and this list
// must follow (a measured change, so a rotation). DEV-ENCLAVE.md says so.

/** Hostnames horse-power is reachable under, exactly as TLS validates them. */
export const HP_HOSTS = Object.freeze([
  // Production. Also the value SSM /ppq-enclave/fleet-config carries for
  // `settle_host` and `passthrough_host` (OPERATIONS.md).
  'backend.ppq.ai',
  // The dev backend's regional default hostname (DEV-ENCLAVE.md:
  // `az webapp show -g ppq-backend-dev -n ppq-backend-dev --query defaultHostName`).
  'ppq-backend-dev-a6fkdvbbbmg3dga3.canadacentral-01.azurewebsites.net',
]);

/**
 * The hostname as TLS compares it: DNS names are case-insensitive and a
 * trailing dot is the same name. Anything that is not a plain string is not a
 * hostname.
 */
export function normalizeHpHost(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Test-only widening of the list: `HP_HOST_ALLOW=localhost` lets the e2e
 * suites boot the real server against a fake horse-power on loopback. Same
 * pattern as `ANTHROPIC_HOST` / `OPENROUTER_HOST` in server.mjs: a process
 * environment variable that boot.sh NEVER sets. The parent's only channel into
 * the enclave's environment is the init blob, and boot.sh exports a fixed set
 * of names from it (hpHosts.test.mjs asserts this one is not among them), so
 * the widening is unreachable from the host.
 */
export function testAllowedHpHosts(env = process.env) {
  const raw = typeof env?.HP_HOST_ALLOW === 'string' ? env.HP_HOST_ALLOW : '';
  return raw.split(',').map(normalizeHpHost).filter(Boolean);
}

function allowedHpHosts(allow) {
  return allow ? [...HP_HOSTS, ...allow] : HP_HOSTS;
}

/** Whether the init blob named a horse-power host this image may talk to. */
export function isAllowedHpHost(value, { allow = testAllowedHpHosts() } = {}) {
  const h = normalizeHpHost(value);
  return h.length > 0 && allowedHpHosts(allow).includes(h);
}

/**
 * Resolve one init-supplied horse-power hostname into the cfg entry server.mjs
 * uses, failing CLOSED: a name outside the list yields no host at all, which
 * is the same state as an unconfigured one — authorize answers 503
 * `authorization unavailable` and spends no key, settles nothing, proxies
 * nothing. The rejected value is kept (for the boot log and /health) so the
 * failure is observable without `--debug-mode`, exactly as key_sources made
 * the KMS fallback observable (#85).
 *
 * @param {string|undefined} value  the env/init value
 * @param {{allow?: string[]}} [o]   extra names (tests only; see testAllowedHpHosts)
 * @returns {{ host: string, status: 'pinned'|'rejected'|'unset', rejected?: string }}
 */
export function pinHpHost(value, { allow = testAllowedHpHosts() } = {}) {
  if (value == null || String(value).trim() === '') return { host: '', status: 'unset' };
  const h = normalizeHpHost(value);
  if (allowedHpHosts(allow).includes(h)) return { host: h, status: 'pinned' };
  // Bounded: the value is parent text and goes into a log line and a JSON
  // health field, nowhere else.
  return { host: '', status: 'rejected', rejected: String(value).slice(0, 253) };
}
