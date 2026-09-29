// Every failure report in the server says whether it is the request's final
// failure (`terminal`) and which request it belongs to (`settle_id`). Some of
// those branches cannot be driven from outside (an attestation-bound upstream
// that answers without its nonce, a binding violation, a sealed opener that
// fails), so this pins the whole call-site table at the source: a new site, or
// a site whose `terminal` changes, must update this table on purpose.
// The observable behaviour of the drivable sites is in report-context.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const SRC = readFileSync(new URL('../src/server.mjs', import.meta.url), 'utf8');

/** Each `reportEnclaveError(...)` call: its code token and argument text. */
function callSites() {
  const sites = [];
  const re = /reportEnclaveError\(/g;
  let m;
  while ((m = re.exec(SRC))) {
    if (/function\s+$/.test(SRC.slice(m.index - 20, m.index))) continue; // the definition
    let depth = 1;
    let i = m.index + m[0].length;
    for (; i < SRC.length && depth; i++) {
      if (SRC[i] === '(') depth++;
      else if (SRC[i] === ')') depth--;
    }
    const args = SRC.slice(m.index + m[0].length, i - 1);
    const code = args.split(',')[0].trim().replace(/^ERROR_CODES\./, '');
    const terminal = /\bterminal:\s*([^,\n]+?),?\s*$/m.exec(args)?.[1] ?? null;
    sites.push({ code, terminal, args });
  }
  return sites;
}

// Source order. `code` is the ERROR_CODES key, or the local variable when the
// code is chosen at runtime. `terminal` is the literal expression in the call.
const EXPECTED = [
  ['code', null],                          // passthrough events: not a query, nothing to settle
  ['SETTLE_FAILED_PERMANENT', 'false'],    // settle bookkeeping, not a query outcome
  ['REQUEST_UNREADABLE', 'true'],          // chat
  ['code', 'true'],                        // chat model rejection before authorize
  ['code', 'true'],                        // chat authorize refused
  ['code', 'true'],                        // chat smart routing rejected
  ['FREE_MODEL_UNAUTHORIZED', 'true'],
  ['TRANSFORM_FAILED', 'true'],
  ['MODEL_REJECTED_PRIVATE_PATH', 'true'],
  ['UPSTREAM_UNREACHABLE', 'true'],        // public model routed to the private provider
  ['TINFOIL_ATTESTATION_FAILED', 'false'], // candidate skipped; a final unreachable follows
  ['UPSTREAM_UNREACHABLE', 'false'],       // binding violation: the next candidate is tried
  ['UPSTREAM_UNREACHABLE', 'true'],        // last candidate failed
  ['UPSTREAM_UNREACHABLE', 'true'],        // no candidate chosen
  ['UPSTREAM_ERROR_STATUS', 'false'],      // passed through and settled
  ['STREAM_FAILED', 'true'],               // attested answer without its nonce: 502, no settle
  ['STREAM_FAILED', 'true'],               // sealed answer could not be opened: 502, no settle
  ['TINFOIL_USAGE_MISSING', 'false'],      // raised inside the settle
  ['CLIENT_ABORT', 'false'],               // settles what was delivered
  ['STREAM_FAILED', 'false'],              // broke mid-stream, settles
  ['REQUEST_UNREADABLE', 'true'],          // decisions
  ['code', 'true'],                        // decisions authorize refused
  ['UPSTREAM_UNREACHABLE', 'true'],
  ['STREAM_FAILED', 'true'],               // body unreadable, no settle
  ['UPSTREAM_ERROR_STATUS', 'true'],       // a refused request never settles
  ['DECISIONS_USAGE_MISSING', 'false'],    // settles at zero
  ['UPSTREAM_UNREACHABLE', 'true'],        // relay: no route to the private router
  ['code', 'true'],                        // relay authorize refused
  ['REQUEST_UNREADABLE', 'true'],          // relay body unreadable, no settle
  ['UPSTREAM_UNREACHABLE', 'true'],
  ['UPSTREAM_ERROR_STATUS', 'true'],       // non-2xx never settles
  ['TINFOIL_USAGE_MISSING', 'false'],      // settles with zero counts
  ['CLIENT_ABORT', '!relaySettles'],       // final only when the answer would not settle
  ['STREAM_FAILED', '!relaySettles'],
  ['INTERNAL_ERROR', null],                // handler threw: fields come from the handler context
  ['INTERNAL_ERROR', null],
  ['INTERNAL_ERROR', null],
];

test('every report site declares terminal per its branch', () => {
  const got = callSites().map((s) => [s.code, s.terminal]);
  assert.deepEqual(got, EXPECTED);
});

test('every query report site names its request settle_id', () => {
  for (const s of callSites()) {
    if (s.terminal === null) continue; // passthrough events and handler-context sites
    assert.match(s.args, /\bsettle_id\b/, `${s.code} report is missing settle_id`);
  }
});

test('the relay settles exactly when its reports say not final', () => {
  assert.match(SRC, /const relaySettles = statusCode >= 200 && statusCode < 300;/);
  assert.match(SRC, /if \(!relaySettles\) return;/);
});

test('each handler marks settling as started before it settles', () => {
  // chat: first statement of settleNow; decisions: right before its settle;
  // relay: right after the non-2xx guard. The wrapper reads the flag to decide
  // whether an unanticipated throw was the request's final failure.
  assert.match(SRC, /const settleNow = \(\) => \{\n(?:\s*\/\/[^\n]*\n)*\s*ctx\.settleStarted = true;/);
  assert.match(SRC, /ctx\.settleStarted = true;\n\s*reportSettlement\(\{/);
  assert.match(SRC, /if \(!relaySettles\) return;\n\s*ctx\.settleStarted = true;/);
  assert.equal(SRC.match(/ctx\.settleStarted = true;/g).length, 3);
  assert.equal(SRC.match(/e\.reportFields = handlerFailureFields\(ctx, /g).length, 3);
});

test('every settle carries the failure_code its handler recorded', () => {
  const settles = SRC.match(/reportSettlement\(\{[\s\S]*?\n\s*\}\);/g);
  assert.equal(settles.length, 3);
  for (const body of settles) assert.match(body, /failure_code: settleFailureCode,/);
});

test('failure_code is set on exactly the fail-and-settle branches', () => {
  const sets = [...SRC.matchAll(/settleFailureCode (\?\?=|=) ([A-Z_.]+);/g)].map((m) => m[2]);
  assert.deepEqual(sets, [
    'ERROR_CODES.UPSTREAM_ERROR_STATUS', // chat: passed-through upstream error
    'ERROR_CODES.STREAM_FAILED',         // chat: broke mid-stream
    'RESPONSE_SEAL_FAILED',              // decisions: answer could not be sealed back
    'ERROR_CODES.STREAM_FAILED',         // relay: 2xx broke mid-stream
  ]);
  // The decisions sealing failure is set in the catch that answers 502.
  assert.match(SRC, /decisions response sealing failed[^\n]*\n\s*settleFailureCode = RESPONSE_SEAL_FAILED;/);
  // The relay only records it when the answer settles at all.
  assert.match(SRC, /if \(relaySettles\) settleFailureCode \?\?= ERROR_CODES\.STREAM_FAILED;/);
});
