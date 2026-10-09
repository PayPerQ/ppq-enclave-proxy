import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isFireRouterModel, isRetiredRoutingModel, RETIRED_ROUTING_MESSAGE } from '../src/routing.mjs';

test('every AutoClaw spelling is retired, with or without a routing suffix; nothing else is', () => {
  for (const id of ['autoclaw', 'autoclaw/auto', 'autoclaw/eco:floor', 'autoclaw:nitro', 'autorouter/a,b,c,d', 'autorouter/a,b,c,d:nitro']) {
    assert.equal(isRetiredRoutingModel(id), true, id);
  }
  for (const id of ['firerouter', 'firerouter/auto', 'auto', 'openrouter/auto', 'autoclawed/x', 'autorouter', '', undefined, null, 7]) {
    assert.equal(isRetiredRoutingModel(id), false, String(id));
  }
  assert.match(RETIRED_ROUTING_MESSAGE, /firerouter\/auto.*firerouter\/eco.*firerouter\/premium/);
});

test('firerouter ids are the namespace only; the bare alias is hp\'s to resolve', () => {
  assert.equal(isFireRouterModel('firerouter/eco'), true);
  assert.equal(isFireRouterModel('firerouter'), false);
  assert.equal(isFireRouterModel(undefined), false);
});
