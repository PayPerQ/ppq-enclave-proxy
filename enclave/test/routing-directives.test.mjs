import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyFreeModelStrip,
  applyToolStrip,
  applyAutoRouterConfig,
  applyWebPluginDirective,
  exaWebPluginRequested,
  parseAutoRouter,
  webSearchEngineOf, applyHardProviderPin } from '../src/routing.mjs';
import { messagesHasWebSearch } from '../src/messages.mjs';

// ── applyFreeModelStrip (issue #6, driven by hp is_free) ─────────────────────

test('free strip drops paid plugins', () => {
  const p = { model: 'ppq/free', plugins: [{ id: 'web' }], messages: [] };
  applyFreeModelStrip(p);
  assert.equal('plugins' in p, false);
});

test('free strip removes the web_search tool but keeps other tools', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'openrouter:web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tools, [{ type: 'function', function: { name: 'f' } }]);
  assert.equal('tool_choice' in p, false); // still has a tool → tool_choice untouched-absent
});

test('free strip deletes an emptied tools array + its tool_choice', () => {
  const p = {
    model: 'ppq/free',
    tools: [{ type: 'openrouter:web_search' }],
    tool_choice: 'auto',
  };
  applyFreeModelStrip(p);
  assert.equal('tools' in p, false);
  assert.equal('tool_choice' in p, false);
});

// The gap this pair closes: web_search named ALONGSIDE other tools. The tools
// array stays non-empty, so the old code left tool_choice pointing at a tool it
// had just deleted and the upstream rejected the request outright — strictly
// worse than losing web search. hp deletes it here (chatPayload.ts), so leaving
// it was also a drift between the two paths.
test('free strip drops a tool_choice targeting the removed web_search tool', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'openrouter:web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
    tool_choice: { type: 'openrouter:web_search' },
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tools, [{ type: 'function', function: { name: 'f' } }]);
  assert.equal('tool_choice' in p, false);
});

test('free strip matches the function-name form of that tool_choice too', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'openrouter:web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
    tool_choice: { function: { name: 'openrouter:web_search' } },
  };
  applyFreeModelStrip(p);
  assert.equal('tool_choice' in p, false);
});

test('free strip keeps a tool_choice aimed at a surviving tool', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'openrouter:web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
    tool_choice: { type: 'function', function: { name: 'f' } },
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tool_choice, { type: 'function', function: { name: 'f' } });
});

// Guard the blast radius: with no web_search declared there is nothing to
// dangle, so tool_choice must survive untouched.
test('free strip leaves tool_choice alone when no web_search was present', () => {
  const p = {
    model: 'ppq/free',
    tools: [{ type: 'function', function: { name: 'f' } }],
    tool_choice: 'auto',
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tools, [{ type: 'function', function: { name: 'f' } }]);
  assert.equal(p.tool_choice, 'auto');
});

test('free strip is a no-op when there is nothing to strip', () => {
  const p = { model: 'ppq/free', messages: [{ role: 'user', content: 'hi' }] };
  applyFreeModelStrip(p);
  assert.deepEqual(p, { model: 'ppq/free', messages: [{ role: 'user', content: 'hi' }] });
});

// Oct 17-19 security reports (Matt's triage): the dated `web_search_YYYYMMDD`
// server tool is a paid search too — hp's `:online` directive on the Messages
// dialect injects exactly that form — and the strip only knew OpenRouter's.
test('free strip removes the dated web_search_* tool and a tool_choice naming it', () => {
  const p = {
    model: 'ppq/free',
    tools: [
      { type: 'web_search_20250305', name: 'web_search' },
      { type: 'function', function: { name: 'f' } },
    ],
    tool_choice: { type: 'tool', name: 'web_search' },
  };
  applyFreeModelStrip(p);
  assert.deepEqual(p.tools, [{ type: 'function', function: { name: 'f' } }]);
  assert.equal('tool_choice' in p, false);
  const only = { model: 'ppq/free', tools: [{ type: 'web_search_preview' }], tool_choice: 'required' };
  applyFreeModelStrip(only);
  assert.equal('tools' in only, false);
  assert.equal('tool_choice' in only, false);
});

test('free strip leaves a function tool named web_search alone (not a server tool)', () => {
  const p = { model: 'ppq/free', tools: [{ type: 'function', function: { name: 'web_search' } }], tool_choice: 'auto' };
  applyFreeModelStrip(p);
  assert.equal(p.tools.length, 1);
  assert.equal(p.tool_choice, 'auto');
});

// ── applyToolStrip (issue #6, driven by hp strip_tools) ──────────────────────

test('tool strip removes tools + tool_choice for an unsupported model', () => {
  const p = {
    model: 'toyco/no-tools',
    tools: [{ type: 'function', function: { name: 'f' } }],
    tool_choice: 'auto',
  };
  applyToolStrip(p);
  assert.equal('tools' in p, false);
  assert.equal('tool_choice' in p, false);
});

test('tool strip leaves an empty tools array alone (matches hp length>0 guard)', () => {
  const p = { model: 'toyco/no-tools', tools: [], tool_choice: 'auto' };
  applyToolStrip(p);
  assert.deepEqual(p.tools, []);
  assert.equal(p.tool_choice, 'auto');
});

test('tool strip is a no-op when there are no tools', () => {
  const p = { model: 'toyco/no-tools', messages: [] };
  applyToolStrip(p);
  assert.deepEqual(p, { model: 'toyco/no-tools', messages: [] });
});


// ── applyAutoRouterConfig (horse-power#790, driven by hp auto_router) ─────────

const SETTINGS = {
  allowed_models: ['openai/gpt-5.5', 'deepseek/deepseek-v4-flash'],
  cost_tier: 'low',
};

test('auto-router injects the allow-list plugin on openrouter/auto', () => {
  const p = { model: 'openrouter/auto', messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.deepEqual(p.plugins, [
    {
      id: 'auto-router',
      allowed_models: ['openai/gpt-5.5', 'deepseek/deepseek-v4-flash'],
      cost_tier: 'low',
    },
  ]);
});

test('auto-router appends after existing plugins, preserving order', () => {
  const p = { model: 'openrouter/auto', plugins: [{ id: 'web' }], messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.deepEqual(p.plugins.map((x) => x.id), ['web', 'auto-router']);
});

test('a caller-supplied auto-router plugin wins', () => {
  const caller = { id: 'auto-router', allowed_models: ['x/y'] };
  const p = { model: 'openrouter/auto', plugins: [caller], messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.deepEqual(p.plugins, [caller]);
});

test('auto-router copies the allow-list rather than aliasing hp settings', () => {
  const p = { model: 'openrouter/auto', messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  p.plugins[0].allowed_models.push('mutated');
  assert.deepEqual(SETTINGS.allowed_models, [
    'openai/gpt-5.5',
    'deepseek/deepseek-v4-flash',
  ]);
});

// The DIRECTIVE decides, not the model string: hp omits `auto_router` for every
// model that should not be constrained (including suffixed Auto, which its
// normal path also leaves alone), so this applies whatever it is handed. Pinned
// because re-adding a model test here would silently diverge from hp's gate.
test('auto-router applies on whatever model hp sent the directive for', () => {
  const p = { model: 'openrouter/auto:exacto', messages: [] };
  applyAutoRouterConfig(p, SETTINGS);
  assert.deepEqual(p.plugins.map((x) => x.id), ['auto-router']);
});

// Without the directive the enclave must NOT invent an allow-list: an older hp
// that doesn't send `auto_router` has to keep working, and a fabricated list
// would be worse than none.
test('auto-router is a no-op when hp sent no directive', () => {
  const p = { model: 'openrouter/auto', messages: [] };
  applyAutoRouterConfig(p, undefined);
  assert.equal('plugins' in p, false);
});


// ── parseAutoRouter (horse-power#790) ────────────────────────────────────────
//
// Guards against hp DRIFT, not against a hostile hp: a renamed field or retired
// cost format must degrade to "no allow-list" rather than become a plugin
// OpenRouter 400s on. Every reject below is a config change that would
// otherwise have turned into an outage.

const GOOD = { allowed_models: ['openai/gpt-5.5', 'anthropic/*'], cost_tier: 'low' };

test('parseAutoRouter accepts a well-formed directive', () => {
  assert.deepEqual(parseAutoRouter(GOOD), {
    allowed_models: ['openai/gpt-5.5', 'anthropic/*'],
    cost_tier: 'low',
  });
});

test('parseAutoRouter copies the array rather than aliasing hp state', () => {
  const out = parseAutoRouter(GOOD);
  out.allowed_models.push('mutated');
  assert.deepEqual(GOOD.allowed_models, ['openai/gpt-5.5', 'anthropic/*']);
});

test('parseAutoRouter rejects a retired numeric cost format', () => {
  // The exact drift this nearly shipped: hp moved cost_quality_tradeoff -> cost_tier.
  assert.equal(parseAutoRouter({ allowed_models: ['a/b'], cost_quality_tradeoff: 7 }), null);
});

for (const [name, bad] of [
  ['absent', undefined],
  ['null', null],
  ['not an object', 'nope'],
  ['no allow-list', { cost_tier: 'low' }],
  ['empty allow-list', { allowed_models: [], cost_tier: 'low' }],
  ['non-string entry', { allowed_models: ['a/b', 42], cost_tier: 'low' }],
  ['malformed slug', { allowed_models: ['a/b', 'has space'], cost_tier: 'low' }],
  ['unknown cost tier', { allowed_models: ['a/b'], cost_tier: 'cheap' }],
  ['over the length cap', { allowed_models: Array(101).fill('a/b'), cost_tier: 'low' }],
]) {
  test(`parseAutoRouter rejects: ${name}`, () => {
    assert.equal(parseAutoRouter(bad), null);
  });
}

// ── Venice ignore merge + quality floor (hp #997) ────────────────────────────

import { transformPayload, parseProviderFloor, applyProviderFloor, applyProviderDirective } from '../src/routing.mjs';

test('a caller provider object no longer drops the platform Venice ignore', () => {
  const p = { model: 'z-ai/glm-5.3-flash', messages: [], provider: { sort: 'price' } };
  transformPayload(p);
  assert.deepEqual(p.provider, { sort: 'price', ignore: ['venice', 'amazon-bedrock'] });
});

test('platform exclusions keep an existing ignore list and do not duplicate entries', () => {
  const p = { model: 'z-ai/glm-5.3-flash', messages: [], provider: { ignore: ['deepinfra', 'venice'] } };
  transformPayload(p);
  assert.deepEqual(p.provider.ignore, ['deepinfra', 'venice', 'amazon-bedrock']);
  const both = { model: 'z-ai/glm-5.3-flash', messages: [], provider: { ignore: ['amazon-bedrock', 'venice'] } };
  transformPayload(both);
  assert.deepEqual(both.provider.ignore, ['amazon-bedrock', 'venice']);
});

test('the venice-edition model is still Venice-only, and still never Bedrock (#453)', () => {
  const p = { model: 'cognitivecomputations/dolphin-mistral-24b-venice-edition', messages: [], provider: { sort: 'price' } };
  transformPayload(p);
  assert.deepEqual(p.provider, { sort: 'price', ignore: ['amazon-bedrock'] });
});

test('parseProviderFloor accepts a clean floor and rejects anything malformed', () => {
  assert.deepEqual(parseProviderFloor({ quantizations: ['fp8', 'mxfp4', 'unknown'] }), {
    quantizations: ['fp8', 'mxfp4', 'unknown'],
  });
  for (const bad of [null, 'fp8', {}, { quantizations: [] }, { quantizations: ['FP 8'] }, { quantizations: [1] },
    { quantizations: Array.from({ length: 17 }, () => 'fp8') }]) {
    assert.equal(parseProviderFloor(bad), null, JSON.stringify(bad));
  }
});

test('applyProviderFloor merges into the routing provider; explicit caller choices win', () => {
  const floor = { quantizations: ['bf16', 'fp8', 'unknown'] };
  const p = { model: 'z-ai/glm-5.3-flash', provider: { ignore: ['venice'] } };
  applyProviderFloor(p, floor);
  assert.deepEqual(p.provider, { ignore: ['venice'], quantizations: ['bf16', 'fp8', 'unknown'] });

  const q = { provider: { quantizations: ['fp4'] } };
  applyProviderFloor(q, floor);
  assert.deepEqual(q.provider, { quantizations: ['fp4'] });

  const o = { provider: { only: ['novita'] } };
  applyProviderFloor(o, floor);
  assert.deepEqual(o.provider, { only: ['novita'] });

  const none = {};
  applyProviderFloor(none, null);
  assert.equal('provider' in none, false);
});

// ── web_search_engine on the settle (horse-power #1088; Oct 17-19 reports) ───

test('web_search_engine: the Exa plugin on the FINAL body is "exa", exactly as hp judges it', () => {
  assert.equal(webSearchEngineOf({ plugins: [{ id: 'web', engine: 'exa', mode: 'fast' }] }), 'exa');
  // The predicate reads the engine field, never defaults it: an engine-less
  // plugin is whatever OpenRouter resolves, which hp does not bill as Exa.
  assert.equal(exaWebPluginRequested({ plugins: [{ id: 'web' }] }), false);
  assert.equal(exaWebPluginRequested({ plugins: [{ id: 'web', engine: 'native' }] }), false);
  assert.equal(exaWebPluginRequested({ plugins: 'web' }), false);
  assert.equal(exaWebPluginRequested(null), false);
});

test('web_search_engine: a provider-native search is "native", no search at all is undefined', () => {
  assert.equal(webSearchEngineOf({ plugins: [{ id: 'web' }] }), 'native', 'engine-less plugin: the provider resolves it');
  assert.equal(webSearchEngineOf({ tools: [{ type: 'openrouter:web_search' }] }), 'native');
  assert.equal(webSearchEngineOf({ tools: [{ type: 'openrouter:web_search' }], tool_choice: 'none' }), undefined, 'a tool that cannot run is not a search');
  assert.equal(webSearchEngineOf({ model: 'm', messages: [] }), undefined);
  // A dialect judges "asks for search" with its own test on the same body.
  assert.equal(webSearchEngineOf({ tools: [{ type: 'web_search_20250305', name: 'web_search' }] }, messagesHasWebSearch), 'native');
  assert.equal(webSearchEngineOf({ tools: [{ type: 'web_search_20250305', name: 'web_search' }] }), undefined, 'the chat test does not know the dated tool');
});

test('web_search_engine: follows the transforms, so the :online directive is "exa" except where the #676 swap makes it native, and the free strip makes it undefined', () => {
  const online = { model: 'deepseek/deepseek-v4-flash', messages: [] };
  applyWebPluginDirective(online); transformPayload(online);
  assert.equal(webSearchEngineOf(online), 'exa');
  const sonnet = { model: 'anthropic/claude-sonnet-4.6', messages: [] };
  applyWebPluginDirective(sonnet); transformPayload(sonnet);
  assert.equal(webSearchEngineOf(sonnet), 'exa', 'the #676 swap covers only the models the plugin breaks');
  const claude = { model: '~anthropic/claude-fable-latest', messages: [] };
  applyWebPluginDirective(claude); transformPayload(claude);
  assert.equal(claude.plugins, undefined, 'swapped onto the server tool');
  assert.equal(webSearchEngineOf(claude), 'native');
  const free = { model: 'ppq/free', messages: [], plugins: [{ id: 'web', engine: 'exa' }], tools: [{ type: 'openrouter:web_search' }] };
  applyFreeModelStrip(free);
  assert.equal(webSearchEngineOf(free), undefined, 'nothing left to search with');
});

// ── `enabled: false` web plugin (horse-power #1094) ─────────────────────────

test('free strip removes a disabled web plugin too (plugins are dropped wholesale)', () => {
  const p = { model: 'ppq/free', plugins: [{ id: 'web', enabled: false }], messages: [] };
  applyFreeModelStrip(p);
  assert.equal('plugins' in p, false);
});

test(':online directive beside a disabled web plugin yields one active plugin', () => {
  const p = { model: 'x/y', plugins: [{ id: 'web', enabled: false }] };
  applyWebPluginDirective(p);
  assert.deepEqual(p.plugins, [{ id: 'web' }], 'the disabled sibling is dropped, not left to contradict the ask');
  // An active caller plugin keeps its options; nothing is added.
  const keep = { model: 'x/y', plugins: [{ id: 'web', engine: 'exa', max_results: 2 }] };
  applyWebPluginDirective(keep);
  assert.deepEqual(keep.plugins, [{ id: 'web', engine: 'exa', max_results: 2 }]);
});

test('exaWebPluginRequested / webSearchEngineOf: a disabled Exa plugin is not an Exa search', () => {
  assert.equal(exaWebPluginRequested({ plugins: [{ id: 'web', engine: 'exa' }] }), true);
  assert.equal(exaWebPluginRequested({ plugins: [{ id: 'web', engine: 'exa', enabled: true }] }), true);
  assert.equal(exaWebPluginRequested({ plugins: [{ id: 'web', engine: 'exa', enabled: false }] }), false);
  assert.equal(webSearchEngineOf({ plugins: [{ id: 'web', engine: 'exa', enabled: false }] }), undefined);
  assert.equal(webSearchEngineOf({ plugins: [{ id: 'web', engine: 'exa' }] }), 'exa');
});

// ── caller provider.zdr survives routing (Oct 17-19 security reports, apienz 3/3) ──

// The Claude default since #453: Anthropic BYOK, then Vertex BYOK, then the
// rest of OpenRouter; never Amazon Bedrock.
const CLAUDE_DEFAULT = {
  order: ['anthropic', 'google-vertex'],
  ignore: ['amazon-bedrock'],
  allow_fallbacks: true,
};

test('zdr: a Claude request keeps the caller zdr on top of the Claude default', () => {
  const p = { model: 'anthropic/claude-sonnet-4.5', messages: [], provider: { zdr: true } };
  transformPayload(p);
  assert.deepEqual(p.provider, { ...CLAUDE_DEFAULT, zdr: true });
});

test('zdr: other caller provider keys still do not survive the Claude routing', () => {
  const p = { model: 'anthropic/claude-sonnet-4.5', messages: [], provider: { zdr: true, sort: 'price', order: ['x'] } };
  transformPayload(p);
  assert.deepEqual(p.provider, { ...CLAUDE_DEFAULT, zdr: true });
});

test('zdr: kept on the Fable pin and on the web-plugin (ignore bedrock) route', () => {
  const fable = { model: 'anthropic/claude-fable-5.1', messages: [], provider: { zdr: true } };
  transformPayload(fable);
  assert.deepEqual(fable.provider, { order: ['anthropic'], allow_fallbacks: false, zdr: true });
  const web = { model: 'anthropic/claude-sonnet-4.5', messages: [], plugins: [{ id: 'web' }], provider: { zdr: true } };
  transformPayload(web);
  assert.deepEqual(web.provider, { ignore: ['amazon-bedrock'], zdr: true });
});

test('zdr: a Claude request without zdr is untouched (no zdr key appears)', () => {
  const p = { model: 'anthropic/claude-sonnet-4.5', messages: [] };
  transformPayload(p);
  assert.deepEqual(p.provider, CLAUDE_DEFAULT);
  const off = { model: 'anthropic/claude-sonnet-4.5', messages: [], provider: { zdr: false } };
  transformPayload(off);
  assert.deepEqual(off.provider, CLAUDE_DEFAULT);
});

test('zdr: opus-4.8 + web search drops it, in both web-search forms (parity with hp opus48Web)', () => {
  const plugin = { model: 'anthropic/claude-opus-4.8', messages: [], plugins: [{ id: 'web' }], provider: { zdr: true } };
  transformPayload(plugin);
  assert.equal(plugin.provider.zdr, undefined);
  const tool = { model: 'anthropic/claude-opus-4.8', messages: [], tools: [{ type: 'openrouter:web_search' }], provider: { zdr: true } };
  transformPayload(tool);
  assert.equal(tool.provider.zdr, undefined);
  // ...but a disabled plugin or an uncallable tool is not a web search: zdr stays.
  const disabled = { model: 'anthropic/claude-opus-4.8', messages: [], plugins: [{ id: 'web', enabled: false }], provider: { zdr: true } };
  transformPayload(disabled);
  assert.equal(disabled.provider.zdr, true);
  const uncallable = {
    model: 'anthropic/claude-opus-4.8', messages: [],
    tools: [{ type: 'openrouter:web_search' }], tool_choice: 'none',
    provider: { zdr: true },
  };
  transformPayload(uncallable);
  assert.equal(uncallable.provider.zdr, true);
  // An uncallable tool is not a web search for the provider decision either:
  // the Claude default stays, as hp's callable-predicate decision keeps it (hp
  // #1096; the earlier by-type read here was the drift the #1107 fixtures found).
  assert.deepEqual(uncallable.provider, { ...CLAUDE_DEFAULT, zdr: true });
  const none = { model: 'anthropic/claude-opus-4.8', messages: [], provider: { zdr: true } };
  transformPayload(none);
  assert.deepEqual(none.provider, { ...CLAUDE_DEFAULT, zdr: true });
});

test('json_schema: a Claude request takes the Claude default (#445 pin folded into #453)', () => {
  const schema = { type: 'json_schema', json_schema: { name: 'a', schema: { type: 'object' } } };
  const p = { model: 'anthropic/claude-haiku-5.5', messages: [], response_format: schema };
  transformPayload(p);
  assert.deepEqual(p.provider, CLAUDE_DEFAULT);
  assert.deepEqual(p.response_format, schema);
  // The caller's zdr still rides on top, as on every Claude branch.
  const zdr = { model: 'anthropic/claude-opus-5.5', messages: [], response_format: schema, provider: { zdr: true } };
  transformPayload(zdr);
  assert.deepEqual(zdr.provider, { ...CLAUDE_DEFAULT, zdr: true });
  for (const type of ['json_object', 'text']) {
    const q = { model: 'anthropic/claude-haiku-5.5', messages: [], response_format: { type } };
    transformPayload(q);
    assert.deepEqual(q.provider, CLAUDE_DEFAULT, type);
  }
  // Branches with their own routing are unchanged by the shape.
  const web = { model: 'anthropic/claude-haiku-5.5', messages: [], plugins: [{ id: 'web' }], response_format: schema };
  transformPayload(web);
  assert.deepEqual(web.provider, { ignore: ['amazon-bedrock'] });
  const fable = { model: 'anthropic/claude-fable-5.1', messages: [], response_format: schema };
  transformPayload(fable);
  assert.deepEqual(fable.provider, { order: ['anthropic'], allow_fallbacks: false });
});

test('#453: no Claude branch names amazon-bedrock in `order`, and Opus 5 takes the default', () => {
  for (const model of ['anthropic/claude-opus-5.5', 'anthropic/claude-opus-5', 'anthropic/claude-sonnet-5.5', 'anthropic/claude-haiku-5.5']) {
    const p = { model, messages: [] };
    transformPayload(p);
    assert.deepEqual(p.provider, CLAUDE_DEFAULT, model);
  }
  // Opus 5 + the web PLUGIN keeps its Anthropic pin (layout, not Bedrock).
  const opus5Web = { model: 'anthropic/claude-opus-5', messages: [], plugins: [{ id: 'web', engine: 'native' }] };
  transformPayload(opus5Web);
  assert.deepEqual(opus5Web.provider, { order: ['anthropic'], allow_fallbacks: false });
});

test('zdr: a non-Anthropic model behaves as before (spread + venice ignore)', () => {
  const p = { model: 'z-ai/glm-5.3-flash', messages: [], provider: { zdr: true } };
  transformPayload(p);
  assert.deepEqual(p.provider, { zdr: true, ignore: ['venice', 'amazon-bedrock'] });
});

test('applyProviderDirective: the directive replaces the caller object but keeps zdr', () => {
  const directive = { only: ['google-vertex'], allow_fallbacks: false };
  const p = { model: 'google/gemini-2.5-flash', messages: [], provider: { zdr: true, sort: 'price' } };
  assert.equal(applyProviderDirective(p, directive), true);
  assert.deepEqual(p.provider, { only: ['google-vertex'], allow_fallbacks: false, zdr: true });
  assert.notEqual(p.provider, directive); // a copy, hp's object is not aliased
  transformPayload(p);
  assert.deepEqual(p.provider, { only: ['google-vertex'], allow_fallbacks: false, zdr: true, ignore: ['venice', 'amazon-bedrock'] });
});

test('applyProviderDirective: no zdr means a plain replace; no/invalid directive is a no-op', () => {
  const p = { model: 'google/gemini-2.5-flash', messages: [], provider: { sort: 'price' } };
  assert.equal(applyProviderDirective(p, { only: ['google-vertex'] }), true);
  assert.deepEqual(p.provider, { only: ['google-vertex'] });
  const q = { model: 'x/y', messages: [], provider: { zdr: true } };
  assert.equal(applyProviderDirective(q, null), false);
  assert.equal(applyProviderDirective(q, undefined), false);
  assert.equal(applyProviderDirective(q, ['only']), false);
  assert.deepEqual(q.provider, { zdr: true });
});

// ── #459: data_collection rides like zdr; routing suffixes; neutral web_search alias ──

test('#459 data_collection: carried on top of the Claude default, the Fable pin and the web route', () => {
  const p = { model: 'anthropic/claude-sonnet-5.5', messages: [], provider: { data_collection: 'deny', zdr: true, sort: 'price' } };
  transformPayload(p);
  assert.deepEqual(p.provider, { ...CLAUDE_DEFAULT, zdr: true, data_collection: 'deny' });
  const fable = { model: 'anthropic/claude-fable-5.1', messages: [], provider: { data_collection: 'allow' } };
  transformPayload(fable);
  assert.deepEqual(fable.provider, { order: ['anthropic'], allow_fallbacks: false, data_collection: 'allow' });
  const web = { model: 'anthropic/claude-sonnet-5.5', messages: [], plugins: [{ id: 'web' }], provider: { data_collection: 'deny' } };
  transformPayload(web);
  assert.deepEqual(web.provider, { ignore: ['amazon-bedrock'], data_collection: 'deny' });
  // A non-Claude model keeps it through the platform merge too.
  const glm = { model: 'z-ai/glm-5.3', messages: [], provider: { data_collection: 'deny' } };
  transformPayload(glm);
  assert.deepEqual(glm.provider, { data_collection: 'deny', ignore: ['venice', 'amazon-bedrock'] });
  // Only the documented values ride.
  const junk = { model: 'anthropic/claude-sonnet-5.5', messages: [], provider: { data_collection: 'maybe' } };
  transformPayload(junk);
  assert.deepEqual(junk.provider, CLAUDE_DEFAULT);
});

test('#459 data_collection: applyProviderDirective and applyHardProviderPin keep it beside zdr', () => {
  const chat = { model: 'google/gemini-4-argon', provider: { data_collection: 'deny', zdr: true, order: ['x'] } };
  applyProviderDirective(chat, { only: ['google-vertex'], allow_fallbacks: false });
  assert.deepEqual(chat.provider, { only: ['google-vertex'], allow_fallbacks: false, zdr: true, data_collection: 'deny' });
  const relay = { model: 'google/gemini-4-argon', provider: { data_collection: 'allow' } };
  applyHardProviderPin(relay, { only: ['google-vertex'], allow_fallbacks: false, ignore: ['venice'] });
  assert.deepEqual(relay.provider, { only: ['google-vertex'], allow_fallbacks: false, ignore: ['venice'], data_collection: 'allow' });
});

test('#459 routing suffixes on Claude mirror hp: the order is dropped, Bedrock stays excluded, sort rides', () => {
  const nitro = { model: 'anthropic/claude-sonnet-4.6', messages: [] };
  transformPayload(nitro, { routingSort: 'throughput' });
  assert.deepEqual(nitro.provider, { ignore: ['amazon-bedrock'], sort: 'throughput' });
  const floor = { model: 'anthropic/claude-sonnet-4.6', messages: [], provider: { zdr: true } };
  transformPayload(floor, { routingSort: 'price' });
  assert.deepEqual(floor.provider, { ignore: ['amazon-bedrock'], zdr: true, sort: 'price' });
  const exacto = { model: 'anthropic/claude-sonnet-4.6:exacto', messages: [] };
  transformPayload(exacto, { exacto: true });
  assert.deepEqual(exacto.provider, { ignore: ['amazon-bedrock'] });
  // An unknown sort value is ignored; no opts means the default.
  const junk = { model: 'anthropic/claude-sonnet-4.6', messages: [] };
  transformPayload(junk, { routingSort: 'latency' });
  assert.deepEqual(junk.provider, CLAUDE_DEFAULT);
  // A non-Claude model keeps the directive's sort through the merge, as before.
  const llama = { model: 'meta-llama/llama-3.3-70b-instruct', messages: [], provider: { sort: 'throughput' } };
  transformPayload(llama, { routingSort: 'throughput' });
  assert.deepEqual(llama.provider, { sort: 'throughput', ignore: ['venice', 'amazon-bedrock'] });
});

test('#459 (#429) the neutral web_search alias is rewritten first, so the Exa collapse and is_online see one form', () => {
  const p = { model: 'openai/gpt-6-astra', messages: [], tools: [{ type: 'web_search' }], tool_choice: { type: 'web_search' } };
  transformPayload(p);
  assert.equal(p.tools, undefined, 'collapsed to the Exa plugin, as hp does');
  assert.deepEqual(p.plugins, [{ id: 'web', engine: 'exa', mode: 'fast' }]);
  assert.equal(p.tool_choice, undefined);
  // Anthropic keeps its native server tool under the wire name.
  const claude = { model: 'anthropic/claude-sonnet-5.5', messages: [], tools: [{ type: 'web_search' }] };
  transformPayload(claude);
  assert.deepEqual(claude.tools, [{ type: 'openrouter:web_search' }]);
  assert.deepEqual(claude.provider, { ignore: ['amazon-bedrock'] });
  // A caller's own `web_search` FUNCTION is not ours to rename.
  const fn = { model: 'openai/gpt-6-astra', messages: [], tools: [{ type: 'function', function: { name: 'web_search' } }], tool_choice: { type: 'function', function: { name: 'web_search' } } };
  transformPayload(fn);
  assert.deepEqual(fn.tools, [{ type: 'function', function: { name: 'web_search' } }]);
  assert.deepEqual(fn.tool_choice, { type: 'function', function: { name: 'web_search' } });
});
