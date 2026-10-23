/**
 * Web-search request transforms — the enclave's port of horse-power's.
 *
 * horse-power's authoritative versions of these helpers live in
 * services/chatPayload.ts (hasWebSearchTool, isActiveWebPlugin,
 * webSearchToolActive, hasWebSearch, applyWebSearchEngine, modelNamespace,
 * webPluginBreaksModel, swapWebPluginForServerTool, modelHasFastNativeSearch,
 * swapWebSearchToolForPlugin). This file ports them one for one so the
 * confidential path applies the same logic as horse-power's cleartext path.
 * Parity is BEHAVIOURAL, not byte-identical (the hp file is TypeScript inside
 * a larger module): horse-power's enclave-conformance workflow drives this
 * repo's routing.mjs with hp's own fixtures and fails on any divergence, so
 * do not change a rule here without the matching change in chatPayload.ts.
 *
 * Pure: operates only on payload.model (a string) + payload.plugins/tools. No
 * catalog, no message content — so it can run inside the enclave with no
 * /authorize round-trip and no new metadata exposure.
 */

/** True when the `openrouter:web_search` server tool is declared on the payload. */
export function hasWebSearchTool(payload) {
  return (
    Array.isArray(payload?.tools) &&
    payload.tools.some((t) => t?.type === 'openrouter:web_search')
  );
}

/**
 * A `web` plugin entry that is actually ON. OpenRouter's documented way to turn
 * a plugin off for one request is `{ id: 'web', enabled: false }`
 * (https://openrouter.ai/docs/guides/features/plugins, "Disabling a default
 * plugin"): no search runs, so the entry must not count as one anywhere it is
 * read (is_online, the Exa engine label the settle reports, the #676 / #2550
 * swaps, the `:online` injection). Mirrors horse-power chatPayload.ts
 * isActiveWebPlugin (horse-power #1094; before it, a caller that disabled the
 * plugin instead of omitting it was marked online and, on a BYOK account,
 * charged the web-search fee for a search that never ran).
 */
export function isActiveWebPlugin(p) {
  return p?.id === 'web' && p?.enabled !== false;
}

/**
 * Any plugin entry that is IN EFFECT, regardless of id. `enabled: false` is
 * OpenRouter's generic per-plugin switch (not web-specific), so an entry
 * carrying it runs nothing and must not steer provider selection: the Anthropic
 * routing block in routing.mjs treats "has plugins" as a reason to leave the
 * Bedrock BYOK pin, which an inert entry should not trigger. (Oct 17-19
 * security reports follow-up, raised by CodeRabbit on PR #348; mirrors
 * horse-power chatPayload.ts isActivePlugin, horse-power #1095.)
 */
export function isActivePlugin(p) {
  return p?.enabled !== false;
}

/** True when a `tool_choice` value forces the `openrouter:web_search` server tool specifically. */
export function toolChoiceTargetsWebSearch(choice) {
  return (
    choice?.type === 'openrouter:web_search' ||
    choice?.function?.name === 'openrouter:web_search'
  );
}

/**
 * True when the `openrouter:web_search` tool is both declared AND callable.
 *
 * `tool_choice: 'none'` disables every tool, and a forced choice targeting a
 * different tool means web search can never run for this request — so declaring
 * the tool is not the same as being able to search.
 *
 * Mirrors horse-power `chatPayload.ts` `webSearchToolActive`.
 */
export function webSearchToolActive(payload) {
  if (!hasWebSearchTool(payload)) return false;
  const choice = payload?.tool_choice;
  if (choice === 'none') return false;
  if (choice && typeof choice === 'object' && !toolChoiceTargetsWebSearch(choice)) {
    return false;
  }
  return true;
}

/**
 * True when web search can actually run: the always-on `web` plugin (On mode)
 * or a callable `openrouter:web_search` server tool (Auto mode).
 *
 * This is the `isOnline` analytics flag, and it must agree with horse-power's
 * `hasWebSearch` or enclave traffic reports differently from cleartext traffic
 * for the same request. Before this existed the enclave tested `plugins` alone,
 * so every Auto-mode search — the DEFAULT for a user who has never touched the
 * setting — was recorded as offline (#8).
 *
 * Note both implementations ignore a `:online` model suffix. That is a real gap,
 * but it is a shared one: adding it here alone would turn a reporting bug into
 * enclave/horse-power drift, which the conformance gate exists to prevent.
 */
export function hasWebSearch(payload) {
  const pluginWeb =
    Array.isArray(payload?.plugins) && payload.plugins.some(isActiveWebPlugin);
  return pluginWeb || webSearchToolActive(payload);
}

/**
 * Default the `web` plugin (On mode) to OpenRouter's Exa engine in its `fast`
 * mode, on every model EXCEPT Perplexity (a search-native model deliberately
 * left on its provider's native search). `mode: 'fast'` is Exa's ~450ms tier;
 * measured end-to-end it beats the unset default (~2.30s → ~1.52s to first
 * token) with citations intact.
 *
 * DELIBERATELY NOT APPLIED TO THE SERVER TOOL (issue PPQdotAI#2550): attaching
 * ANY third-party engine to `openrouter:web_search` triggers a flat ~10s of
 * OpenRouter orchestration before the first token. Leaving the tool's engine
 * unset lets OpenRouter default it to `auto` (provider-native first). Models
 * with no provider-native search never reach this: swapWebSearchToolForPlugin
 * has already converted their tool into the plugin.
 *
 * Only SUPPLIES defaults — a caller that set `engine`/`mode` keeps their values.
 */
export function applyWebSearchEngine(payload) {
  if (
    typeof payload?.model === 'string' &&
    payload.model.startsWith('perplexity/')
  ) {
    return;
  }
  if (Array.isArray(payload?.plugins)) {
    for (const p of payload.plugins) {
      if (!isActiveWebPlugin(p)) continue;
      if (p.engine === undefined) p.engine = 'exa';
      if (p.engine === 'exa' && p.mode === undefined) p.mode = 'fast';
    }
  }
}

/**
 * The provider namespace of a model slug, as `author/` ('' when it carries
 * none). Sees through OpenRouter's floating-alias `~` prefix, so
 * `~anthropic/claude-fable-latest` is the same namespace as
 * `anthropic/claude-fable-5`.
 *
 * Shared by BOTH swaps on purpose (issue horse-power#827): they used to
 * disagree — webPluginBreaksModel on a substring, modelHasFastNativeSearch on a
 * prefix — so a `~anthropic/*` payload was swapped plugin -> tool and then
 * straight back to the plugin. Mirrors horse-power chatPayload.ts.
 */
export function modelNamespace(model) {
  if (typeof model !== 'string') return '';
  const slug = model.toLowerCase().replace(/^~/, '');
  const slash = slug.indexOf('/');
  return slash === -1 ? '' : slug.slice(0, slash + 1);
}

// Models where OpenRouter forwards the Exa web plugin's injected search-results
// `system` message verbatim to Anthropic's directive-capable API surface, which
// 400s every turn after the first (issue #676). Substring match covers dated
// permaslugs + `-fast` derived twins, gated on the `anthropic` namespace so a
// non-Anthropic model containing a fragment (e.g. "fable") can never match.
//
// THIS LIST FAILS OPEN: a directive-capable Claude model missing here keeps the
// plugin and 400s on every turn after the first. Sonnet 5 was added in
// horse-power#827, ~2 months after #676 shipped with the other three. Probe a
// THREE-message conversation before assuming a new Claude model is unaffected —
// turn 1 succeeds either way.
export const WEB_PLUGIN_BROKEN_MODELS = [
  'fable',
  'claude-opus-5',
  'claude-opus-4.8',
  'claude-sonnet-5',
];

export function webPluginBreaksModel(model) {
  return (
    modelNamespace(model) === 'anthropic/' &&
    WEB_PLUGIN_BROKEN_MODELS.some((frag) => model.includes(frag))
  );
}

/**
 * For models the web plugin breaks (#676), carry the search as the
 * `openrouter:web_search` server tool instead of the plugin. No-op unless a
 * `web` plugin (engine exa/unset) is present.
 *
 * The emitted tool is deliberately ENGINE-LESS (issue PPQdotAI#2550): it used
 * to carry `engine: 'exa'`, which put every Claude "On"-mode request onto the
 * ~10s third-party server-tool floor. Unset lets OpenRouter resolve `auto` to
 * Anthropic's own search (~3s, citations intact).
 */
export function swapWebPluginForServerTool(payload) {
  if (!Array.isArray(payload.plugins)) return;
  const web = payload.plugins.find(isActiveWebPlugin);
  if (!web || (web.engine !== undefined && web.engine !== 'exa')) return;
  payload.plugins = payload.plugins.filter((p) => p?.id !== 'web');
  if (payload.plugins.length === 0) delete payload.plugins;
  if (!hasWebSearchTool(payload)) {
    const parameters = {};
    if (typeof web.max_results === 'number') parameters.max_results = web.max_results;
    payload.tools = [
      ...(Array.isArray(payload.tools) ? payload.tools : []),
      { type: 'openrouter:web_search', parameters },
    ];
  }
}

/**
 * The ONLY namespaces that keep the `openrouter:web_search` server tool; every
 * other model has its tool collapsed to the Exa `web` plugin (issue
 * PPQdotAI#2550). anthropic/ is REQUIRED (the plugin 400s there, #676);
 * perplexity/ is search-native and cheaper than Exa. See horse-power
 * chatPayload.ts for the full measured rationale.
 */
export const FAST_NATIVE_SEARCH_NAMESPACES = ['anthropic/', 'perplexity/'];

export function modelHasFastNativeSearch(model) {
  return FAST_NATIVE_SEARCH_NAMESPACES.includes(modelNamespace(model));
}

/**
 * The web-search "Auto" collapse (issue PPQdotAI#2550). Inverse of
 * swapWebPluginForServerTool: converts the `openrouter:web_search` server tool
 * back into the `web` plugin on models with NO provider-native search — the
 * tool's third-party-engine path costs a flat ~10s of OpenRouter
 * orchestration; the plugin reaches the same Exa results in ~2-4s.
 *
 * SEMANTIC TRADEOFF, deliberately accepted: the tool lets the model choose per
 * turn, the plugin searches every turn. Only Exa-bound tools translate; a
 * caller who pinned another engine keeps their choice. Disjoint from
 * swapWebPluginForServerTool by construction (anthropic/ returns early here).
 */
export function swapWebSearchToolForPlugin(payload) {
  if (!Array.isArray(payload.tools)) return;
  if (modelHasFastNativeSearch(payload.model)) return;
  const webTool = payload.tools.find((t) => t?.type === 'openrouter:web_search');
  if (!webTool) return;
  // Only a CALLABLE tool is collapsed. The plugin form runs on every turn
  // regardless of tool calls, so converting a tool the caller suppressed
  // (`tool_choice: 'none'`, or a forced choice naming another tool) would turn
  // a search they switched off back on; and it would do so even past a disabled
  // `web` sibling they sent alongside. Leave the request as declared instead.
  // (CodeRabbit on PR #348; mirrors horse-power chatPayload.ts, horse-power
  // #1096.)
  if (!webSearchToolActive(payload)) return;
  const engine = webTool.parameters?.engine;
  if (engine !== undefined && engine !== 'exa') return;

  payload.tools = payload.tools.filter((t) => t?.type !== 'openrouter:web_search');
  const noToolsLeft = payload.tools.length === 0;
  if (noToolsLeft) delete payload.tools;
  // Two ways a stale tool_choice would 400 upstream once web search is gone:
  // one that named the tool we just removed, and any choice at all when NO
  // tools survive.
  if (noToolsLeft || toolChoiceTargetsWebSearch(payload.tool_choice)) {
    delete payload.tool_choice;
  }

  const alreadyHasPlugin =
    Array.isArray(payload.plugins) && payload.plugins.some(isActiveWebPlugin);
  if (!alreadyHasPlugin) {
    const web = { id: 'web' };
    // engine/mode are left for applyWebSearchEngine to default (exa + fast).
    if (typeof webTool.parameters?.max_results === 'number') {
      web.max_results = webTool.parameters.max_results;
    }
    // A disabled `web` entry the caller also sent is dropped rather than left
    // beside the active one: the declared tool is the explicit intent, and two
    // `web` entries that disagree would leave OpenRouter to pick.
    payload.plugins = [
      ...(Array.isArray(payload.plugins) ? payload.plugins.filter((p) => p?.id !== 'web') : []),
      web,
    ];
  }
}
