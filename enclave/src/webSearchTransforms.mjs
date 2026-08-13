/**
 * Web-search request transforms — SINGLE SOURCE OF TRUTH.
 *
 * This module is the authoritative copy. The enclave (ppq-enclave-proxy
 * enclave/src/webSearchTransforms.mjs) vendors a BYTE-IDENTICAL copy so the
 * confidential path applies the exact same logic as horse-power. The enclave
 * conformance test asserts the two files are identical + behaviourally in sync
 * — do not edit one without the other.
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

/** True when a `tool_choice` value forces the `openrouter:web_search` server tool specifically. */
export function toolChoiceTargetsWebSearch(choice) {
  return (
    choice?.type === 'openrouter:web_search' ||
    choice?.function?.name === 'openrouter:web_search'
  );
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
      if (p?.id !== 'web') continue;
      if (p.engine === undefined) p.engine = 'exa';
      if (p.engine === 'exa' && p.mode === undefined) p.mode = 'fast';
    }
  }
}

// Models where OpenRouter forwards the Exa web plugin's injected search-results
// `system` message verbatim to Anthropic's directive-capable API surface, which
// 400s every turn after the first (issue #676). Substring match covers dated
// permaslugs + `-fast` derived twins, gated on the `anthropic` namespace so a
// non-Anthropic model containing a fragment (e.g. "fable") can never match.
export const WEB_PLUGIN_BROKEN_MODELS = ['fable', 'claude-opus-5', 'claude-opus-4.8'];

export function webPluginBreaksModel(model) {
  return (
    typeof model === 'string' &&
    model.includes('anthropic') &&
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
  const web = payload.plugins.find((p) => p?.id === 'web');
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
  if (typeof model !== 'string') return false;
  const m = model.toLowerCase();
  return FAST_NATIVE_SEARCH_NAMESPACES.some((ns) => m.startsWith(ns));
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
    Array.isArray(payload.plugins) && payload.plugins.some((p) => p?.id === 'web');
  if (!alreadyHasPlugin) {
    const web = { id: 'web' };
    // engine/mode are left for applyWebSearchEngine to default (exa + fast).
    if (typeof webTool.parameters?.max_results === 'number') {
      web.max_results = webTool.parameters.max_results;
    }
    payload.plugins = [...(Array.isArray(payload.plugins) ? payload.plugins : []), web];
  }
}
