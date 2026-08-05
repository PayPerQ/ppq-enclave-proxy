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

/**
 * Standardize web search on the Exa engine for every model except Perplexity
 * (which has its own built-in search). Touches only the `web` plugin and the
 * `openrouter:web_search` tool — never caller-defined function tools.
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
      if (p?.id === 'web' && p.engine === undefined) p.engine = 'exa';
    }
  }
  if (Array.isArray(payload?.tools)) {
    for (const t of payload.tools) {
      if (t?.type === 'openrouter:web_search' && t.parameters?.engine === undefined) {
        t.parameters = { ...(t.parameters || {}), engine: 'exa' };
      }
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
 */
export function swapWebPluginForServerTool(payload) {
  if (!Array.isArray(payload.plugins)) return;
  const web = payload.plugins.find((p) => p?.id === 'web');
  if (!web || (web.engine !== undefined && web.engine !== 'exa')) return;
  payload.plugins = payload.plugins.filter((p) => p?.id !== 'web');
  if (payload.plugins.length === 0) delete payload.plugins;
  if (!hasWebSearchTool(payload)) {
    const parameters = { engine: 'exa' };
    if (typeof web.max_results === 'number') parameters.max_results = web.max_results;
    payload.tools = [
      ...(Array.isArray(payload.tools) ? payload.tools : []),
      { type: 'openrouter:web_search', parameters },
    ];
  }
}
