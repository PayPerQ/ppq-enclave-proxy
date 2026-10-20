/**
 * Streaming usage/cost extractor.
 *
 * A dependency-free port of horse-power's utils/streamParser.ts
 * (parseCostingChunk) plus the line-buffering the chat controller does around
 * it. Numbers are kept as JS numbers here (not BigNumber) — horse-power's
 * /enclave/settle re-wraps them in BigNumber and applies the billing margin, so
 * the enclave only needs to report the upstream figures it observed.
 */

import { providerName } from './providerName.mjs';

const MIN_COST = { input: 0.0000003, output: 0.000001 };

// Re-exported so existing imports from cost.mjs keep working.
export { providerName };

function parseCostingChunk(line) {
  try {
    if (!line.includes('"usage"')) return null;
    let json = line.startsWith('data: ') ? line.slice(6).trim() : line.trim();
    if (json === '[DONE]' || json === '') return null;

    const c = JSON.parse(json);

    const fromUsage = (usage, model, id, provider) => {
      const isByok = usage.is_byok === true;
      // The BYOK branch below bills the provider's inference cost only when
      // the frame carries one (hp's streamParser applies the same truthiness
      // test); otherwise the row is billed from OpenRouter's `cost`, Exa charge
      // included, and must NOT report itself as BYOK, or hp would add the fee
      // on a cost that already carries it. So the settle's `is_byok` is the
      // branch taken, not the flag the frame carried.
      const byokCost = isByok && Boolean(usage.cost_details?.upstream_inference_cost);
      const inputTokens = Number(
        usage.prompt_tokens || usage.input_tokens || 0,
      );
      const outputTokens = Number(
        usage.completion_tokens || usage.output_tokens || 0,
      );
      let totalCost;
      if (model?.endsWith(':free') && (usage.cost === 0 || usage.cost == null)) {
        totalCost = inputTokens * MIN_COST.input + outputTokens * MIN_COST.output;
      } else if (byokCost) {
        totalCost = Number(usage.cost_details.upstream_inference_cost);
      } else {
        totalCost = Number(usage.total_cost || usage.cost || 0);
      }
      const cacheReadTokens =
        usage.prompt_tokens_details?.cached_tokens ??
        usage.input_tokens_details?.cached_tokens ??
        usage.cache_read_input_tokens;
      const cacheWriteTokens =
        usage.prompt_tokens_details?.cache_write_tokens ??
        usage.input_tokens_details?.cache_write_tokens ??
        usage.cache_creation_input_tokens;
      // Reported VERBATIM for hp's settle to interpret per provider: on the
      // Vertex compat surface reasoning is ADDITIVE to completion_tokens and
      // billed at the output rate (hp folds it, descriptor-gated); on the
      // OR/Responses conventions it is already INSIDE the completion count
      // and hp deliberately ignores it there.
      const reasoningTokens =
        usage.completion_tokens_details?.reasoning_tokens ??
        usage.output_tokens_details?.reasoning_tokens;
      return {
        model,
        totalCost,
        inputTokens,
        outputTokens,
        // Whether the cost above is BYOK-sourced (`upstream_inference_cost`,
        // which excludes OpenRouter's own charges such as the Exa web-search
        // fee) or OpenRouter's `cost` (which includes them). The settle
        // reports it as `is_byok` so hp can bill the published web-search fee
        // on exactly the rows whose settled cost provably lacks it
        // (horse-power #1088; Oct 17-19 security reports, hel's paid-fee
        // finding). A boolean only once a usage frame has been read.
        isByok: byokCost,
        generationId: id,
        cacheReadTokens:
          typeof cacheReadTokens === 'number' ? cacheReadTokens : undefined,
        cacheWriteTokens:
          typeof cacheWriteTokens === 'number' ? cacheWriteTokens : undefined,
        reasoningTokens:
          typeof reasoningTokens === 'number' ? reasoningTokens : undefined,
        provider: providerName(provider),
      };
    };

    // OpenRouter names the provider it routed to on the chunk itself; on the
    // Responses and Anthropic shapes it may ride inside the wrapped object.
    if (c.usage) return fromUsage(c.usage, c.model, c.id, c.provider);
    if (c.response?.usage)
      return fromUsage(
        c.response.usage,
        c.response.model,
        c.response.id,
        c.response.provider ?? c.provider,
      );
    if (c.message?.usage) {
      // Anthropic message_start: model + id only, no final numbers.
      return {
        model: c.message.model,
        totalCost: 0,
        inputTokens: 0,
        outputTokens: 0,
        generationId: c.message.id,
        provider: providerName(c.message.provider ?? c.provider),
      };
    }
    return null;
  } catch {
    return null;
  }
}

export class CostExtractor {
  constructor({ isFreeModel = false } = {}) {
    this.isFreeModel = isFreeModel;
    this.buffer = '';
    this.result = {
      model: undefined,
      totalCost: 0,
      inputTokens: 0,
      outputTokens: 0,
      generationId: undefined,
      cacheReadTokens: undefined,
      cacheWriteTokens: undefined,
      reasoningTokens: undefined,
      provider: undefined,
      // undefined until a usage frame says which cost regime the row is in.
      isByok: undefined,
    };
    this.decoder = new TextDecoder();
  }

  feed(chunk) {
    this.buffer += this.decoder.decode(chunk, { stream: true });
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || '';
    for (const line of lines) this._line(line);
  }

  _line(line) {
    if (line.trim() === '') return;
    const parsed = parseCostingChunk(line);
    if (!parsed) {
      // Capture a generation id even before the usage frame arrives.
      if (!this.result.generationId && line.includes('"gen-')) {
        const m = line.match(/"id"\s*:\s*"(gen-[^"]+)"/);
        if (m) this.result.generationId = m[1];
      }
      // Likewise the served model: every streamed chunk names it, the usage
      // frame is only the last to. Without this an aborted stream settled with
      // no `served_model`, and an `openrouter/auto` abort could not be priced
      // at all (Auto has no rate of its own; the served model does). Bounded
      // to the slug shape so a content line can never be mistaken for one;
      // the usage frame's value still wins below when it arrives.
      if (!this.result.model && line.includes('"model"')) {
        const m = line.match(/"model"\s*:\s*"([a-zA-Z0-9._:/@~-]{1,96})"/);
        if (m) this.result.model = m[1];
      }
      return;
    }
    const r = this.result;
    if (parsed.totalCost) r.totalCost = parsed.totalCost;
    if (parsed.inputTokens) r.inputTokens = parsed.inputTokens;
    if (parsed.outputTokens) r.outputTokens = parsed.outputTokens;
    if (parsed.model) r.model = parsed.model;
    if (!r.generationId && parsed.generationId?.startsWith('gen-')) {
      r.generationId = parsed.generationId;
    }
    if (parsed.cacheReadTokens !== undefined)
      r.cacheReadTokens = parsed.cacheReadTokens;
    if (parsed.cacheWriteTokens !== undefined)
      r.cacheWriteTokens = parsed.cacheWriteTokens;
    if (parsed.reasoningTokens !== undefined)
      r.reasoningTokens = parsed.reasoningTokens;
    if (parsed.provider !== undefined) r.provider = parsed.provider;
    if (parsed.isByok !== undefined) r.isByok = parsed.isByok;
    if (this.isFreeModel) r.totalCost = 0;
  }

  finish() {
    if (this.buffer.trim() !== '') this._line(this.buffer);
    this.buffer = '';
    return this.result;
  }
}
