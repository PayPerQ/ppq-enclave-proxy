/**
 * Streaming usage/cost extractor.
 *
 * A dependency-free port of horse-power's utils/streamParser.ts
 * (parseCostingChunk) plus the line-buffering the chat controller does around
 * it. Numbers are kept as JS numbers here (not BigNumber) — horse-power's
 * /enclave/settle re-wraps them in BigNumber and applies the billing margin, so
 * the enclave only needs to report the upstream figures it observed.
 */

const MIN_COST = { input: 0.0000003, output: 0.000001 };

function parseCostingChunk(line) {
  try {
    if (!line.includes('"usage"')) return null;
    let json = line.startsWith('data: ') ? line.slice(6).trim() : line.trim();
    if (json === '[DONE]' || json === '') return null;

    const c = JSON.parse(json);

    const fromUsage = (usage, model, id) => {
      const isByok = usage.is_byok === true;
      const inputTokens = Number(
        usage.prompt_tokens || usage.input_tokens || 0,
      );
      const outputTokens = Number(
        usage.completion_tokens || usage.output_tokens || 0,
      );
      let totalCost;
      if (model?.endsWith(':free') && (usage.cost === 0 || usage.cost == null)) {
        totalCost = inputTokens * MIN_COST.input + outputTokens * MIN_COST.output;
      } else if (isByok && usage.cost_details?.upstream_inference_cost) {
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
      return {
        model,
        totalCost,
        inputTokens,
        outputTokens,
        generationId: id,
        cacheReadTokens:
          typeof cacheReadTokens === 'number' ? cacheReadTokens : undefined,
        cacheWriteTokens:
          typeof cacheWriteTokens === 'number' ? cacheWriteTokens : undefined,
      };
    };

    if (c.usage) return fromUsage(c.usage, c.model, c.id);
    if (c.response?.usage)
      return fromUsage(c.response.usage, c.response.model, c.response.id);
    if (c.message?.usage) {
      // Anthropic message_start: model + id only, no final numbers.
      return {
        model: c.message.model,
        totalCost: 0,
        inputTokens: 0,
        outputTokens: 0,
        generationId: c.message.id,
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
    if (this.isFreeModel) r.totalCost = 0;
  }

  finish() {
    if (this.buffer.trim() !== '') this._line(this.buffer);
    this.buffer = '';
    return this.result;
  }
}
