/**
 * Web-search counts for the trace (#488): searches the upstream reports, and
 * distinct cited URLs and hosts. Reads chat-completions frames only (citations
 * as `annotations[].url_citation`, searches as
 * `usage.server_tool_use_details.web_search_requests`). URLs and hosts are hashed only to
 * de-duplicate and leave as counts.
 */

import { createHash } from 'node:crypto';

const MAX_PENDING_CHARS = 4 * 1024 * 1024;
const MAX_TRACKED = 1000;
const MAX_HOST_CHARS = 253;

const digest = (s) => createHash('sha256').update(s).digest('base64').slice(0, 16);

function hostOf(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return undefined;
  }
}

export class WebSearchStats {
  /** @param {{ onFirstCitation?: () => void, json?: boolean }} [o] `json`: one body, parsed at finish(). */
  constructor({ onFirstCitation, json = false } = {}) {
    this.onFirstCitation = onFirstCitation;
    this.json = json;
    this.urls = new Set();
    this.hosts = new Set();
    this.searches = undefined;
    this.pending = '';
    this.skipping = false;
    this.decoder = new TextDecoder();
  }

  /** @param {Uint8Array} chunk */
  feed(chunk) {
    const text = this.decoder.decode(chunk, { stream: true });
    if (this.json) {
      if (this.skipping) return;
      this.pending += text;
      if (this.pending.length > MAX_PENDING_CHARS) {
        this.pending = '';
        this.skipping = true;
      }
      return;
    }
    let start = 0;
    let nl;
    while ((nl = text.indexOf('\n', start)) !== -1) {
      const line = this.skipping ? '' : this.pending + text.slice(start, nl);
      this.pending = '';
      this.skipping = false;
      start = nl + 1;
      this.readLine(line);
    }
    if (this.skipping) return;
    this.pending += text.slice(start);
    if (this.pending.length > MAX_PENDING_CHARS) {
      this.pending = '';
      this.skipping = true;
    }
  }

  readLine(line) {
    if (!line.includes('url_citation') && !line.includes('web_search_requests')) return;
    let json = line.trim();
    if (json.startsWith('data:')) json = json.slice(5).trim();
    if (json[0] !== '{') return;
    let frame;
    try {
      frame = JSON.parse(json);
    } catch {
      return;
    }
    const n = frame?.usage?.server_tool_use_details?.web_search_requests;
    if (Number.isInteger(n) && n >= 0) this.searches = n;
    if (!Array.isArray(frame?.choices)) return;
    for (const choice of frame.choices) {
      this.readAnnotations(choice?.delta?.annotations);
      this.readAnnotations(choice?.message?.annotations);
    }
  }

  readAnnotations(list) {
    if (!Array.isArray(list)) return;
    for (const a of list) {
      if (a?.type !== 'url_citation') continue;
      const url = a.url_citation?.url ?? a.url;
      if (typeof url !== 'string') continue;
      if (this.urls.size === 0) this.onFirstCitation?.();
      if (this.urls.size < MAX_TRACKED) this.urls.add(digest(url));
      const host = hostOf(url);
      if (host && this.hosts.size < MAX_TRACKED) this.hosts.add(digest(host.slice(0, MAX_HOST_CHARS)));
    }
  }

  /** @returns {{ searches?: number, citations: number, domains: number }} */
  finish() {
    if (!this.skipping && this.pending) this.readLine(this.pending);
    this.pending = '';
    return { searches: this.searches, citations: this.urls.size, domains: this.hosts.size };
  }
}
