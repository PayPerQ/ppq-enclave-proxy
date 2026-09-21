/**
 * The thin path check, and the transparent proxy for everything the enclave
 * does not serve itself.
 *
 * WHY THIS EXISTS
 * ---------------
 * api.ppq.ai is moving onto the enclave so that chat completions become
 * private without anyone changing a URL. TLS binds to a hostname, not a path,
 * so once the enclave holds the api.ppq.ai certificate EVERY request for that
 * name lands here — balance, keys, media, webhooks, the transcription
 * WebSocket — and the path is the first thing on the wire that says which is
 * which. Nothing in front of the enclave can see it: the load balancer forwards
 * TCP bytes and the host's nginx reads only the ClientHello. The decision has
 * to be made here, after our own TLS termination, and this module is that
 * decision plus the byte pump it implies.
 *
 * WHAT IT IS, AND IS NOT
 * ----------------------
 * A compatibility shim. The routes it forwards are served by horse-power
 * exactly as they are today; they transit the enclave and no privacy claim is
 * made for them. The claim stays "chat completions on api.ppq.ai are private".
 *
 * PER REQUEST, NEVER PER CONNECTION
 * ---------------------------------
 * OpenAI SDKs reuse keep-alive connections. A byte pump that pinned a whole
 * connection to horse-power after seeing `/v1/models` would send the next
 * request on it — a chat call — to horse-power in the clear. The check runs on
 * every request the HTTP server hands us, so a connection can alternate freely.
 *
 * TRANSPARENT
 * -----------
 * Bodies are piped in both directions and never parsed or buffered: a 100 MB
 * image edit does not sit in enclave memory, a Stripe webhook body reaches
 * horse-power byte-identical for its signature check, and an SSE stream on
 * /v1/messages stays a stream. Headers pass verbatim except hop-by-hop ones and
 * any client-supplied IP header (the enclave is the only trusted source of the
 * client address; see `enclaveClientIpMac`). horse-power's response headers,
 * including CORS, come back verbatim, so it answers its own preflights.
 *
 * FAILURE SHAPE
 * -------------
 * horse-power unreachable is a 502 with a fixed, content-free message and an
 * `ERROR_CODES.PASSTHROUGH_UNREACHABLE` report. Never horse-power's own text.
 *
 * Injectable (`requestImpl`, `now`) so the whole thing is testable over plain
 * HTTP against an in-process fake horse-power.
 */
import https from 'node:https';
import { createHmac } from 'node:crypto';

/**
 * What the enclave serves itself: path → methods. Anything else, any method,
 * goes to horse-power. OPTIONS on these paths stays here too, so the CORS
 * answer browsers get for the chat endpoints is unchanged.
 */
export const ENCLAVE_ROUTES = Object.freeze({
  '/chat/completions': ['POST'],
  '/v1/chat/completions': ['POST'],
  // Structured-decision models (decisions.mjs): private for the same reason
  // chat is. `/v1/systemone` is the path the official TypeSafe SDK posts to.
  '/decisions': ['POST'],
  '/v1/decisions': ['POST'],
  '/v1/systemone': ['POST'],
  '/health': ['GET'],
  '/attestation': ['GET'],
  '/acme/csr': ['POST'],
  '/acme/install': ['POST'],
});

/** Paths the proxy rewrites before forwarding. */
const REWRITES = Object.freeze({
  // The enclave's own /health is what the load balancer polls; this is for a
  // monitor that wants horse-power's answer through the same hostname.
  '/hp/health': '/health',
});

export function pathOf(url) {
  const u = url || '';
  const i = u.indexOf('?');
  return i === -1 ? u : u.slice(0, i);
}

export function isEnclaveRoute(method, url) {
  const methods = ENCLAVE_ROUTES[pathOf(url)];
  if (!methods) return false;
  return method === 'OPTIONS' || methods.includes(method);
}

export function rewritePath(url) {
  const u = url || '/';
  const p = pathOf(u);
  const to = REWRITES[p];
  return to ? to + u.slice(p.length) : u;
}

/**
 * MAC over the client address horse-power should trust, keyed with the settle
 * secret. Mirrored byte-for-byte in horse-power utils/clientIp.ts
 * (`enclaveClientIpMac`); hp accepts the current or the previous minute.
 * Azure App Service rewrites X-Forwarded-For, so the address has to travel in
 * a header Azure leaves alone, and it has to be one a client cannot forge —
 * the proxy strips every inbound `x-ppq-client-ip*` before adding its own.
 */
export function enclaveClientIpMac(ip, unixMinute, secret) {
  return createHmac('sha256', secret).update(`${ip}|${unixMinute}`).digest('hex');
}

// RFC 7230 §6.1 hop-by-hop headers, plus the two de-facto ones. `trailer` is
// deliberately NOT here (RFC 7230 dropped it from the list): horse-power emits
// usage trailers on some routes and the client must be told to expect them.
/** Idle keep-alive sockets to horse-power live this long (see createPassthrough). */
export const FREE_SOCKET_TIMEOUT_MS = 30_000;

/** Bodiless methods a stale-socket failure may retry once (RFC 9110 §9.2.2). */
const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Why the hop to horse-power failed, as a closed-vocabulary token the report
 * can carry (errorReport.mjs). The enclave has no readable console in
 * production (--debug-mode zeroes the PCRs), so `e.message` in log() is
 * invisible; this is the only way the reason leaves the enclave. Node's
 * errno codes are already tokens; the two message-only cases get their own.
 */
export function failureReason(e) {
  const code = typeof e?.code === 'string' ? e.code : '';
  if (/^[A-Z][A-Z0-9_]{1,40}$/.test(code)) return code;
  const msg = typeof e?.message === 'string' ? e.message : '';
  if (msg === 'connect timeout') return 'CONNECT_TIMEOUT';
  if (msg === 'socket hang up') return 'SOCKET_HANG_UP';
  return 'OTHER';
}

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'transfer-encoding',
  'upgrade',
  'proxy-connection',
]);

// Anything a client could use to claim an address. horse-power's IP cascade
// reads several of these; behind the enclave the only trustworthy source is
// the MAC'd pair this module adds.
const CLIENT_IP_HEADERS = new Set([
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'x-client-ip',
  'cf-connecting-ip',
  'true-client-ip',
  'forwarded',
]);

/**
 * Headers to send upstream: everything inbound minus hop-by-hop, minus
 * connection-named, minus IP claims, minus `host` (replaced), plus the MAC'd
 * client address when the enclave knows it. `keepUpgrade` retains
 * `connection`/`upgrade` for a WebSocket handshake, where they are the point.
 */
export function outboundHeaders(inbound, { host, clientIp, mac, keepUpgrade = false } = {}) {
  const out = {};
  const named = connectionNominated(inbound);
  for (const [k, v] of Object.entries(inbound)) {
    const key = k.toLowerCase();
    if (v === undefined) continue;
    if (key === 'host') continue;
    if (CLIENT_IP_HEADERS.has(key)) continue;
    if (key.startsWith('x-ppq-client-ip')) continue;
    if (HOP_BY_HOP.has(key)) {
      if (!(keepUpgrade && (key === 'connection' || key === 'upgrade'))) continue;
    } else if (named.includes(key)) {
      continue;
    }
    out[key] = v;
  }
  out.host = host;
  if (clientIp && mac) {
    out['x-ppq-client-ip'] = clientIp;
    out['x-ppq-client-ip-mac'] = mac;
  }
  return out;
}

/** Field names a `Connection` header nominates as hop-by-hop, lowercased. */
function connectionNominated(headers) {
  return String(headers.connection || '')
    .toLowerCase()
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Response headers back to the client: verbatim minus the hop-by-hop set and
 * minus any field the upstream's own `Connection` header nominated. `trailer`
 * stays: the ordinary path relays the trailers it announces.
 */
export function responseHeaders(upstream) {
  const out = {};
  const named = connectionNominated(upstream);
  for (const [k, v] of Object.entries(upstream)) {
    const key = k.toLowerCase();
    if (v === undefined) continue;
    if (HOP_BY_HOP.has(key)) continue;
    if (named.includes(key)) continue;
    out[key] = v;
  }
  return out;
}

/**
 * Raw header lines, case preserved, minus `skip` (lowercased names). A 101 is
 * relayed whole; a declined upgrade drops the transfer framing, because
 * Node's client has already decoded the body we then pipe.
 */
function rawHeaderBlock(rawHeaders, skip = new Set()) {
  let s = '';
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    if (skip.has(String(rawHeaders[i]).toLowerCase())) continue;
    s += `${rawHeaders[i]}: ${rawHeaders[i + 1]}\r\n`;
  }
  return s;
}
/**
 * What a declined upgrade must not repeat: the hop-by-hop set, whatever the
 * upstream's Connection header nominated, and `trailer` — this path pipes the
 * decoded body and relays no trailers, so it must not advertise any.
 */
function declinedUpgradeSkip(headers) {
  return new Set([...HOP_BY_HOP, 'trailer', ...connectionNominated(headers)]);
}

/**
 * What a relayed 101 must not repeat: the same, minus `connection` and
 * `upgrade`, which ARE the handshake.
 */
function acceptedUpgradeSkip(headers) {
  const skip = new Set([...HOP_BY_HOP, ...connectionNominated(headers)]);
  skip.delete('connection');
  skip.delete('upgrade');
  return skip;
}

const UNAVAILABLE = JSON.stringify({
  error: { message: 'upstream unavailable', type: 'server_error', code: 502 },
});
const OVERLOADED = JSON.stringify({
  error: { message: 'too many concurrent requests', type: 'server_error', code: 503 },
});

/** A whole HTTP/1.1 response on a raw socket, close-framed. */
function rawResponse(status, reason, body) {
  return `HTTP/1.1 ${status} ${reason}\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`;
}

/**
 * @param {object} o
 * @param {string} o.host        Host/SNI horse-power is addressed by (api.ppq.ai)
 * @param {number} o.port        loopback port of the vsock tunnel to horse-power
 * @param {string} [o.servername]
 * @param {string} [o.secret]    settle secret, keys the client-IP MAC
 * @param {(m:string)=>void} [o.log]
 * @param {(code:string, fields?:object)=>void} [o.onEvent]  content-free reporter
 * @param {number} [o.maxInflight]
 * @param {number} [o.connectTimeoutMs]  until horse-power's status line; streams then run untimed
 * @param {number} [o.freeSocketTimeoutMs]  idle keep-alive sockets are dropped after this
 * @param {Function} [o.requestImpl]  https.request by default; http.request in tests
 * @param {()=>number} [o.now]
 */
export function createPassthrough({
  host,
  port,
  servername = host,
  secret = '',
  log = () => {},
  onEvent = () => {},
  maxInflight = 512,
  connectTimeoutMs = 60_000,
  freeSocketTimeoutMs = FREE_SOCKET_TIMEOUT_MS,
  requestImpl = https.request,
  now = Date.now,
}) {
  if (!host || !port) throw new Error('passthrough needs host and port');
  // Keep-alive to horse-power: one TLS handshake per pooled socket instead of
  // one per request. Only for the real transport; a test's http.request gets
  // Node's default agent.
  //
  // `timeout` is the idle bound on POOLED sockets: Node's agent re-arms it
  // when a socket is returned to the free list and destroys the socket when
  // it fires (verified on Node 22). Without it a socket sat in the pool until
  // horse-power's front end closed it from the other side, and the next
  // request written onto that half-dead socket failed with ECONNRESET before
  // any status line — the dominant shape of `passthrough_unreachable` at
  // 100% weight (2026-09-21, ~1% of pass-through calls). The per-request
  // connect timeout below overrides this while a request is in flight.
  const agent =
    requestImpl === https.request
      ? new https.Agent({ keepAlive: true, maxSockets: maxInflight, timeout: freeSocketTimeoutMs })
      : undefined;
  let inflight = 0;

  function ipHeaders(req) {
    // Set by the PROXY-protocol listener on the api port (proxyListener.mjs);
    // absent on the 443 path, which means no header, and horse-power falls
    // back to its own cascade.
    const ip = req.socket?.clientIp;
    if (!ip || !secret) return {};
    return { clientIp: ip, mac: enclaveClientIpMac(ip, Math.floor(now() / 60_000), secret) };
  }

  function sendJson(res, status, body) {
    if (res.headersSent) return res.destroy();
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
    res.end(body);
  }

  function handle(req, res) {
    if (inflight >= maxInflight) {
      log('passthrough: overloaded');
      return sendJson(res, 503, OVERLOADED);
    }
    inflight += 1;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      inflight -= 1;
    };
    let responded = false;
    let clientGone = false;
    let attempts = 0;
    let up = null;
    const idempotent = IDEMPOTENT_METHODS.has(req.method);
    const outbound = {
      host: '127.0.0.1',
      port,
      servername,
      method: req.method,
      path: rewritePath(req.url),
      headers: outboundHeaders(req.headers, { host, ...ipHeaders(req) }),
    };
    const attempt = () => {
      attempts += 1;
      // A retry goes on a fresh connection, never on another pooled socket
      // that may be just as stale.
      up = requestImpl({ ...outbound, agent: attempts === 1 ? agent : false });
      // Bounded until horse-power answers with a status line; after that the
      // response may legitimately stay open for as long as a stream lasts.
      up.setTimeout(connectTimeoutMs, () => {
        if (!responded) up.destroy(new Error('connect timeout'));
      });
      up.on('response', (upRes) => {
        responded = true;
        up.setTimeout(0);
        res.writeHead(upRes.statusCode, upRes.statusMessage, responseHeaders(upRes.headers));
        // end:false so trailers can be appended before the final chunk.
        upRes.pipe(res, { end: false });
        upRes.on('end', () => {
          const t = upRes.trailers;
          if (t && Object.keys(t).length) res.addTrailers(t);
          res.end();
          finish();
        });
        upRes.on('error', () => {
          res.destroy();
          finish();
        });
      });
      up.on('error', (e) => {
        log(`passthrough error: ${e.message}`);
        if (responded) {
          res.destroy();
          return finish();
        }
        const reused = up.reusedSocket === true;
        // A pooled socket that horse-power had already closed fails before a
        // single byte of the request was processed; a bodiless idempotent
        // request is safe to send again, once, on a fresh connection.
        if (reused && idempotent && attempts === 1 && !clientGone) {
          log('passthrough: retrying once on a fresh socket');
          return attempt();
        }
        sendJson(res, 502, UNAVAILABLE);
        onEvent('passthrough_unreachable', { reason: failureReason(e), reused_socket: reused, attempts });
        finish();
      });
      // The client's body was piped on the first attempt; a retry is only ever
      // for a bodiless method, so the request is simply ended.
      if (attempts === 1) req.pipe(up);
      else up.end();
    };
    // The client went away: stop horse-power working for nobody.
    res.on('close', () => {
      if (!res.writableFinished) {
        clientGone = true;
        up?.destroy();
        finish();
      }
    });
    req.on('error', () => up?.destroy());
    attempt();
  }

  /**
   * WebSocket (or any Upgrade): forward the handshake, then splice the two
   * sockets. `head` is whatever the client sent optimistically after its
   * handshake; it belongs on the upstream socket AFTER the 101, not in the
   * request body.
   */
  function upgrade(req, socket, head) {
    // Same cap as ordinary requests: an upgrade holds one upstream socket for
    // as long as the conversation lasts, which is exactly what the cap bounds.
    if (inflight >= maxInflight) {
      log('passthrough: overloaded (upgrade)');
      if (socket.writable) socket.end(rawResponse(503, 'Service Unavailable', OVERLOADED));
      else socket.destroy();
      return;
    }
    inflight += 1;
    let done = false;
    let clientGone = false;
    // Set once horse-power has answered (101 or a decline): after that an
    // upstream error can only mean a broken body, never something a fresh
    // 502 could describe — and writing one would corrupt the response in flight.
    let responded = false;
    const finish = () => {
      if (done) return;
      done = true;
      inflight -= 1;
    };
    const up = requestImpl({
      host: '127.0.0.1',
      port,
      servername,
      method: req.method,
      path: rewritePath(req.url),
      headers: outboundHeaders(req.headers, { host, keepUpgrade: true, ...ipHeaders(req) }),
      agent: false,
    });
    up.setTimeout(connectTimeoutMs, () => up.destroy(new Error('connect timeout')));
    up.on('upgrade', (upRes, upSocket, upHead) => {
      responded = true;
      up.setTimeout(0);
      socket.write(
        `HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n${rawHeaderBlock(upRes.rawHeaders, acceptedUpgradeSkip(upRes.headers))}\r\n`,
      );
      if (upHead && upHead.length) socket.write(upHead);
      if (head && head.length) upSocket.write(head);
      upSocket.pipe(socket);
      socket.pipe(upSocket);
      // The HTTP server hands over sockets with half-open allowed, so a FIN
      // from one side raises 'end' but never 'close'. A WebSocket conversation
      // is over when either side says so: tear both down on 'end' as well.
      const drop = () => {
        socket.destroy();
        upSocket.destroy();
        finish();
      };
      for (const s of [socket, upSocket]) {
        s.on('error', drop);
        s.on('end', drop);
        s.on('close', drop);
      }
    });
    // horse-power declined the upgrade: relay its answer with close framing.
    // Node has already decoded any chunked body, so the transfer-encoding
    // header must not be repeated or the client parses plain bytes as chunks.
    up.on('response', (upRes) => {
      responded = true;
      // The connect timeout is an idle timer on the socket; a slow declined
      // body must not trip it after the head has been relayed.
      up.setTimeout(0);
      socket.write(
        `HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n${rawHeaderBlock(upRes.rawHeaders, declinedUpgradeSkip(upRes.headers))}connection: close\r\n\r\n`,
      );
      upRes.pipe(socket);
      upRes.on('end', finish);
      upRes.on('error', () => {
        socket.destroy();
        finish();
      });
    });
    up.on('error', (e) => {
      // A client that left before the handshake finished is not an upstream
      // failure: no report, nothing to answer.
      if (clientGone) return finish();
      // The answer was already on the wire: only the body broke.
      if (responded) {
        socket.destroy();
        return finish();
      }
      log(`passthrough upgrade error: ${e.message}`);
      onEvent('passthrough_unreachable', { reason: failureReason(e), reused_socket: up.reusedSocket === true, attempts: 1 });
      // end(), not write()+destroy(): destroy discards what has not flushed,
      // and this answer is the only thing the client will ever get.
      if (socket.writable) socket.end(rawResponse(502, 'Bad Gateway', UNAVAILABLE));
      else socket.destroy();
      finish();
    });
    // The client can close cleanly (no 'error') before horse-power has
    // answered; without this the upstream request would run to its connect
    // timeout and hold the inflight slot the whole time.
    const cancel = () => {
      if (done) return;
      clientGone = true;
      up.destroy();
      // The server-side socket is half-open-capable and stays open after the
      // client's FIN unless we close it ourselves.
      socket.destroy();
      finish();
    };
    // 'end' as well: the HTTP server hands over half-open-capable sockets, so
    // a client FIN before the handshake raises 'end' and never 'close'.
    socket.on('error', cancel);
    socket.on('end', cancel);
    socket.on('close', cancel);
    up.end();
  }

  return { handle, upgrade, inflight: () => inflight };
}
