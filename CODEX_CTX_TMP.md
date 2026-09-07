## Current live state (verified today)

- Production enclave: PCR0 3838dc9b (v0.10.1), attests OK, serves chat.
- `enclave.ppq.ai` :443 — nginx terminates TLS with a Let's Encrypt cert
  (expires 2026-10-13, renewed by hand, no automation). nginx proxies to
  127.0.0.1:8443 -> socat -> vsock -> enclave.
- `enclave-direct.ppq.ai` :443 — SNI split routes it as RAW TCP to the enclave,
  which terminates its own TLS. It now holds a real Let's Encrypt STAGING cert
  it obtained itself via TLS-ALPN-01, key generated in-enclave.
- Sealed store works: a restart reuses the cert (identical serial) and places
  no order. /health reports acme_store:"ok".
- Browser path uses EHBP (HPKE-sealed bodies). Host-blindness on the public
  path comes from the EHBP seal, NOT from TLS, because nginx terminates.
- Clients pin PCR0 via /api/enclave-pin, which reads published-pcr.json from
  the public repo. Accept-list carries {running, incoming} during a rollover.
- A cutover drains attestation coverage ~90% -> 17%, ~45 min to recover.
- There is NO rollback EIF; recovery is a ~25 min rebuild.

# ── SNI split on :443 — phase 1 of #52 ───────────────────────────────────────
# Added 2026-09-03. Routes by SNI WITHOUT terminating, so the enclave can answer
# a TLS-ALPN-01 challenge on 443 (the only port a CA validates on) while
# enclave.ppq.ai keeps being terminated here exactly as before.
#   enclave-direct.ppq.ai -> raw TCP to the enclave (it terminates its own TLS)
#   everything else       -> 127.0.0.1:8444, the http server in conf.d/enclave.conf
#
# NO PROXY PROTOCOL. `proxy_protocol` takes a literal on/off, not a variable, so
# it cannot be enabled per-SNI -- and it must NOT reach enclave-direct, whose
# plain TLS server would read a PROXY header as ClientHello garbage. Enabling it
# for both is therefore not an option. The client address is not lost: this
# block logs the real $remote_addr below, and nothing downstream consumes it
# (server.mjs reads no x-forwarded-for).
#
# Rollback: delete this block, restore `listen 443 ssl;` in conf.d/enclave.conf,
# `nginx -t && systemctl reload nginx`.
stream {
    map $ssl_preread_server_name $enclave_upstream {
        enclave-direct.ppq.ai  127.0.0.1:8443;
        default                127.0.0.1:8444;
    }
    log_format sni '$remote_addr [$time_local] sni=$ssl_preread_server_name -> $upstream_addr $status $bytes_sent';
    access_log /var/log/nginx/sni-split.log sni;

    server {
        listen 443;
        ssl_preread on;
        proxy_pass $enclave_upstream;
        proxy_timeout 300s;
        proxy_connect_timeout 10s;
    }
}
--- proposed plan ---
Step 1: Point ACME at Let's Encrypt PRODUCTION for the SHADOW hostname only
        (enclave-direct.ppq.ai). nginx keeps carrying enclave.ppq.ai untouched.
        Verify a browser-trusted cert on the shadow name.
Step 2: Add enclave.ppq.ai to the enclave's ACME domains and move the SNI split
        so that name also goes raw TCP to the enclave.
Step 3: Retire nginx TLS termination, re-pin clients, publish the trust story.
