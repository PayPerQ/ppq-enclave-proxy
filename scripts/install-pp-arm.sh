#!/usr/bin/env bash
# Install, refresh or remove the nginx api arm on THIS box (plan W2.2): the
# :8445 stream server that writes a PROXY v1 header into /run/ppq/pp.sock,
# where scripts/pp-forwarder.sh feeds the enclave's vsock:8445 listener.
# Idempotent, run as root, from a checkout of this repo:
#
#   bash scripts/install-pp-arm.sh              # install or refresh, nginx -t, reload
#   bash scripts/install-pp-arm.sh --uninstall  # remove the arm, nginx -t, reload
#
# Two layouts, detected from /etc/nginx/nginx.conf, one managed file each:
#   production  nginx.conf already has a top-level `stream {` (the SNI split,
#               scripts/nginx-sni-split.conf). `stream` may appear only once,
#               so the arm's server block (scripts/nginx-pp-arm-server.conf)
#               goes to /etc/nginx/stream.d/ppq-pp-arm.conf and ONE line,
#               `include /etc/nginx/stream.d/*.conf;`, is added inside that
#               block, only if absent.
#   dev         no stream block. scripts/nginx-pp-arm.conf, which carries its
#               own stream {}, is installed as /etc/nginx/ppq-pp-arm.conf and
#               included at top level (DEV-ENCLAVE.md, "Testing PROXY protocol
#               on the dev box").
# Nothing else in nginx.conf is touched; a timestamped backup is kept beside
# it. The socket does not have to exist for `nginx -t` to pass: nginx connects
# to a unix upstream per connection, so a box where pp-forwarder.sh has not
# started yet simply fails the api NLB's health check until it has.
#
# The stream module is a separate package on Amazon Linux 2023 and must match
# nginx's version exactly (scripts/nginx-sni-split.conf tells that story);
# dnf resolves that when both are installed together.
#
# Rehearsal knobs (never needed on a real box): NGINX_ROOT relocates every
# path under another directory, and RELOAD=0 runs `nginx -t` against that
# copy without touching the service. Used to prove the production-layout edit
# on a copy of the real nginx.conf before applying it.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${NGINX_ROOT:-/etc/nginx}"
CONF=$ROOT/nginx.conf
STREAM_D=$ROOT/stream.d
ARM_FILE=$STREAM_D/ppq-pp-arm.conf
DEV_FILE=$ROOT/ppq-pp-arm.conf
MARK="include $STREAM_D/*.conf;"
# The include line this script inserts carries a marker comment: --uninstall
# removes only a line it owns, never a pre-existing include of the same
# directory that other stream fragments may rely on.
OWNED_MARK="$MARK # ppq-pp-arm"
DEV_MARK="include $DEV_FILE;"
[ "$(id -u)" = 0 ] || { echo "install-pp-arm: run as root" >&2; exit 1; }

reload() {
  if [ "${RELOAD:-1}" = 0 ]; then nginx -t -c "$CONF"; return; fi
  nginx -t
  systemctl enable --now nginx >/dev/null 2>&1 || true
  systemctl reload nginx
}
# A literal string as a sed address: escape everything sed's basic regex
# treats specially (the paths carry `/`, `.` and `*`).
lit() { printf '%s' "$1" | sed -e 's/[][\/.*^$]/\\&/g'; }

if [ "${1:-}" = "--uninstall" ]; then
  [ -f "$CONF" ] && cp -p "$CONF" "$CONF.bak-pp-arm-$(date +%s)"
  rm -f "$ARM_FILE" "$DEV_FILE"
  # Both include forms, whichever layout put them there. `#` delimits the
  # addresses so the slashes in the paths stay literal.
  sed -i -e "/$(lit "$OWNED_MARK")/d" -e "/$(lit "$DEV_MARK")/d" "$CONF"
  reload
  echo "install-pp-arm: removed; :8445 no longer listens"
  exit 0
fi

if ! command -v nginx >/dev/null 2>&1 || [ ! -e /usr/share/nginx/modules/mod-stream.conf ]; then
  dnf install -y nginx nginx-mod-stream
fi
[ -f "$CONF" ] || { echo "install-pp-arm: no $CONF" >&2; exit 1; }
cp -p "$CONF" "$CONF.bak-pp-arm-$(date +%s)"

if grep -qF "$DEV_MARK" "$CONF"; then
  # dev layout already in place: refresh the managed file only.
  install -m 644 "$HERE/nginx-pp-arm.conf" "$DEV_FILE"
  layout=dev
elif grep -Eq '^stream[[:space:]]*\{' "$CONF"; then
  install -d -m 755 "$STREAM_D"
  install -m 644 "$HERE/nginx-pp-arm-server.conf" "$ARM_FILE"
  if ! grep -qF "$MARK" "$CONF"; then
    # First `stream {` line only; the include goes right after it.
    sed -i -E "0,/^stream[[:space:]]*\{/s##&\n    $(lit "$OWNED_MARK")#" "$CONF"
  fi
  layout=production
else
  install -m 644 "$HERE/nginx-pp-arm.conf" "$DEV_FILE"
  echo "$DEV_MARK" >> "$CONF"
  layout=dev
fi
reload
echo "install-pp-arm: $layout layout installed; listening:"
ss -ltn 2>/dev/null | grep -E '[:.]8445[[:space:]]' || echo "  (nothing on :8445 -- check journalctl -u nginx)"
