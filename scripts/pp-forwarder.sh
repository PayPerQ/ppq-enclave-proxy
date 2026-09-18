#!/usr/bin/env bash
# The host-side forwarder for the api path: a socat on the unix socket nginx's
# arm proxies to (scripts/nginx-pp-arm.conf), feeding the enclave's PROXY
# protocol listener on vsock:8445. run-host.sh runs this when
# INBOUND_PP_SOCKET is set; it is also runnable on its own, so a box whose
# enclave is already up can gain the arm without a restart (which the
# one-shot init channel would otherwise force):
#
#   INBOUND_PP_SOCKET=/run/ppq/pp.sock ENCLAVE_CID=16 bash scripts/pp-forwarder.sh
#
# Idempotent: a previous forwarder on the same socket is replaced.
#
# A UNIX SOCKET, NOT A TCP PORT, ON PURPOSE. A PROXY header is an
# unauthenticated claim about who the client is: whoever can write to this
# listener can make the enclave -- and horse-power, through the MAC'd
# x-ppq-client-ip pair -- believe any address. A loopback TCP port is
# writable by every local user; a socket file with mode 660 root:nginx is
# writable only by root and by nginx's workers (which run as `nginx`), i.e.
# by the one process that writes the address it actually accepted the
# connection from. The directory is 750 root:nginx so nothing else can even
# reach the socket. Nothing here is network-reachable, so nothing to keep out
# of a security group.
#
# What this does and does not establish: the address is asserted by this
# host, exactly like the load balancer's own view of the peer. Its integrity
# rests on the host; it is not part of the enclave's privacy claim (the
# threat model already says the parent sees IPs). See README, "PROXY
# protocol on the api port".
set -euo pipefail
: "${INBOUND_PP_SOCKET:?set INBOUND_PP_SOCKET to /run/ppq/<name>}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
if ! getent group nginx >/dev/null; then
  echo ">> FATAL: INBOUND_PP_SOCKET set but no 'nginx' group: install nginx first (the socket is group-owned by it)" >&2
  exit 1
fi
# The socket lives in a DEDICATED directory, /run/ppq, and nowhere else.
# This script sets that directory's owner and mode, and a path like
# /run/pp.sock would have it set them on /run itself and break every other
# service on the box. The directory is created only if missing; an
# existing one is verified and never modified.
# Exactly one safe basename under /run/ppq: letters, digits, dot, underscore,
# dash, no leading dot, no "..". The value is interpolated into a `sh -c`
# command line AND into socat's comma-delimited option list below, so
# whitespace, commas, quotes or `$(...)` in it would be re-parsed as shell or
# socat syntax. Refuse anything outside that set (CodeRabbit on #179).
if ! printf '%s' "${INBOUND_PP_SOCKET}" | grep -Eq '^/run/ppq/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$'; then
  echo ">> FATAL: INBOUND_PP_SOCKET must be /run/ppq/<name> with <name> in [A-Za-z0-9_.-] (no leading dot, no '..'), got ${INBOUND_PP_SOCKET}" >&2
  exit 1
fi
if ! printf '%s' "${ENCLAVE_CID}" | grep -Eq '^[0-9]+$'; then
  echo ">> FATAL: ENCLAVE_CID must be a number, got ${ENCLAVE_CID}" >&2
  exit 1
fi
PP_DIR=/run/ppq
if [ ! -e "${PP_DIR}" ]; then
  install -d -m 750 -o root -g nginx "${PP_DIR}"
else
  if [ ! -d "${PP_DIR}" ]; then
    echo ">> FATAL: ${PP_DIR} exists and is not a directory" >&2
    exit 1
  fi
  got="$(stat -c '%U:%G %a' "${PP_DIR}")"
  if [ "${got}" != "root:nginx 750" ]; then
    echo ">> FATAL: ${PP_DIR} is ${got}, expected root:nginx 750 -- fix it by hand (this script never changes an existing directory)" >&2
    exit 1
  fi
fi
echo ">> starting PROXY-protocol inbound forwarder (unix:${INBOUND_PP_SOCKET} -> enclave vsock:8445)"
pkill -f "UNIX-LISTEN:${INBOUND_PP_SOCKET}," 2>/dev/null || true
# unlink-early: a stale socket file from the previous run would otherwise
# make the bind fail. mode/user/group apply to the socket file socat creates.
setsid sh -c "exec socat UNIX-LISTEN:${INBOUND_PP_SOCKET},fork,unlink-early,backlog=1024,mode=660,user=root,group=nginx VSOCK-CONNECT:${ENCLAVE_CID}:8445" </dev/null >/dev/null 2>&1 &
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S "${INBOUND_PP_SOCKET}" ] && break; sleep 0.3; done
[ -S "${INBOUND_PP_SOCKET}" ] || { echo ">> FATAL: ${INBOUND_PP_SOCKET} did not appear" >&2; exit 1; }
ls -l "${INBOUND_PP_SOCKET}"
