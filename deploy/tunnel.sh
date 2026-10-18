#!/usr/bin/env bash
# Run hermit-relay and hermit-witness on this machine and publish each one
# through a Cloudflare quick tunnel (no account needed). Quick tunnels have
# no uptime guarantee: rerun this when the URLs stop answering.
#
#   deploy/tunnel.sh [state-dir]        (default ~/.local/share/hermit)
#
# Writes <state-dir>/{relay,witness}.url and keeps the admin token in
# <state-dir>/admin.token (mode 600). Point the demo scripts at it with:
#
#   RELAY=$(cat .../relay.url) WITNESS=$(cat .../witness.url) \
#   ADMIN_TOKEN=$(cat .../admin.token) demo/e2e.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATE=${1:-$HOME/.local/share/hermit}
mkdir -p "$STATE/relay" "$STATE/witness" "$STATE/logs"

cargo build -q --release --manifest-path "$ROOT/Cargo.toml" -p hermit-relay -p hermit-witness
BIN=$ROOT/target/release

if [[ ! -s $STATE/admin.token ]]; then
  (umask 077 && head -c 24 /dev/urandom | xxd -p | tr -d '\n' >"$STATE/admin.token")
fi

# Restart cleanly: the witness key and all data live in $STATE and persist.
pkill -x hermit-relay || true
pkill -x hermit-witness || true
pkill -x cloudflared || true
sleep 1

HERMIT_ADMIN_TOKEN=$(cat "$STATE/admin.token") setsid nohup "$BIN/hermit-relay" \
  --listen 127.0.0.1:8787 --data "$STATE/relay" >"$STATE/logs/relay.log" 2>&1 </dev/null &
setsid nohup "$BIN/hermit-witness" \
  --listen 127.0.0.1:8788 --data "$STATE/witness" >"$STATE/logs/witness.log" 2>&1 </dev/null &

# HTTP/2 rather than the QUIC default: QUIC through WSL stalls on bodies of
# 64 KB and up, which is every wallet section.
tunnel() {
  local name=$1 port=$2 url=""
  for _ in 1 2 3; do
    setsid nohup cloudflared tunnel --no-autoupdate --protocol http2 --url "http://127.0.0.1:$port" \
      >"$STATE/logs/tunnel-$name.log" 2>&1 </dev/null &
    for _ in $(seq 30); do
      url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$STATE/logs/tunnel-$name.log" | head -1 || true)
      [[ -n $url ]] && break
      grep -q "failed to request" "$STATE/logs/tunnel-$name.log" && break
      sleep 2
    done
    if [[ -n $url ]]; then
      echo "$url" >"$STATE/$name.url"
      echo "$name: $url"
      return 0
    fi
    sleep 10
  done
  echo "could not open a tunnel for $name; see $STATE/logs/tunnel-$name.log" >&2
  return 1
}
tunnel relay 8787
tunnel witness 8788

# The tunnel needs a few seconds before it routes; wait until the witness
# answers through it.
for _ in $(seq 30); do
  key=$(curl -sf --max-time 5 "$(cat "$STATE/witness.url")/key" || true)
  [[ -n $key ]] && { echo "witness key: $key"; exit 0; }
  sleep 2
done
echo "tunnels opened but the witness does not answer yet" >&2
exit 1
