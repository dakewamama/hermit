# Sourced by the demo scripts from their work directory.
#
# Starts a local hermit-relay and hermit-witness, unless RELAY / WITNESS
# already point at running ones (e.g. a deployment). A remote relay's admin
# token must then be given as ADMIN_TOKEN.

PORT=${PORT:-8787}
RELAY_BIN=${RELAY_BIN:-$ROOT/target/debug/hermit-relay}
WITNESS_BIN=${WITNESS_BIN:-$ROOT/target/debug/hermit-witness}
SERVER_PIDS=()

stop_servers() {
  if ((${#SERVER_PIDS[@]})); then kill "${SERVER_PIDS[@]}" 2>/dev/null; fi
  return 0
}
# Armed before anything starts, so no failure below can leak a server.
# Callers may replace it, but must keep calling stop_servers.
trap stop_servers EXIT

if [[ -z ${RELAY:-} ]]; then
  ADMIN_TOKEN=${ADMIN_TOKEN:-$(head -c 16 /dev/urandom | xxd -p)}
  HERMIT_ADMIN_TOKEN=$ADMIN_TOKEN "$RELAY_BIN" --listen "127.0.0.1:$PORT" --data relay-data \
    >relay.log 2>&1 &
  SERVER_PIDS+=($!)
  RELAY=http://127.0.0.1:$PORT
fi
if [[ -z ${WITNESS:-} ]]; then
  "$WITNESS_BIN" --listen "127.0.0.1:$((PORT + 1))" --data witness-data >witness.log 2>&1 &
  SERVER_PIDS+=($!)
  WITNESS=http://127.0.0.1:$((PORT + 1))
fi
: "${ADMIN_TOKEN:?set ADMIN_TOKEN to the admin token of the remote relay}"

sleep 1
# A server that failed to bind exits at once; never run against a stale one.
for pid in "${SERVER_PIDS[@]}"; do
  kill -0 "$pid" 2>/dev/null || {
    echo "FAIL: server exited at startup:"
    cat relay.log witness.log 2>/dev/null
    exit 1
  }
done

relay_mode() {
  curl -sf -X POST "$RELAY/admin/mode" -H "Authorization: Bearer $ADMIN_TOKEN" -d "$1" >/dev/null \
    && echo "(relay is now: $1)"
}
