#!/usr/bin/env bash
# End-to-end run against a real Zcash testnet wallet: a fresh zcash-devtool
# wallet synced from a live lightwalletd, moved between devices through
# hermit capsules, and attacked.
#
#   DEVTOOL=/path/to/zcash-devtool demo/e2e.sh
#
# Needs network access to testnet.zec.rocks (or set SERVER). Runs its own
# relay and witness unless RELAY / WITNESS / ADMIN_TOKEN name deployed ones.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HERMIT=${HERMIT:-$ROOT/target/debug/hermit}
DEVTOOL=${DEVTOOL:?set DEVTOOL to a zcash-devtool binary}
SERVER=${SERVER:-https://testnet.zec.rocks:443}
WORK=$(mktemp -d)
cd "$WORK"
source "$ROOT/demo/servers.sh"
trap 'stop_servers; echo "workdir: $WORK"' EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
expect() { # expect <code> <cmd...>
  local want=$1; shift
  set +e; "$@"; local got=$?; set -e
  if [[ $got -ne $want ]]; then echo "FAIL: expected exit $want, got $got: $*"; exit 1; fi
}
wallet() { # a stalled lightwalletd connection must fail, not hang
  local out rc=0
  out=$(timeout 120 "$DEVTOOL" wallet "$@" 2>&1) || rc=$?
  [[ $rc -ne 124 ]] || { echo "FAIL: devtool timed out: wallet $*" >&2; exit 1; }
  [[ $rc -eq 0 ]] || { echo "FAIL: devtool exited $rc: wallet $*" >&2; echo "$out" >&2; exit 1; }
  grep -v ' INFO ' <<<"$out" || true
}

step "real testnet wallet on device A"
wallet -w walletA init --name e2e -i walletA.age -n test >/dev/null
wallet -w walletA sync >/dev/null
addr_a=$(wallet -w walletA list-addresses | awk '/Default Address/ {print $3}')
echo "address: $addr_a"

"$HERMIT" --home A device init --name laptop >/dev/null
"$HERMIT" --home B device init --name phone >phone.json
"$HERMIT" --home C device init --name tablet >tablet.json

step "capsule + pairing"
"$HERMIT" --home A create --wallet walletA --store "$RELAY" --include-secret --witness "$WITNESS"
"$HERMIT" --home A device add phone.json
"$HERMIT" --home A pair >pair.json
"$HERMIT" --home B join --store dir://storeB pair.json
"$HERMIT" --home B sync "$RELAY"

step "restore on device B (view-only) and resume scanning"
"$HERMIT" --home B restore --into walletB --server "$SERVER"
wallet -w walletB sync >/dev/null
addr_b=$(wallet -w walletB list-addresses | awk '/Default Address/ {print $3}')
[[ "$addr_a" == "$addr_b" ]] && echo "✓ same address on device B"
wallet -w walletB display-mnemonic --enable -i walletA.age | grep -q "No mnemonic" \
  && echo "✓ device B cannot reveal the spend key"

step "restore with spend authority (still locked to the wallet identity)"
"$HERMIT" --home B restore --into walletB2 --with-secret --offline
[[ $(wallet -w walletB2 display-mnemonic --enable -i walletA.age | wc -w) -eq 24 ]] \
  && echo "✓ spend key unlocks only with the wallet's age identity"

step "rollback: the relay freezes and silently drops writes"
relay_mode freeze
"$HERMIT" --home A label contact:bob u1bob
expect 20 "$HERMIT" --home A status --offline
expect 20 "$HERMIT" --home B status --offline
echo "✓ passive device B detects withheld state through the witness"
relay_mode honest
"$HERMIT" --home A status --offline
echo "✓ withheld state republished from A's replica"

step "corrupting relay cannot poison a fresh device"
"$HERMIT" --home D device init --name kiosk >kiosk.json
"$HERMIT" --home A device add kiosk.json
"$HERMIT" --home A pair >pair-d.json
"$HERMIT" --home D join --store "$RELAY" pair-d.json
relay_mode corrupt
expect 1 "$HERMIT" --home D restore --into walletD --offline
relay_mode honest

step "partitioned label edits merge"
"$HERMIT" --home B sync "$RELAY"
"$HERMIT" --home A label "tx:first" "rent October"
"$HERMIT" --home B --local label contact:alice u1alice
"$HERMIT" --home B sync "$RELAY"
expect 21 "$HERMIT" --home B status --offline
"$HERMIT" --home B merge
"$HERMIT" --home B sync "$RELAY"
[[ $("$HERMIT" --home A labels | wc -l) -eq 3 ]] && echo "✓ both devices' labels kept"

step "export the verified head as ZeWIF and check it against the schema"
"$HERMIT" --home A zewif --out export.zewif
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p hermit --example zewif_conformance -- export.zewif

step "wallet synced from a lying server: refused at signing"
cp -r walletA evil
sqlite3 evil/data.sqlite \
  "UPDATE blocks SET hash = randomblob(32) WHERE height = (SELECT MAX(height) FROM blocks)"
expect 23 "$HERMIT" --home A snapshot --wallet evil --server "$SERVER"

step "partitioned authority edits conflict"
"$HERMIT" --home A device add tablet.json
"$HERMIT" --home B --local device revoke laptop
"$HERMIT" --home B sync "$RELAY"
expect 22 "$HERMIT" --home B merge

printf '\n\033[1mALL OK\033[0m\n'
