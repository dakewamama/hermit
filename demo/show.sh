#!/usr/bin/env bash
# Paced walkthrough for recording. Runs against a real, already-synced
# zcash-devtool testnet wallet; press Enter between scenes (PACE=0 to run
# straight through).
#
#   DEVTOOL=... WALLET=path/to/wallet IDENTITY=path/to/wallet.age demo/show.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HERMIT=${HERMIT:-$ROOT/target/debug/hermit}
DEVTOOL=${DEVTOOL:?set DEVTOOL to a zcash-devtool binary}
WALLET=$(realpath "${WALLET:?set WALLET to a synced devtool wallet dir}")
IDENTITY=$(realpath "${IDENTITY:?set IDENTITY to the wallet age identity}")
PACE=${PACE:-1}

WORK=$(mktemp -d)
cd "$WORK"
source "$ROOT/demo/servers.sh"
trap stop_servers EXIT

bold=$'\033[1m' dim=$'\033[2m' off=$'\033[0m'
scene() { printf '\n%s━━ %s%s\n' "$bold" "$*" "$off"; }
say() { printf '%s%s%s\n' "$dim" "$*" "$off"; }
run() { printf '%s$ %s%s\n' "$bold" "$*" "$off"; "$@"; }
pause() { [[ $PACE == 0 ]] || read -rp "" _; }
wallet() { "$DEVTOOL" wallet "$@" 2>&1 | grep -v ' INFO ' || true; }
attempt() { set +e; "$@"; printf '%s(exit %d)%s\n' "$dim" $? "$off"; set -e; }

"$HERMIT" --home laptop device init --name laptop >/dev/null
"$HERMIT" --home phone device init --name phone >phone.json
"$HERMIT" --home tablet device init --name tablet >tablet.json

scene "1. A real shielded wallet on Zcash testnet"
say "zcash-devtool wallet, birthday $(awk -F' = ' '/^birthday/ {print $2}' "$WALLET/keys.toml")"
wallet -w "$WALLET" list-addresses | grep "Default Address"
pause

scene "2. Seal its state into a capsule on an untrusted relay"
run "$HERMIT" --home laptop create --wallet "$WALLET" --store "$RELAY" --witness "$WITNESS"
say "what anyone fetching from the relay gets:"
cap=$(jq -r .capsule_id laptop/capsule.json)
for blob in $(curl -sf "$RELAY/c/$cap/b"); do
  printf '  %10s bytes  %s\n' "$(curl -sf "$RELAY/c/$cap/b/$blob" | wc -c)" "$blob"
done
curl -sf "$RELAY/c/$cap/b/$blob" | head -c 120 | xxd | head -4
pause

scene "3. A new phone joins and restores. No seed, no birthday, no rescan"
run "$HERMIT" --home laptop device add phone.json
"$HERMIT" --home laptop pair >pair.json
run "$HERMIT" --home phone join --store "$RELAY" pair.json
run "$HERMIT" --home phone restore --into phone-wallet
start=$(date +%s)
wallet -w phone-wallet sync >/dev/null
say "phone wallet synced in $(( $(date +%s) - start ))s"
wallet -w phone-wallet list-addresses | grep "Default Address"
pause

scene "4. The phone can see, but cannot spend"
run "$DEVTOOL" wallet -w phone-wallet display-mnemonic --enable -i "$IDENTITY" 2>&1 | grep -v ' INFO '

pause

scene "5. The relay goes stale and silently drops a write"
relay_mode freeze
run "$HERMIT" --home laptop label contact:alice u1alice
attempt "$HERMIT" --home laptop status --offline
relay_mode honest
run "$HERMIT" --home laptop status --offline
pause

scene "6. Two devices edit labels offline, then meet"
"$HERMIT" --home phone sync "$RELAY" >/dev/null
run "$HERMIT" --home laptop label tx:first "rent October"
run "$HERMIT" --home phone --local label contact:bob u1bob
run "$HERMIT" --home phone sync "$RELAY"
run "$HERMIT" --home phone merge
run "$HERMIT" --home phone labels
pause

scene "7. A wallet synced from a lying server is refused before signing"
cp -r "$WALLET" evil-wallet
sqlite3 evil-wallet/data.sqlite \
  "UPDATE blocks SET hash = randomblob(32) WHERE height = (SELECT MAX(height) FROM blocks)"
attempt "$HERMIT" --home laptop snapshot --wallet evil-wallet
pause

scene "8. Hand the verified state to any wallet: ZeWIF"
run "$HERMIT" --home laptop zewif --out wallet.zewif
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p hermit --example zewif_conformance -- wallet.zewif
pause

scene "9. Concurrent changes to who holds authority are never auto-merged"
"$HERMIT" --home laptop sync "$RELAY" >/dev/null
run "$HERMIT" --home laptop device add tablet.json
run "$HERMIT" --home phone --local device revoke laptop
run "$HERMIT" --home phone sync "$RELAY"
attempt "$HERMIT" --home phone merge
say "a human decides: the phone keeps its revocation"
head=$("$HERMIT" --home phone log | awk '/revoke device laptop/ {print $2}')
run "$HERMIT" --home phone resolve --keep "$head"
run "$HERMIT" --home phone log

