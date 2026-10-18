#!/usr/bin/env bash
# Shielded payments end to end on a private regtest chain, then Hermit moves
# the paying wallet to a new device which keeps spending.
#
#   ZEBRAD=zebrad ZAINOD=zainod DEVTOOL=<devtool built with regtest_support> \
#     demo/regtest.sh
#
# Real Zcash consensus (Zebra), a real indexer (Zaino), real Orchard notes:
# coinbase is mined straight to the wallet's unified address. Expect ~10
# minutes, mostly mining the 100 blocks coinbase needs to mature.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HERMIT=${HERMIT:-$ROOT/target/debug/hermit}
ZEBRAD=${ZEBRAD:-zebrad}
ZAINOD=${ZAINOD:-zainod}
DEVTOOL=${DEVTOOL:?set DEVTOOL to a zcash-devtool built with --features regtest_support}
BASE=${BASE_PORT:-19200}
RPC=127.0.0.1:$BASE GRPC=127.0.0.1:$((BASE + 1)) P2P=127.0.0.1:$((BASE + 2))
INDEXER=http://$GRPC

WORK=$(mktemp -d)
cd "$WORK"
PIDS=()
cleanup() {
  if ((${#PIDS[@]})); then kill "${PIDS[@]}" 2>/dev/null; fi
  echo "workdir: $WORK"
}
trap cleanup EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
rpc() {
  curl -sf --max-time 1200 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "http://$RPC"
}
wallet() {
  local out rc=0
  out=$(timeout 600 "$DEVTOOL" wallet "$@" 2>&1) || rc=$?
  [[ $rc -eq 0 ]] || { echo "FAIL: devtool exited $rc: wallet $*" >&2; echo "$out" >&2; exit 1; }
  grep -v ' INFO ' <<<"$out" || true
}
address() { wallet -w "$1" list-addresses | awk '/Default Address/ {print $3}'; }
mine() { rpc generate "[$1]" >/dev/null; }
# Zaino indexes asynchronously; sync until the wallet has seen `txid`.
sync_until() {
  local w=$1 txid=$2
  for _ in $(seq 30); do
    wallet -w "$w" sync -s "$GRPC" >/dev/null
    wallet -w "$w" list-tx | grep -q "$txid" && return 0
    sleep 2
  done
  echo "FAIL: $w never saw $txid" >&2
  exit 1
}

start_zebrad() {
  "$ZEBRAD" -c zebrad.toml start >>zebrad.log 2>&1 &
  ZEBRA_PID=$!
  PIDS+=("$ZEBRA_PID")
  for _ in $(seq 60); do rpc getblockchaininfo '[]' >/dev/null 2>&1 && return 0; sleep 1; done
  echo "FAIL: zebrad did not come up" >&2
  tail -20 zebrad.log >&2
  exit 1
}
write_zebrad_config() {
  cat >zebrad.toml <<EOF
[mining]
internal_miner = false
miner_address = "$1"

[network]
network = "Regtest"
listen_addr = "$P2P"
cache_dir = false
initial_mainnet_peers = []
initial_testnet_peers = []

[network.testnet_parameters.activation_heights]
Canopy = 1
NU5 = 1

[rpc]
listen_addr = "$RPC"
enable_cookie_auth = false

[state]
cache_dir = "$WORK/zebra-state"
ephemeral = false
EOF
}

step "regtest chain: Zebra, NU5 from height 1"
# A throwaway address (Zebra's own regtest default) mines the first blocks,
# because a wallet's birthday must be at or after Sapling activation.
write_zebrad_config tmJymvcUCn1ctbghvTJpXBwHiMEB8P6wxNV
start_zebrad
mine 2

step "Zaino indexer in front of it"
"$ZAINOD" generate-config --output zainod.toml >/dev/null
sed -i -e 's|^network = .*|network = "Regtest"|' \
  -e "s|^zebra_db_path = .*|zebra_db_path = \"$WORK/zebra-state\"|" \
  -e "s|^path = .*|path = \"$WORK/zaino-state\"|" \
  -e "s|^listen_address = .*|listen_address = \"$GRPC\"|" \
  -e "s|^validator_jsonrpc_listen_address = .*|validator_jsonrpc_listen_address = \"$RPC\"|" zainod.toml
"$ZAINOD" start --config zainod.toml >zainod.log 2>&1 &
PIDS+=($!)
for _ in $(seq 60); do grep -q "grpc.*Ready" zainod.log && break; sleep 1; done
grep -q "grpc.*Ready" zainod.log || { echo "FAIL: zaino not ready" >&2; tail -20 zainod.log >&2; exit 1; }

step "wallets: ours (A) and a counterparty (bob)"
cat >heights.toml <<'EOF'
overwinter = 1
sapling = 1
blossom = 1
heartwood = 1
canopy = 1
nu5 = 1
nu6 = "never"
nu6_1 = "never"
nu6_2 = "never"
nu6_3 = "never"
nu7 = "never"
EOF
for w in walletA bob; do
  wallet -w "$w" init --name "$w" -i "$w.age" -n regtest --activation-heights heights.toml -s "$GRPC" >/dev/null
done
addr_a=$(address walletA)
addr_bob=$(address bob)

step "mine shielded coinbase to A and let it mature"
kill "$ZEBRA_PID"
wait "$ZEBRA_PID" 2>/dev/null || true
write_zebrad_config "$addr_a"
start_zebrad
mine 101
first_coinbase=$(rpc getblock '["3", 1]' | jq -r '.result.tx[0]')
sync_until walletA "$first_coinbase"
wallet -w walletA balance | tr -d ' \n' | grep -oE 'orchard_balance:Balance\{spendable_value:Zatoshis\([0-9]+' \
  | sed 's/.*(/  spendable Orchard zatoshis: /'

step "A pays bob, shielded, with a memo"
tx1=$(wallet -w walletA send -i walletA.age --address "$addr_bob" --value 150000000 \
  --memo "rent October" -s "$GRPC" | grep -oE '^[0-9a-f]{64}$')
mine 1
sync_until bob "$tx1"
wallet -w bob enhance -s "$GRPC" >/dev/null
wallet -w bob list-tx | grep -q 'Memo::Text("rent October")' && echo "✓ bob decrypted the memo"

step "Hermit: seal A, label the payment, move it to a new device"
"$HERMIT" --home laptop device init --name laptop >/dev/null
"$HERMIT" --home phone device init --name phone >phone.json
"$HERMIT" --home laptop create --wallet walletA --store dir://store --include-secret
"$HERMIT" --home laptop label "tx:${tx1:0:8}" "rent October -> bob"
"$HERMIT" --home laptop label contact:bob "$addr_bob" >/dev/null
"$HERMIT" --home laptop device add phone.json
"$HERMIT" --home laptop pair >pair.json
"$HERMIT" --home phone join --store dir://phone-store pair.json
"$HERMIT" --home phone sync dir://store
"$HERMIT" --home phone restore --into phone-wallet --with-secret --server "$INDEXER"
[[ $(address phone-wallet) == "$addr_a" ]] && echo "✓ same wallet on the phone"
"$HERMIT" --home phone labels

step "the phone keeps spending"
tx2=$(wallet -w phone-wallet send -i walletA.age --address "$addr_bob" --value 25000000 \
  --memo "sent from my new phone via Hermit" -s "$GRPC" | grep -oE '^[0-9a-f]{64}$')
mine 1
sync_until bob "$tx2"
wallet -w bob enhance -s "$GRPC" >/dev/null
wallet -w bob list-tx | grep -q 'sent from my new phone via Hermit' \
  && echo "✓ bob received the phone's payment and its memo"

printf '\n\033[1mALL OK\033[0m\n'
