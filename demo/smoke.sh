#!/usr/bin/env bash
# Offline end-to-end check of the attack matrix against a synthetic
# zcash_client_sqlite-shaped wallet. No network, no real funds.
#
#   demo/smoke.sh [path/to/zc]
set -euo pipefail

ZC=${1:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/zc}
WORK=$(mktemp -d)
trap 'echo "workdir: $WORK"' EXIT
cd "$WORK"

expect() { # expect <code> <cmd...>
  local want=$1; shift
  set +e; "$@"; local got=$?; set -e
  if [[ $got -ne $want ]]; then echo "FAIL: expected exit $want, got $got: $*"; exit 1; fi
}

mkdir w
printf 'mnemonic = "age-encrypted-placeholder"\nnetwork = "test"\nbirthday = 3000000\n' > w/keys.toml
sqlite3 w/data.sqlite "
  CREATE TABLE blocks(height INTEGER PRIMARY KEY, hash BLOB);
  CREATE TABLE scan_queue(block_range_start INTEGER, block_range_end INTEGER, priority INTEGER);
  INSERT INTO blocks VALUES (3100000, randomblob(32));
  INSERT INTO scan_queue VALUES (3000000, 3090001, 10), (3090001, 3100001, 30);"

$ZC --home A device init --name laptop >/dev/null
$ZC --home B device init --name phone >phone.json
$ZC --home C device init --name tablet >tablet.json

echo "== create + pair"
$ZC --home A create --wallet w --store dir://storeA --include-secret
$ZC --home A device add phone.json
$ZC --home A pair >pair.json
$ZC --home B join --store dir://storeB pair.json
$ZC --home B sync dir://storeA

echo "== view-only restore"
$ZC --home B restore --into wB --offline
! grep -q mnemonic wB/keys.toml

echo "== rollback"
$ZC --home A label contact:bob u1bob
cap=$(ls storeA)
newest=$(ls -t "storeA/$cap/m" | head -1)
mv "storeA/$cap/m/$newest" hidden
expect 20 $ZC --home A status --offline
mv hidden "storeA/$cap/m/$newest"

echo "== partitioned metadata edits merge"
$ZC --home B sync dir://storeA
$ZC --home A label tx:ab12 "rent Oct"
$ZC --home B label contact:alice u1alice
$ZC --home B sync dir://storeA
expect 21 $ZC --home B status --offline
$ZC --home B merge
$ZC --home A sync dir://storeB
[[ $($ZC --home A labels | wc -l) -eq 3 ]]

echo "== partitioned authority edits conflict"
$ZC --home A device add tablet.json
$ZC --home B device revoke laptop
$ZC --home B sync dir://storeA
expect 22 $ZC --home B merge

echo "ALL OK"
