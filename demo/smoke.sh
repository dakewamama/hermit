#!/usr/bin/env bash
# Offline end-to-end check of the attack matrix against a synthetic
# zcash_client_sqlite-shaped wallet. No network, no real funds.
#
#   demo/smoke.sh [path/to/hermit]
set -euo pipefail

HERMIT=${1:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/hermit}
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

$HERMIT --home A device init --name laptop >/dev/null
$HERMIT --home B device init --name phone >phone.json
$HERMIT --home C device init --name tablet >tablet.json

echo "== create + pair"
$HERMIT --home A create --wallet w --store dir://storeA --include-secret
$HERMIT --home A device add phone.json
$HERMIT --home A pair >pair.json
$HERMIT --home B join --store dir://storeB pair.json
$HERMIT --home B sync dir://storeA

echo "== view-only restore"
$HERMIT --home B restore --into wB --offline
! grep -q mnemonic wB/keys.toml

echo "== rollback"
$HERMIT --home A label contact:bob u1bob
cap=$(ls storeA)
newest=$(ls -t "storeA/$cap/m" | head -1)
mv "storeA/$cap/m/$newest" hidden
expect 20 $HERMIT --home A status --offline
mv hidden "storeA/$cap/m/$newest"

echo "== partitioned metadata edits merge"
$HERMIT --home B sync dir://storeA
$HERMIT --home A label tx:ab12 "rent Oct"
$HERMIT --home B label contact:alice u1alice
$HERMIT --home B sync dir://storeA
expect 21 $HERMIT --home B status --offline
$HERMIT --home B merge
$HERMIT --home A sync dir://storeB
[[ $($HERMIT --home A labels | wc -l) -eq 3 ]]

echo "== partitioned authority edits conflict"
$HERMIT --home A device add tablet.json
$HERMIT --home B device revoke laptop
$HERMIT --home B sync dir://storeA
expect 22 $HERMIT --home B merge

echo "ALL OK"
