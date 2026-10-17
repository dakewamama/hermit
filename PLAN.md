# Zcash Continuity — build plan (ZECATHON)

Locked 2026-10-17. Deadline is unconfirmed: assumed **Tue 2026-10-28**, from the "~14 days left" post on Oct 14. Check it on thezecathon.com after signing in, along with the track list and submission requirements.
Target track: **Core & Tooling**, which also keeps us eligible for the grand prize.

---

## 0. What changed from the original plan, and why

| Original claim | Reality (checked 2026-10-17) | Consequence |
|---|---|---|
| "Export Zallet state to ZeWIF, import into Wallet B" | No wallet exports or imports ZeWIF today. The only producer is `zewif-zcashd` (via zmigrate), which reads legacy zcashd `wallet.dat`. Zallet does not mention ZeWIF. | ZeWIF can't be the transport for the demo. It becomes our **schema for classification**, and full ZeWIF output is a stretch goal. |
| "Run Z3 with two commands" | Z3 needs Docker (Compose ≥ 2.24.4). This machine has no Docker. The Z3 docs give no way to mine past init or to fund a shielded address. | Install Docker on day 1 and run a funding spike. Keep a fallback environment ready. |
| 25-item scope | 10 days, small team | Cut to 9 MUST items (§3). Everything else is SHOULD or WON'T. |

**Key insight that de-risks the build:** Zallet, `zcash-devtool`, and the mobile SDKs all store wallet state in **`zcash_client_sqlite`**. The adapter should target that database schema, not Zallet's RPC. That gives us one adapter for two real wallets, plus a fallback environment that needs neither Docker nor Zebra: `zcash-devtool` on testnet, using a public lightwalletd/Zaino endpoint and the testnet faucet.

---

## 1. One-sentence pitch

> Your wallet is software; your shielded state is yours. **Zcash Continuity** moves a live shielded wallet between machines and wallet apps inside an encrypted, signed, lineage-checked capsule. Untrusted storage can't roll it back or fork it without being caught, and the spend key never travels with it.

## 2. The demo (this is the spec: build backwards from it)

A 3-minute video and one script, `demo/run.sh`, that a judge can rerun:

1. **Device A**: a wallet has received shielded ZEC, sent a shielded tx, and has labels/notes attached. `zc snapshot` → capsule **S1** (shows: anchor height/hash, section classes, sizes, signature).
2. `zc push` to **two dumb stores** (local dir + HTTP relay). Both stores see only ciphertext.
3. **Device B** (fresh datadir): `zc pull && zc verify && zc restore`. Output: lineage OK, witness OK, anchor matches Zebra/lightwalletd, **blocks to rescan: 37 vs full rescan: 1,204**. The wallet opens with the same balance and tx history.
4. Spend key check: device B can **view** but not **spend** until the spend authority envelope is unlocked separately. Show the attempt to spend failing, then succeeding after the explicit unlock.
5. **Attack 1, rollback**: the relay serves S0 while S3 is the latest → `ROLLBACK DETECTED` (exit 20).
6. **Attack 2, fork**: A and B both write S4 off S3. The metadata-only divergence → `MERGED` into S5 with two parents.
7. **Attack 3, illegal fork**: A and B concurrently change the *authority* section (device add/remove) → `CONFLICT: manual resolution required` (exit 22). Nothing is written.
8. **Attack 4, forged chain**: a capsule whose anchor hash doesn't match the chain → `ANCHOR MISMATCH` (exit 23).

If steps 1–3 and 5–7 work, we have a submission. Steps 4 and 8 are cheap extras.

## 3. Scope

**MUST (submission-critical)**
1. `kernel`: manifest, transition, lineage (parents/seq), deterministic state root, Ed25519 device signatures, verify.
2. `capsule`: per-section encryption to device recipients (age X25519; Zallet already uses age).
3. Section classes with merge rules (§5) and a fork resolver.
4. Local high-water mark for rollback detection, plus fork detection on equal `seq`.
5. Witness service (~150 LOC): cosigns `(capsule_id, seq, hash)` and refuses equivocation, so a fresh device can detect rollback.
6. Two storage backends: `dir://` and `http://` relay (dumb PUT/GET of blobs). The relay has a `--hostile` mode to stage the attacks.
7. Zcash adapter on `zcash_client_sqlite`: snapshot DB → sections; anchor `(height, block_hash)`; scanned ranges → progress section; restore into a fresh datadir.
8. Chain verification of the anchor against the node (Zebra `getblockhash`) or lightwalletd (`GetBlock`).
9. `demo/run.sh`, README, video.

**SHOULD (only once MUST items are green)**
- Spend-authority envelope kept separate (step 4 of the demo).
- Cross-wallet restore: Zallet DB → zcash-devtool, if both are on a compatible schema version. Claim this only if it actually works.
- Partial `zcash_client_sqlite → ZeWIF` exporter for accounts/UFVKs/tx ids/scan ranges. This is the only *upstream-useful* artifact, so it's worth a lot to Zcash judges.

**WON'T (say so in the README)**
Ragu/PCD, a UI, a new wallet, Zebra/Zaino forks, on-chain anything, a generic multi-domain kernel, threshold keys, or TEE evidence. `Evidence` stays an enum so these slot in later.

## 4. Repo layout

```
zcash-continuity/
├── Cargo.toml                  # workspace
├── crates/
│   ├── kernel/      manifest.rs  transition.rs  lineage.rs  class.rs  merge.rs  verify.rs  root.rs
│   ├── capsule/     envelope.rs  seal.rs (age)  codec.rs (deterministic CBOR, minicbor)
│   ├── store/       dir.rs  http.rs
│   └── witness/     log.rs  (sled or sqlite append-only)
├── adapters/zcash/  sqlite_snapshot.rs  classify.rs  anchor.rs  restore.rs  zewif_export.rs (SHOULD)
├── apps/
│   ├── zc/          # CLI
│   ├── relay/       # axum blob relay, --hostile
│   └── witnessd/    # axum witness
├── demo/run.sh
└── integration/     # z3 fork overrides OR devtool-testnet scripts
```

## 5. Data model: the exact definitions

```rust
struct Manifest {
    version: u16,                 // 1
    capsule_id: Hash32,           // = H(genesis manifest without sig)
    seq: u64,                     // strictly parent.seq + 1 (merge: max(parents)+1)
    parents: Vec<Hash32>,         // 1 normally, 2 for merge, 0 for genesis
    domain: "zcash/v1",
    anchor: Option<ChainAnchor>,  // { network, height, block_hash }
    sections: Vec<SectionRef>,    // sorted by name
    state_root: Hash32,           // H(sorted section (name, class, plaintext_hash))
    devices: Hash32,              // hash of authority section = current device set
    author: DevicePubKey,
    lamport: u64,
    evidence: Vec<Evidence>,      // Signature(author) mandatory; WitnessCosig optional
}
struct SectionRef { name, class: Class, plaintext_hash: Hash32, blob: Hash32 /*ciphertext addr*/, len }
enum Class { Derived, Progress, Metadata, Authority, Secret }
enum Evidence { Signature{..}, WitnessCosig{witness, sig}, /* future */ Pcd{..}, Tee{..} }
```

Hash: BLAKE2b-256 with personalization `"ZcContinuity_v1"` (the Zcash convention). Encoding: deterministic CBOR (RFC 8949 §4.2), the same as ZeWIF. Blobs are content-addressed: the store holds `blobs/<hash>` and `heads/<capsule_id>`. **The head pointer is advisory only. Truth comes from signatures and lineage.**

**Class semantics.** This table is the thesis, so test it exhaustively.

| Class | Zcash contents | On concurrent change | On restore |
|---|---|---|---|
| Derived | tx data, blocks, commitment tree frontier | take either; re-verify against the chain | verify anchor, else reject |
| Progress | scanned ranges, fully-scanned height | **max is allowed only if the claimed hash at that height verifies**, otherwise conflict | rescan from `anchor.height` |
| Metadata | labels, contacts, tx notes | LWW-register per key `(lamport, device)` → auto-merge | apply |
| Authority | device set, viewing-key set | **any concurrent change = CONFLICT** | must match the signer's set |
| Secret | encrypted seed / spend key | never in the default capsule; a separate envelope for separate recipients | explicit unlock |

**Verdicts and exit codes:** `OK 0`, `ROLLBACK 20`, `FORK_MERGEABLE 21` (auto-merged), `CONFLICT 22`, `ANCHOR_MISMATCH 23`, `BAD_SIG 24`, `UNKNOWN_DEVICE 25`.

**Rollback rule:** reject when `seq < local_hwm.seq`, or when `seq == hwm.seq` and the hash differs (that's a fork). On a fresh device, require a witness cosig for the head and ask the witness for its latest `seq`.

**Zcash mapping (first pass; confirm against the real schema on day 3).** The wallet DB is the opaque payload, split by table group:
- `Derived`: `blocks`, `transactions`, the commitment tree tables (`*_tree_shards`, `*_tree_cap`, `*_tree_checkpoints`)
- `Progress`: `scan_queue`, the fully-scanned height
- `Authority`: `accounts` (UFVKs only)
- `Metadata`: our own `labels.cbor`, because `zcash_client_sqlite` has no labels; this is exactly the wallet-local state ZeWIF says gets lost
- `Secret`: Zallet's age-encrypted keystore, or the devtool seed file. Excluded by default.

Restore = rebuild the DB from sections, run the wallet → it resumes scanning at `anchor.height`.

## 6. Day-by-day (10 days)

| Day | Date | Deliverable (done = demoable) | Owner |
|---|---|---|---|
| 1 | Sat 10/18 | **Environment spike, 4h timebox.** Install Docker → Z3 regtest up → mine → get funds into an Orchard address (try a Zebra `miner_address` set to a UA; otherwise shield coinbase via Zallet `z_shieldcoinbase`/`z_sendmany`). **If it isn't working by hour 4 → switch to zcash-devtool on testnet + faucet.** In parallel: workspace, `kernel` types, codec, hashing. | env / kernel |
| 2 | Sun 10/19 | Kernel: sign/verify, lineage, rollback/fork detection, all with unit tests. Capsule age-sealing. | kernel |
| 3 | Mon 10/20 | Real wallet with a shielded send + receive in hand. Dump `zcash_client_sqlite` schema, finalize §5 mapping. `zc snapshot` produces S1. | adapter |
| 4 | Tue 10/21 | Stores (`dir`, `http` relay), `zc push/pull`. Restore into a fresh datadir; wallet opens. | adapter / apps |
| 5 | Wed 10/22 | Anchor verification against chain. Rescan delta measured and printed. **Milestone: demo steps 1–3 work end to end.** | adapter |
| 6 | Thu 10/23 | Merge engine (LWW metadata, authority conflict), witness service, hostile relay modes. Demo steps 5–7. | kernel / apps |
| 7 | Fri 10/24 | `demo/run.sh` fully scripted; property tests (random fork interleavings never produce silent authority merges). | all |
| 8 | Sat 10/25 | SHOULDs: secret envelope (step 4), then the ZeWIF partial export or the cross-wallet restore. | — |
| 9 | Sun 10/26 | **Feature freeze.** README (philosophy ≤ 1 screen, then architecture, threat model, limits), record the video. | — |
| 10 | Mon 10/27 | Buffer. Submit **a day early**. | — |

**Kill rules:** if day 5's milestone slips past day 6, drop the witness and the HTTP relay (use two `dir://` stores, rollback via the local HWM only) and protect the demo. Never trade away steps 1–3.

## 7. Threat model (README section; judges in privacy tracks read this)

- Storage/relay: fully untrusted. It sees blob sizes and timing, nothing else. Known leak: blob sizes reveal wallet size; pad to buckets (SHOULD).
- Witness: trusted only for *freshness*, not confidentiality or authority. Equivocation is provable (two signed cosigs at the same seq).
- Compromised device: can author valid transitions until removed. Removing it is an Authority transition, and concurrent removals CONFLICT.
- Out of scope: a compromised node or lightwalletd lying about the chain (mitigated by using our own Zebra), side channels, metadata leaked while syncing.

## 8. Day-1 checklist (do now)

```bash
# Docker in WSL2: Docker Desktop with WSL integration, or docker-ce inside the distro
git clone https://github.com/ZcashFoundation/z3 && cd z3 && ./scripts/regtest-init.sh
docker compose --env-file .env.regtest up -d
# fallback env:
git clone https://github.com/zcash/zcash-devtool   # zcash_client_sqlite CLI wallet
```
Note: this machine has 8 GB RAM. Building Zebra and Zallet from source is slow, so prefer the Z3 images.

## 9. Open questions to close on day 1
1. Exact deadline, the track names, and whether a video, live demo, or open-source license is required.
2. Can Zebra regtest mine directly to a shielded UA? If not, which Zallet RPC shields coinbase?
3. Which `zcash_client_sqlite` schema version does Zallet ship, and does zcash-devtool match it (needed for the cross-wallet SHOULD)?
4. Where does Zallet keep its secret material (age keystore in the DB vs. a separate file)? This decides how the Secret section is split.
