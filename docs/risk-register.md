# Risk register — adopting an RKE2 cluster with Talos control planes

Everything we learned, ordered by **how strongly it argues against doing this**.
Read top-down and stop when you reach something you are not willing to accept.

Status of the work itself: the full path — adopt a Talos CP, migrate a worker,
decommission an RKE2 CP — is **proven end to end** on a cluster shaped like
production (3 RKE2 CPs, Cilium in kube-proxy-replacement mode, Secrets
encryption on). Nothing below is speculative; every row was observed.

The happy path has since been drilled against failure: the adopted control plane
was rebooted, the shim was taken down under load, and a worker was re-registered
across both a shim and a stock `rke2-server`. Those drills corrected one finding
(#4), added three (#4b, #16, #17) and confirmed the rest. Before generating any
machine config, run
[`preflight.sh`](../examples/adopt-rke2-cluster/preflight.sh) — most rows here
began life as a parameter Talos defaulted to something plausible and wrong.

## 🛑 Blockers — resolve before you start

| # | Finding | Why it hurts | Status |
|---|---|---|---|
| 1 | 🔑 **The shim holds a CA private key.** It signs Kubernetes identities, so compromising the pod compromises the cluster. | Inherent to the design — `serving-kubelet` and the cluster identities have no built-in Kubernetes signer. Can't be engineered away. | ⚠️ Accepted risk. Contained: distroless nonroot, read-only rootfs, dropped caps, least-privilege RBAC. Treat `rke2-shim` RBAC as control-plane-grade. |
| 2 | 🧩 **The RKE2 supervisor protocol is undocumented.** Everything here was reverse-engineered from real binaries. | Rancher owes you no compatibility. A future RKE2 release can change it, and you own that forever. | ✅ Mitigated, not solved. Contracts captured per version, replayed in CI, unknown endpoints fail loudly. Measured **identical** across v1.31.8 → v1.35.7. |
| 3 | 🕸️ **Cilium must be reconfigured cluster-wide before adopting.** Talos runs a tighter capability bounding set; Cilium's defaults die with `unable to apply caps: operation not permitted`. | The fix edits the **shared** `HelmChartConfig`, redeploying Cilium on **every** node — RKE2 ones included. It is the only required change not confined to the Talos node. | ✅ Verified: all RKE2 nodes stayed `Ready` through the rollout. Do it as a deliberate pre-step. |

| 3b | 💣 **The 2-certificate CA bundle kills the Talos controller-manager — but only once the last RKE2 control plane is gone.** | `kube-controller-manager` refuses to start its CSR signer: `error reading CA cert file ...: expected 1 certificate, found 2`. Adopting RKE2 **requires** `cluster.ca` to be a bundle (`server-ca` + `client-ca`) so both are trusted, and Talos hands that same file to the signer. Trust wants two certs; signing wants one. RKE2's own controller-manager holds the lease throughout the migration, so this stays invisible until the moment you finish — then **all three** Talos controller-managers crashloop and **every controller stops**: no DaemonSet reconciliation, no Deployments, no node lifecycle. Hit live at the very end of a migration that looked complete. | ✅ Shadow the signer's copy with a single-cert file via `controllerManager.extraVolumes` (`extraArgs` will not do: Talos denies `cluster-signing-cert-file`). The mount path yields a 56-char volume name, under the limit that defeats the same trick elsewhere (#19). See [migration-from-rke2.md](migration-from-rke2.md). **Apply it before removing the last RKE2 CP, not after.** |

## ⚠️ Serious — plan explicitly around these

| # | Finding | Why it hurts | Status |
|---|---|---|---|
| 4 | 🔌 **Each control plane is blind to the *other's* native nodes.** The Talos API server gets `401` against un-migrated RKE2 kubelets; RKE2 API servers get `502` against Talos nodes. | `kubectl logs`/`exec`/`port-forward` fail on that half of the cluster. The `401` is structural: Talos has **one** signing key, RKE2 has two. The CA bundle is `server-ca`-first (so the Talos serving cert is trusted by agents), which means Talos' `apiserver-kubelet-client` cert is *also* `server-ca`-signed — but RKE2 kubelets validate client certs against `client-ca`. Flipping the order just breaks the other direction. | ✅ **Contained on every path, by construction.** The `401` itself is unfixable on Talos 1.13 (both routes tested, both blocked) — but nothing has to reach it: **humans/CI** are held on RKE2 by pinning the VIP (#21), **in-cluster clients** by `endpoint-reconciler-type: none` (#20), and **Talos nodes** are served by `talosctl`, which needs no Kubernetes API at all. All three verified live. |
| 4b | 🌐 **Talos will silently default the cluster CIDRs, and it fails late.** Talos defaults to `10.244.0.0/16` / `10.96.0.0/12`; RKE2 typically uses `10.42.0.0/16` / `10.43.0.0/16`. | Two distinct failures. (a) The Talos API server's serving cert gets a SAN for the *wrong* `kubernetes` ClusterIP, so in-cluster clients that load-balance onto it fail TLS — intermittently, cluster-wide, in unrelated workloads. (b) If the Talos controller-manager ever wins the lease, new nodes get PodCIDRs the CNI cannot route — and it **always** wins once the last RKE2 CP is gone. | ✅ Solved by [`preflight.sh`](../examples/adopt-rke2-cluster/preflight.sh), which reads both CIDRs from the live control plane and refuses to render a config without them. Also inherits `--api-audiences`, which RKE2 sets to a **two-entry** list. |
| 5 | 🗝️ **Secrets encryption key names must match.** RKE2 names its key `aescbckey`, Talos hardcodes `key1`; Kubernetes selects by **name**, so identical material still fails. | Without a fix, neither control plane can read the other's Secrets — which also silently blocks Node registration, since the kubelet bootstrap token *is* a Secret. | ✅ **Solved**, RKE2 untouched: shadow Talos' generated config via `extraVolumes`. Fixed upstream in Talos v1.14 (`KubeEtcdEncryptionConfig`). |
| 6 | 🧨 **RKE2 evicts etcd members whose `Node` object is missing.** | Observed live: a boot failure meant no Node object, the pre-added learner was pruned, and `initial-cluster` then failed `validating peerURLs`. | ✅ Bounded. Add the learner **immediately** before the node boots. A *registered* Talos node is safe — confirmed by decommissioning a CP with the Talos member present. |
| 7 | 🔐 **RKE2 splits its PKI three ways.** Client certs → `client-ca`; the shim's own TLS → `server-ca`; `serving-kubelet` → `server-ca`. A single-CA Talos cluster hides this entirely. | Get it wrong and every RKE2 node logs `tls: bad certificate`, or kubelet serving certs are rejected as `unknown authority`. | ✅ Solved: bundle both CAs with **`server-ca` first** (it is the signing key, and agents must trust the Talos serving cert), plus `--tls-cert/--tls-key` and `--serving-ca-cert/--serving-ca-key` on the shim. Pinned by tests. The cost of that ordering is #4's `401`. |
| 8 | ⏱️ **Version skew is a hard constraint.** Talos 1.13 supports Kubernetes 1.31–1.36. | Two API servers on different minors against one etcd is unsupported and risks storage-version damage. | ✅ Pin with `--kubernetes-version` to the RKE2 minor. Upgrade Kubernetes only **after** migration. |

| 8b | 🌩️ **The supervisor saturates at ~9 bootstraps/s per control plane**, and the cost is scrypt on the node password, not certificate signing. | Latency grows linearly with concurrency while throughput stays flat — a re-registration storm (rack power event) queues rather than parallelises. A full bootstrap costs ~1 s of CPU per node. | 🔵 Bounded and probably **inherent to RKE2**, whose scrypt parameters these are — but the baseline against a stock `rke2-server` is **unmeasured**. Size control-plane CPU for the storm, not steady state. Numbers and levers: [benchmarks.md](benchmarks.md). |

## 🟡 Operational — will bite, cheap to avoid

| # | Finding | Why it hurts | Status |
|---|---|---|---|
| 9 | 💥 **`machine.files` needs `op: create`, not `overwrite`.** `overwrite` requires the file to already exist. | On a fresh node `writeUserFiles` fails and takes the whole boot with it — no etcd, no kubelet — while the node answers on apid at its static IP, so it *looks* alive. Symptom is misleading: `/etc/kubernetes: read-only file system`. | ✅ Fixed in docs and example. |
| 10 | 🎫 **ServiceAccount issuer/audience mismatch.** Talos defaults to its own endpoint; RKE2 uses the in-cluster issuer. | Pods on the Talos node get `401` from every RKE2 API server. Cilium is usually the first casualty. | ✅ Fixed via `apiServer.extraArgs`; the signing key is already shared by the PKI import. Existing pods must be recreated. |
| 11 | 🚦 **Never `member add` to a one-member etcd.** Quorum goes 1 → 2 and the cluster stops serving. | Took an RKE2 API server down instantly in an early test. | ✅ Always `--learner`. On a 3-CP cluster this is a non-issue, which is why prod-shaped testing matters. |
| 12 | 🔭 **`talosctl validate` does not enforce argument deny-lists.** | It accepts config that is rejected at runtime. I "confirmed" a wrong conclusion this way once. | ✅ Documented. Deny-lists are enforced on the node only. |
| 13 | 🧷 **KubePrism must be disabled during coexistence.** It load-balances the kubelet onto RKE2 API servers, which reject Talos-issued client certs. | Node registration fails with 401s. | ✅ `machine.features.kubePrism.enabled: false`; revisit after the RKE2 CPs are gone. |
| 14 | 🎯 **Talos self-promotes out of learner.** Its etcd controller promotes once caught up. | `etcdctl member promote` typically answers `can only promote a learner member`. Plan quorum for a voting member appearing on its own. | ✅ Documented. |
| 15 | 🧮 **Generate `initial-cluster` immediately before applying.** | A colleague adding a CP mid-run invalidated a pre-generated list. Don't build it from the `etcd.k3s.io/initial` annotation — that's a stale snapshot. | ✅ [`preflight.sh`](../examples/adopt-rke2-cluster/preflight.sh) reads it live. |
| 16 | ⏳ **The pinned `initial-cluster` is perishable, and its staleness is silent.** | Verified on a live reboot: etcd logged `member-initialized=true`, `"restarting local member"`, `initial-cluster:""` — it read membership from its data dir and **ignored the flag**, which still named a control plane decommissioned hours earlier. So it drifts unnoticed, and is consulted only when a node starts from an **empty** data dir — reprovision, disk replacement, `talosctl reset` — which is precisely when being wrong is unrecoverable. | ✅ Re-render before any such operation; drop the arg once the last RKE2 CP is gone. |
| 17 | 🔢 **Mixed etcd minor versions.** Talos ships a newer etcd than RKE2 bundles (3.6.11 vs 3.5.21 here). | etcd tolerates one minor of skew during a *rolling upgrade*, not as a steady state. The cluster version pins to the lowest member, so nothing looks wrong — then **removing the last RKE2 CP silently auto-upgrades 3.5 → 3.6**, a one-way door needing an explicit downgrade procedure to reverse. | ✅ Flagged by preflight. **Snapshot etcd immediately before removing the final RKE2 CP**, and keep the window inside one minor. |
| 18 | 🎫 **The Talos admin kubeconfig does not work against RKE2 API servers.** | `talosctl kubeconfig` mints a client cert signed by `server-ca` (first in the bundle), but RKE2 sets `--client-ca-file` to `client-ca` **only** and answers `You must be logged in to the server`. The reverse works: Talos trusts the two-cert bundle. | ✅ Use the **RKE2 admin kubeconfig** (`/etc/rancher/rke2/rke2.yaml`) for the whole migration — it is the one credential valid against both control planes, and it survives the VIP handover unchanged. |
| 19 | 📏 **A Talos `extraVolumes` mountPath longer than ~63 characters silently breaks the static pod.** | Talos derives the Kubernetes volume name from the mount path. Shadowing `/system/secrets/kubernetes/kube-apiserver/apiserver-kubelet-client.crt` yields a **69**-character name; the pod is rejected as invalid, the component never starts, and the node reports a circular `Authorization error ... nodes/proxy` that points nowhere near the cause. | ✅ Keep mount paths short. Note the encryption override works only because *its* path happens to fit. |
| 20 | 🤖 **In-cluster clients cannot be steered by a VIP.** Rancher's `cattle-cluster-agent`, operators and controllers all use the `kubernetes` ClusterIP, whose endpoints every API server registers itself into. | So Rancher's *View logs / Execute shell* against pods on **un-migrated RKE2 nodes** would fail intermittently with #4's `401`, and if #4b was not fixed, every in-cluster TLS handshake to a Talos node fails as well. | ✅ **Solved globally**: give the Talos API servers `endpoint-reconciler-type: none` and they withdraw from the `kubernetes` Service, so in-cluster traffic reaches **only** RKE2 while both exist. Verified: endpoints went from 3 to 1, both Talos API servers kept serving normally on their own addresses and via the VIP. 🛑 **Must be removed before the last RKE2 control plane goes**, or in-cluster clients have zero backends — `adopt.sh decommission` refuses if it is still set. |
| 21 | 📜 **The VIP must be in the API server certificate SANs on both sides, before the first handover.** | A human papers over this with `--insecure-skip-tls-verify`; an in-cluster agent cannot. Talos *does* add the VIP automatically — but only once a node has actually held it, which is after the switch that needed it. | ✅ `preflight.sh --vip <addr>` renders `cluster.apiServer.certSANs`. On RKE2 it must be in `tls-san`; if you already run a VIP it already is, otherwise adding it means touching RKE2. |
| 22 | 🏷️ **The shim's `nodeSelector` is load-bearing and looks like a bug.** RKE2 labels control planes `node-role.kubernetes.io/control-plane: "true"`; Talos uses `""`. | The selector matches the **empty string**, and that is the only thing keeping the shim off the RKE2 servers. "Fixing" it to an existence-based affinity deploys it onto RKE2 control planes, where it fights `rke2-server` for `:9345` and crashloops. Reproduced accidentally. | ✅ Documented; keep the empty-string match and comment it. |

## ✅ Verified working — the reasons this is viable at all

| Finding | Evidence |
|---|---|
| 🤝 Talos and RKE2 control planes **share one etcd and one cluster** | 4 members, all voting; both API servers serving; bidirectional reads/writes |
| 📥 Talos imports RKE2's PKI wholesale | `talosctl gen secrets --from-kubernetes-pki`, with a 2-cert CA bundle |
| 🔁 **Workers migrate without an OS rebuild** | drain → wipe `/var/lib/rancher/rke2/agent` → repoint `server:` → restart |
| 🧹 RKE2 CPs decommission cleanly | etcd 4 → 3; RKE2 removed only its own member, Talos untouched |
| 🚫 **Zero control-plane downtime** | quorum never at risk; an API server always serving |
| 🔒 RKE2 configuration never modified | `encryption-config.json` byte-identical to backup afterwards |
| 🔑 **Node passwords are byte-compatible in BOTH directions** | Deleted the secret, re-registered against the shim, then pointed the agent at a real `rke2-server`: it accepted the shim-authored scrypt hash unchanged and the node stayed `Ready`. The reverse was already proven. **A mixed VIP pool is therefore safe.** |
| 🔀 Agents fan out a tunnel to **every** supervisor | Not failover — the agent dials `wss://<each>:9345/v1-rke2/connect` concurrently, and real `rke2-server`s accept the migrated worker's tunnel (`Handling backend connection request`). |
| 👁️ Migrated workers are reachable from **both** control planes | `logs` and `exec` verified through an RKE2 API server *and* the Talos one, against a kubelet whose serving cert, client cert and tunnel all came from the shim. |
| ♻️ An adopted Talos CP **survives reboot** | etcd rejoined from its data dir with the same member ID and cluster ID; quorum never dipped; the shim rescheduled itself. |
| 🛟 The shim is **not** a single point of failure | Taken down mid-flight: every node stayed `Ready`, and an agent restarted *while its configured server was dead* still bootstrapped — it falls back to the real `rke2-server`s in its cached pool. Only a first-ever bootstrap pointed solely at the shim would block. |
| ➕ A **second** Talos control plane joins the same way | Driven entirely by [`adopt.sh`](../examples/adopt-rke2-cluster/adopt.sh): learner added, config applied, `Ready` at t+180s, 4 etcd members. The shim DaemonSet scheduled itself onto it unprompted. |
| 🧹 Decommissioning is scriptable and safe | RKE2 CP removed with the driver: etcd 4 → 3, RKE2 removed only its own member, both Talos members untouched, no downtime. |
| 🎈 **The control-plane VIP hands over to Talos in under a second** | kube-vip on both distributions sharing one lease: **~0.7 s** of VIP outage measured (7 lost pings at 100 ms), symmetric in both directions. See [control-plane-vip.md](control-plane-vip.md). |
| 🧬 kube-vip needs **no** special treatment on Talos | Unlike Cilium (#3), it starts with just `NET_ADMIN`, `NET_RAW`, `SYS_TIME` — first try, both Talos control planes. |

## The honest summary

There is no technical blocker left. What remains is **ownership**: you take on an
undocumented protocol (#2) and a component holding a CA key (#1), in exchange for
replacing your control planes without downtime and without rebuilding workers.

If that trade is acceptable, the three things that most reduce risk are:

1. **Run [`preflight.sh`](../examples/adopt-rke2-cluster/preflight.sh) and let it
   generate the config.** Every parameter it checks is one Talos would otherwise
   default to something plausible and wrong. It refuses to render on failure.
2. **Keep the coexistence window short** — it bounds #4, #6 and #2 simultaneously.
3. **Do the Cilium change (#3) as its own deliberate step**, verified, before any
   Talos node exists.

A note on how this register is maintained: item #4 previously claimed RKE2 API
servers could not reach migrated workers, and called it unfixable. That was
**wrong** — it was diagnosed against a kubelet still holding a serving cert
issued before the dual-CA fix landed. Re-testing on a clean re-registration
disproved it. Findings here are only as good as their last re-test.
