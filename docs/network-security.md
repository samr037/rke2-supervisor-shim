# Network security

## The problem NetworkPolicy cannot solve

The shim runs with `hostNetwork: true`, and that is not negotiable: after
bootstrap an rke2 agent dials `<apiserver-ip>:9345` for the tunnel, taking the
address from `/v1-rke2/apiservers`, so the supervisor must listen on the
control-plane node's own address.

**Kubernetes NetworkPolicy does not apply to hostNetwork pods.** Their traffic
reaches the node's network stack directly and never traverses the pod network,
so a `podSelector` policy for `:9345` would look like protection and provide
none. This is the single most important thing to understand here.

```mermaid
flowchart TB
    subgraph node["Control-plane node"]
        direction TB
        NFT["Talos ingress firewall<br/>(nftables, machine config)"]
        HOST["host network :9345 :9346 :6443 :50000"]
        subgraph pods["pod network"]
            NP["NetworkPolicy applies here"]
        end
        NFT --> HOST
        HOST -. "hostNetwork pods bypass<br/>the pod network entirely" .-> SHIM["rke2-supervisor-shim"]
    end
    EXT["everything else on the LAN"] --> NFT
    style NFT fill:#2d6cdf,color:#fff
    style NP stroke-dasharray: 4 4
```

So enforcement has to happen at the host. Three layers, in order of what
actually does the work:

| Layer | File | Applies to hostNetwork? |
| --- | --- | --- |
| Talos ingress firewall | `deploy/talos-ingress-firewall.yaml` | **yes** — the real control |
| Cilium host firewall | `deploy/cilium-host-policy.yaml` | yes, with `hostFirewall.enabled` **and** `policyCIDRMatchMode=nodes` |
| Kubernetes NetworkPolicy | `deploy/network-policy.yaml` | no — default-deny floor for other pods |

## Layer 1: the Talos ingress firewall

Talos drives nftables from machine config — no CNI involvement, no extra
components. This is the control to rely on.

### Port matrix for a control-plane node running the shim

Taken from `talosctl netstat --listening` on a live node, not from documentation.

| Port | Service | Who should reach it |
| --- | --- | --- |
| 50000/tcp | apid (`talosctl`) | management network only |
| 50001/tcp | trustd | cluster nodes |
| 6443/tcp | kube-apiserver | management + cluster nodes |
| 2379-2380/tcp | etcd | **control-plane peers only** |
| 10250/tcp | kubelet | cluster nodes |
| 10256/tcp | kube-proxy health | cluster nodes |
| **9345/tcp** | **shim supervisor** | **nodes allowed to join** |
| **9346/tcp** | **shim metrics** | **the scraper only** |
| 4789/udp | flannel VXLAN | cluster nodes (Cilium uses 8472) |

Everything else the node listens on — KubePrism 7445, scheduler 10259,
controller-manager 10257, kubelet healthz 10248, kube-proxy metrics 10249, host
DNS — binds to `127.0.0.1` or a link-local address and is unreachable from
outside regardless.

Why 9345 deserves a tight subnet: anything that can reach it **and** holds the
join token can enrol a node into your cluster. Why 9346 deserves one: the
metrics are unauthenticated and disclose node names and certificate expiry.

If nothing scrapes the shim, take `9346` off the network instead: the chart
binds it to `127.0.0.1` with `metrics.enabled=false`, and `--metrics-listen=""`
switches the listener off entirely. The chart's probes use `9345`, so neither
affects health checking.

### Applying it safely

A default action of `block` with one rule missing locks out `talosctl` **and**
`kubectl` at the same time.

> **`--mode=try` did NOT roll this back when we tested it.** The patch was
> applied with `--mode=try --timeout=6m`; long after the timeout the ten
> firewall documents were still present in the machine config and the rules were
> still enforcing. Talos' try-mode rollback appears not to cover *additional
> config documents* the way it covers edits to the `v1alpha1` document.
>
> **Do not rely on try-mode as your safety net for this patch.** Keep an
> independent path to the machine — the hypervisor console, or a second
> control-plane node you have not patched yet — before you apply.

```bash
talosctl patch mc -n <cp-ip> --patch @deploy/talos-ingress-firewall.yaml
```

Substitute `$CLUSTER_SUBNET`, `$WORKER_SUBNET`, `$MGMT_SUBNET`, `$MONITORING`
and `$CP1..3` first. Roll forward one node at a time and verify each before
moving on.

To remove the firewall again, re-apply a machine config without these documents:

```bash
talosctl apply-config -n <cp-ip> -f clusterconfig/<node>.yaml   # no firewall docs
```

### Verified on the maquette

Applied to a live control-plane node, with `$MONITORING` set to a single host:

```
NfTablesChain  ingress  filter  input  priority -140  policy drop   ← active

kubectl / talosctl                     still working
9345 from the rke2 worker              HTTP 200      (allowed)
9346 from the rke2 worker              blocked       (as intended)
9346 from the monitoring host          HTTP 200      (allowed)
rke2 pod -> ClusterIP + cluster DNS    PASS
```

Nothing in the cluster noticed. The rule set above is therefore known-complete
for this topology — add rules for anything else you run on the node.

## Layer 2: Cilium host firewall (optional)

Cilium is the one CNI that *can* police host traffic, via
`CiliumClusterwideNetworkPolicy` with a `nodeSelector` instead of an
`endpointSelector`. [`deploy/cilium-host-policy.yaml`](../deploy/cilium-host-policy.yaml)
expresses the port matrix above that way. It needs **two** non-default Cilium
settings:

```bash
helm upgrade cilium ... --set hostFirewall.enabled=true \
                        --set policyCIDRMatchMode=nodes
```

> 🛑 **Without `policyCIDRMatchMode=nodes` this policy locks the node out of its
> own cluster.** By default Cilium's `fromCIDR` never matches in-cluster nodes:
> traffic from another node carries the reserved `remote-node` identity, not a
> CIDR identity. Every rule that names node addresses — kubelets and agents
> reaching `6443` and `9345`, etcd peers, apiservers reaching `10250` — then
> matches nothing, and the host firewall drops it.

The previous version of the file hid that problem by allowing the `remote-node`
and `cluster` entities on **every** port, which opened `9345`, `9346`, etcd and
the kubelet to every pod in the cluster. The rewrite (2026-10-17 audit) has
explicit rules instead:

| Source | Ports |
| --- | --- |
| node / management CIDRs | 6443, 50000–50001, 9345, 10250, 10256 |
| the scraper's /32 | 9346 |
| control-plane /32s only | 2379–2380 (etcd) |
| `health`, `remote-node` entities | 4240/tcp and ICMP echo (cilium-health) |
| `remote-node` entity | 8472/udp (VXLAN; adjust for Geneve, native routing or WireGuard) |
| `cluster` entity (pods) | 6443 (the `kubernetes` Service), 53 (Talos host DNS, if forwarded) |
| metrics-server pods, by label | 10250 |

**Stage it in audit mode.** Put the host endpoint in policy audit mode
(`cilium-dbg endpoint config <host-ep-id> PolicyAuditMode=Enabled`), watch
`cilium-dbg monitor -t policy-verdict --related-to <host-ep-id>` for `audit`
verdicts until nothing legitimate shows up, and keep a second path to the
machine open before enforcing. The rewritten policy has **not** been applied to
a live cluster; the earlier one was not verified either.

Prefer the Talos firewall: it has no prerequisites and keeps enforcing if
Cilium is degraded or being upgraded. Treat Cilium host policy as defence in
depth, not a replacement.

## Layer 3: NetworkPolicy

`deploy/network-policy.yaml` sets a default-deny floor for the `rke2-shim`
namespace. It does **not** protect the shim. It exists so that any pod later
added to that namespace is closed by default, and so the intent is recorded
where a reviewer will look.

Its apiserver egress rule names the control-plane addresses on `6443`, not any
host on that port (which would let a pod there reach any other cluster's
apiserver). Most CNIs evaluate egress after the `kubernetes` Service is DNATed
to an apiserver endpoint, so node addresses are what must be listed; on Cilium,
`ipBlock` ignores node IPs unless `policyCIDRMatchMode=nodes` is set.

Do not mistake it for coverage of `:9345`.

## Worker-side considerations

The rke2 workers are ordinary mutable Linux hosts and are outside Talos'
firewall. Worth restricting there too:

| Port | Service | Who |
| --- | --- | --- |
| 10250/tcp | kubelet | control-plane nodes only |
| 10256/tcp | kube-proxy health | cluster nodes |
| 4789/udp | VXLAN | cluster nodes |
| 22/tcp | SSH | management network only |

Note the KubePrism shim (`worker/components/kubeprism-shim.sh` in the maquette
repo) binds `127.0.0.1:7445`, so it needs no rule.

## Threat model in one paragraph

The asset is the cluster CA private key, held in the shim pod. Reaching `:9345`
without the token gets you a CA certificate from `/cacerts` and a `401` for
everything else. Reaching it *with* the token lets you enrol a **new** node and
obtain the shared `system:rke2-controller` identity, which can relabel any Node
within the limits of its admission policy. It does not let you impersonate an
existing node: one with a password on record needs that password, and one
without (a Talos control plane, for instance) is refused with `409` (see
[security.md](security.md#1-takeover-of-nodes-that-never-enrolled--critical)).
Reaching `:9346` gets you node names and expiry dates. Reaching the pod itself, or `exec`ing into it, gets you the CA key
and therefore the cluster. Restrict `:9345` to the subnet whose machines are
allowed to be nodes, restrict `:9346` to the scraper, and treat RBAC on the
`rke2-shim` namespace as control-plane-grade.
