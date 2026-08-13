# kube-vip through an RKE2 → Talos migration

Working manifests for the control-plane VIP, verified end to end on a live mixed
cluster (1 RKE2 control plane + 2 Talos control planes, one etcd). The reasoning
is in [docs/control-plane-vip.md](../../docs/control-plane-vip.md).

Replace `<VIP>` with your address, and check `vip_interface` on **both**
distributions — they usually differ (`eth0` on a Debian-based RKE2 node,
`ens18`/`enp0s…` on Talos, even on the same hypervisor with the same NIC).

## Order of operations

```bash
kubectl apply -f 00-rbac.yaml
kubectl apply -f 10-daemonset-rke2.yaml      # BEFORE adopting any Talos node
# ... adopt Talos control planes, migrate every worker ...
kubectl apply -f 20-daemonset-talos.yaml     # only once workers are migrated
kubectl -n kube-system delete ds kube-vip-rke2
```

Both DaemonSets share the lease `plndr-cp-lock` and the same VIP, so the last
two steps are a leader transition rather than a stop-then-start: the address is
never unowned. **Measured outage: ~0.7 s.**

## Why two DaemonSets

| | RKE2 | Talos |
|---|---|---|
| `node-role.kubernetes.io/control-plane` | `"true"` | `""` |
| LAN interface | `eth0` | `ens18` |
| control-plane taint | none | `NoSchedule` |

Selecting on the label **value** is what pins the VIP to one distribution. Note
kube-vip's own generated manifest uses `operator: Exists`, which matches both —
so if you already run kube-vip, **add the `nodeSelector` before the first Talos
node joins**, or the VIP will start answering from an API server that cannot
reach your un-migrated kubelets.

## Two things that are not obvious

- `KUBERNETES_SERVICE_HOST=127.0.0.1` / `PORT=6443` — the component providing the
  API VIP must not depend on service routing to elect itself. Do not use
  `127.0.0.1:7445`; KubePrism is disabled during coexistence.
- Capabilities: `NET_ADMIN`, `NET_RAW`, `SYS_TIME` are enough on Talos. This is
  **not** like Cilium, which needs its whole bounding set enumerated.

## Use the RKE2 admin kubeconfig

It is the only credential that works against **both** control planes. The Talos
admin cert is signed by `server-ca`, and RKE2 API servers trust `client-ca`
only, so they reject it. Point the RKE2 kubeconfig at the VIP and it keeps
working across the handover unchanged.
