# Certificates: lifetimes, renewal, and CA rotation

Three separate certificate lifecycles meet in this shim. They fail in different
ways and on very different timescales, so treat them separately.

| Certificate | Issued by | TTL | Renewed by |
| --- | --- | --- | --- |
| agent `serving-kubelet`, `client-kubelet`, `client-kube-proxy`, `client-rke2-controller` | the shim, from the cluster CA | 365 d | **restarting `rke2-agent`** |
| the shim's own serving certificate | the shim, from the cluster CA | 365 d | itself, automatically |
| the Talos Kubernetes cluster CA | Talos | 10 y | `talosctl rotate-ca` (manual) |

Measured against a real rke2 v1.31.8 server: it issues 1-year agent certificates
and a 10-year CA. The shim matches both.

## Agent certificates

rke2 renews agent certificates **every time the agent starts**, and rotates them
automatically if they are expired or within 90 days of expiry.

The important property, and the reason expiry here is unpleasant rather than
catastrophic:

> An agent re-bootstraps with the **join token and its node password**, not with
> its existing certificate.

So a node whose certificates expired completely still recovers with:

```bash
systemctl restart rke2-agent
```

There is no lockout, and no manual signing step. This holds against the shim
because the certificate endpoints authenticate with HTTP Basic (`node:<token>`)
plus the `Rke2-Node-*` headers — never with the client certificate being
replaced.

The node password behind that re-bootstrap is **byte-compatible in both
directions**, which is what makes a mixed pool of shims and real `rke2-server`s
safe. Verified by deleting the `<node>.node-password.rke2` Secret, re-registering
through the shim so the *shim* authored the scrypt hash, then pointing the agent
at a stock `rke2-server`: it accepted the hash unchanged and the node stayed
`Ready`. The reverse — the shim verifying an RKE2-authored hash — happens on
every migration.

### Which CA signs what, and the one thing it costs

Adopting an RKE2 cluster means importing **two** CAs into a system that signs
with **one**. Talos signs every cluster certificate with the first key in the
bundle, and the bundle is `server-ca`-first. That ordering is deliberate:

| Certificate | Signed by | Because |
|---|---|---|
| the Talos apiserver's serving cert | `server-ca` | rke2 agents pinned `server-ca` from `/cacerts` on first contact |
| the shim's TLS on `:9345` | `server-ca` | same pin |
| `serving-kubelet` (via `--serving-ca-*`) | `server-ca` | RKE2 apiservers verify kubelet serving certs against it |
| `client-kubelet`, `client-kube-proxy`, `client-rke2-controller` | `client-ca` | RKE2 apiservers' `--client-ca-file` is `client-ca` only |

The cost is one thing the bundle order cannot satisfy: Talos also signs its own
`apiserver-kubelet-client` cert with `server-ca`, and RKE2 kubelets validate
client certs against `client-ca`. So the **Talos apiserver gets `401` against
un-migrated RKE2 kubelets**. Flipping the order does not fix it — it breaks the
agents' pin instead. The gap shrinks as workers migrate; see
[kubelet-egress.md](kubelet-egress.md).

### Which admin kubeconfig to carry

The same asymmetry decides which credential you can use, and it is not the one
most people would reach for:

| kubeconfig | vs RKE2 API servers | vs Talos API servers |
|---|---|---|
| **RKE2 admin** — `/etc/rancher/rke2/rke2.yaml` | ✅ | ✅ |
| Talos admin — `talosctl kubeconfig` | ❌ `You must be logged in to the server` | ✅ |

`talosctl kubeconfig` mints its client cert with the bundle's first key —
`server-ca` — and RKE2 API servers set `--client-ca-file` to `client-ca` only, so
they reject it. Talos trusts the whole bundle and accepts either.

**Carry the RKE2 admin kubeconfig for the entire migration.** Pointed at the
control-plane VIP it keeps working unchanged across the handover to Talos, so
there is no moment where operators need to swap credentials.

### Expiry warnings

A real rke2 server emits a Kubernetes `Warning` event with reason
`CertificateExpirationWarning` when a node certificate is within 120 days of
expiring. That event comes from the server, so replacing the server with a shim
removed it — a node left running for twelve months could reach expiry silently.

The shim now restores it. On every issuance it records the expiry as an
annotation on the node's existing password Secret:

```
kube-system/<node>.node-password.rke2
  metadata.annotations:
    rke2-supervisor-shim/not-after.client-kubelet:  2027-08-12T15:00:57Z
    rke2-supervisor-shim/not-after.serving-kubelet: 2027-08-12T15:00:57Z
```

An hourly scan emits the same event, with the same reason, so existing alerting
keeps working:

```bash
kubectl get events --field-selector reason=CertificateExpirationWarning -A
```

### Metrics

Prometheus metrics are served on `:9346/metrics` (host port, since the pod runs
with `hostNetwork`):

| Metric | Meaning |
| --- | --- |
| `rke2_shim_certificate_expiry_seconds{node,kind}` | expiry of each issued node certificate |
| `rke2_shim_certificates_expiring_soon` | how many are inside the 120-day window |
| `rke2_shim_certificates_issued_total{kind}` | issuance counter |
| `rke2_shim_serving_certificate_expiry_seconds` | the shim's own certificate |

A reasonable alert:

```promql
rke2_shim_certificate_expiry_seconds - time() < 30 * 24 * 3600
```

## The shim's serving certificate

Originally this was minted by hand with `openssl` and pinned to specific IPs —
fragile, because adding or re-addressing a control-plane node silently produced
wrong SANs.

It is now self-managed, mirroring what rke2 does with `dynamiclistener`: issued
from the cluster CA at startup, with SANs collected from `NODE_IP` (downward
API), every address on the host, the node name, and anything in `--extra-sans`.
It is reissued automatically once it is within 30 days of expiry, swapped in via
`tls.Config.GetCertificate` so no connection is dropped and no restart is
needed.

Supplying `--tls-cert` and `--tls-key` still overrides this if you would rather
manage it externally (cert-manager, for instance).

## Cluster CA rotation — the one to plan for

The Talos Kubernetes CA is valid for ten years, so this is not a calendar
problem. It is a **compromise-response** problem: `talosctl rotate-ca` is what
you run on the worst day, which is exactly when you do not want to be
improvising.

When the cluster CA changes, four things break at once:

1. the shim's `rke2-shim-pki` Secret still holds the **old** CA and key;
2. the shim's serving certificate is signed by the old CA;
3. every agent has the old CA cached at
   `/var/lib/rancher/rke2/agent/server-ca.crt` and will reject the new one;
4. every client certificate the shim ever issued is no longer trusted by the
   apiserver.

### Runbook

Do the control plane first, then the fleet. Agents keep running throughout —
existing workloads are not interrupted — but they cannot re-register until their
step completes.

```bash
# 1. Rotate the Talos CA (follow the Talos procedure for your topology)
talosctl --nodes <cp> rotate-ca --kubernetes

# 2. Re-extract the new cluster CA and replace the shim's Secret
kubectl -n rke2-shim create secret generic rke2-shim-pki \
  --from-file=cluster-ca.crt=./cluster-ca.crt \
  --from-file=cluster-ca.key=./cluster-ca.key \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Restart the shim. It mints a new serving certificate from the new CA.
kubectl -n rke2-shim rollout restart deploy/rke2-supervisor-shim

# 4. On EVERY rke2 worker: drop the cached CA and re-bootstrap.
#    Without this the agent rejects the shim's new TLS certificate.
systemctl stop rke2-agent
rm -rf /var/lib/rancher/rke2/agent
systemctl start rke2-agent
```

Step 4 is a full-fleet rolling operation. Drain each node first if the workloads
warrant it.

Note that `/etc/rancher/node/password` is **not** removed in step 4, so the node
keeps its identity and the stored password Secret still matches. If you do wipe
it, you must also delete the Secret or the node gets `409 Conflict`:

```bash
kubectl -n kube-system delete secret <node>.node-password.rke2
```

### Not automated, deliberately

CA rotation is rare, destructive, and needs judgement about ordering and
draining. Automating it would mean building something that reboots your whole
fleet, tested roughly never. A documented runbook you can read under pressure is
worth more. Revisit that if you ever rotate on a schedule rather than in
response to an incident.
