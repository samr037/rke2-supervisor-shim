# rke2-supervisor-shim chart

```bash
# 1. Out-of-band secrets (never in the chart: one of them is a private key)
kubectl create namespace rke2-shim
kubectl -n rke2-shim create secret generic rke2-shim-pki \
  --from-file=cluster-ca.crt=./cluster-ca.crt \
  --from-file=cluster-ca.key=./cluster-ca.key
kubectl -n rke2-shim create secret generic rke2-shim-token \
  --from-literal=token="$(openssl rand -hex 24)"

# 2. Install, supplying a /v1-rke2/config captured from a REAL rke2 server
helm install shim charts/rke2-supervisor-shim \
  --set-file agentConfig.contents=conformance/testdata/v1.31.8+rke2r1/config.json
```

## Why some things are not templated

**The PKI Secret.** It contains the cluster CA *private key*. A chart is
something you commit; a private key is not. Create it out of band and reference
it with `pki.existingSecret`.

**The agent config.** It is a payload captured from a real rke2 server of the
version your agents run, not something to hand-write — see
[../../docs/compatibility.md](../../docs/compatibility.md). The chart refuses to
install without it rather than shipping a plausible-looking default.

## Notable values

| Key | Default | Why it matters |
| --- | --- | --- |
| `cluster.apiServers` | `[]` | empty means control-plane nodes are discovered and refreshed. Pin only if you must — every address listed must run a shim. |
| `servingCert.certFile/keyFile` | `""` | empty means the shim mints and rotates its own from the cluster CA, with SANs per node. Required for multi-CP unless you manage a cert with every node's SANs. |
| `namespace.create` | `true` | the namespace needs `pod-security.kubernetes.io/enforce: privileged`; `helm --create-namespace` cannot set labels. |
| `networkPolicy.enabled` | `false` | it would not protect the shim (hostNetwork). See [../../docs/network-security.md](../../docs/network-security.md). |

It installs a **DaemonSet** over control-plane nodes, never a Deployment: rke2
assumes a supervisor beside every apiserver.
