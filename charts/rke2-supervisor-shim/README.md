# rke2-supervisor-shim chart

```bash
# 1. Namespace, privileged for PodSecurity (the shim is hostNetwork, which
#    "baseline" forbids). Created here because the Secrets must exist first.
kubectl create namespace rke2-shim
kubectl label namespace rke2-shim \
  pod-security.kubernetes.io/{enforce,audit,warn}=privileged

# 2. Out-of-band secrets (never in the chart: one of them is a private key)
kubectl -n rke2-shim create secret generic rke2-shim-pki \
  --from-file=cluster-ca.crt=./cluster-ca.crt \
  --from-file=cluster-ca.key=./cluster-ca.key
kubectl -n rke2-shim create secret generic rke2-shim-token \
  --from-literal=token="$(openssl rand -hex 24)"

# 3. Install, supplying a /v1-rke2/config captured from a REAL rke2 server
helm install shim charts/rke2-supervisor-shim --namespace rke2-shim \
  --set namespace.create=false \
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
| `image.tag` / `image.digest` | `""` / `""` | tag defaults to `appVersion`; `latest` is rejected by the schema. Set `digest` to run exactly the image you verified with `cosign verify` or `gh attestation verify`. |
| `metrics.enabled` | `true` | `false` binds the (always-on) metrics listener to `127.0.0.1`. Probes use the supervisor port either way. |
| `secretsAdmissionPolicy.enabled` | `auto` | a ValidatingAdmissionPolicy limiting the shim's Secret writes in `kube-system` to `*.node-password.rke2`, and forbidding changes to a stored hash. `auto` installs it when the cluster serves `admissionregistration.k8s.io/v1` VAP (Kubernetes ≥ 1.30). |
| `rbac.create` | `true` | `false` now disables every RBAC object, including the `system:rke2-controller` binding. |

`values.schema.json` rejects malformed values at install time: ports, CIDRs,
IPs, DNS names, Secret keys, and file names containing `/` or `..`.

**RBAC on the `rke2-shim` namespace is control-plane-grade.** The PKI Secret
holds the cluster CA private key; anyone who can create pods, exec, or read
Secrets there can sign any Kubernetes identity.

The join token is mounted as a file (`--token-file`), not an environment
variable. This needs an image that has the `--token-file` flag (0.1.0 or later).

It installs a **DaemonSet** over control-plane nodes, never a Deployment: rke2
assumes a supervisor beside every apiserver.
