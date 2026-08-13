# The RKE2 supervisor protocol (as spoken by v1.35.7+rke2r1)

Reverse-engineered empirically, not from source: a real `rke2 agent` was proxied
through `shim/mitm.py` to a throwaway real `rke2 server` acting as a reference
oracle, and the full transcript captured (`shim/mitm.log`).

This is an **internal, undocumented protocol**. It is stable enough to implement
against, but Rancher owes you no compatibility. Re-capture it when you upgrade.

## Transport

* TLS on port **9345**.
* The agent pins trust to whatever `GET /cacerts` returns on first contact
  (cached at `/var/lib/rancher/rke2/agent/server-ca.crt`). The serving cert must
  chain to it. Our shim serves a cert minted from the Talos cluster CA and
  returns that CA from `/cacerts`, so the chain validates for real.
* After bootstrap the agent talks to its own local load balancer on
  `127.0.0.1:6444`, which forwards to the supervisor — so requests arrive with
  `Host: 127.0.0.1:6444`.
* **The agent maintains a server pool, and the `server:` in its config is only a
  seed.** It learns the rest from `/v1-rke2/apiservers` and persists them to
  `/var/lib/rancher/rke2/agent/etc/rke2-agent-load-balancer.json`:

  ```json
  { "ServerURL": "https://<seed>:9345",
    "ServerAddresses": ["<shim>:9345", "<rke2-cp-1>:9345", "<rke2-cp-2>:9345"] }
  ```

  Two consequences that are easy to get wrong. First, the pool is derived by
  taking the **apiserver** list and substituting port 9345 — the agent *assumes
  every apiserver also runs a supervisor*, so a control-plane node without one
  is added as a dead backend. Second, an agent that has bootstrapped once will
  fall back to any member of that pool, which is why the shim being down does
  not strand an existing node.
* **The tunnel is a fan-out, not a failover.** The agent dials
  `wss://<addr>:9345/v1-rke2/connect` to **every** server in the pool
  concurrently and keeps them all open:

  ```
  Connecting to proxy  url="wss://<shim>:9345/v1-rke2/connect"
  Connecting to proxy  url="wss://<rke2-cp-1>:9345/v1-rke2/connect"
  Connecting to proxy  url="wss://<rke2-cp-2>:9345/v1-rke2/connect"
  ```

  A stock `rke2-server` accepts a shim-bootstrapped agent's tunnel
  (`Handling backend connection request [<node>]`), so a migrated worker stays
  reachable through every RKE2 apiserver's egress selector as well as the
  shim's. This is what makes mixed-supervisor operation safe — see
  [kubelet-egress.md](kubelet-egress.md).

## Authentication

Two independent layers:

| Layer | Mechanism |
| --- | --- |
| cluster | HTTP Basic, username **literally `node`**, password = cluster token |
| node | headers `Rke2-Node-Name`, `Rke2-Node-Password`, `Rke2-Node-Ip` |

The node password is trust-on-first-use: the server records it on first
registration (real rke2 stores it as a `<node>.node-password.rke2` Secret) and
rejects a mismatch afterwards. `Rke2-Node-Ip` is comma-separated and includes
IPv6.

Header names are `Rke2-`-prefixed, **not** `K3s-` — RKE2 rebrands them from the
vendored k3s code.

## Endpoints

Observed bootstrap order:

```
GET  /cacerts                              unauthenticated
GET  /v1-rke2/config                       agent configuration (JSON, 65 keys)
GET  /v1-rke2/client-ca.crt                rke2-client-ca  (PEM)
GET  /v1-rke2/server-ca.crt                rke2-server-ca  (PEM)
POST /v1-rke2/serving-kubelet.crt          node-scoped
POST /v1-rke2/client-kubelet.crt           node-scoped
POST /v1-rke2/client-kube-proxy.crt        cluster-wide
POST /v1-rke2/client-rke2-controller.crt   cluster-wide
GET  /v1-rke2/readyz                       200 "ok"
GET  /v1-rke2/apiservers                   ["<ip>:6443", ...]
WSS  /v1-rke2/connect                      remotedialer tunnel (see below)
```

### Certificate issuance — the important part

The cert endpoints are **POST, not GET** (a GET returns
`400 "node name not set"`, which is a misleading error). The request body is a
**DER-encoded CSR**, ~190 bytes. The response is `text/plain`: the **leaf
certificate followed by the issuing CA**, PEM — and **no private key**. The
agent generates and keeps its own key.

That matters a lot: a shim only ever needs to *sign*. It never holds or
transmits node private keys.

Subjects the reference server issues, which a shim must reproduce exactly:

| Endpoint | Subject | EKU |
| --- | --- | --- |
| `serving-kubelet.crt` | `CN=<node>` + SANs | serverAuth |
| `client-kubelet.crt` | `O=system:nodes, CN=system:node:<node>` | clientAuth |
| `client-kube-proxy.crt` | `CN=system:kube-proxy` | clientAuth |
| `client-rke2-controller.crt` | `CN=system:rke2-controller` | clientAuth |

`serving-kubelet` SANs: `DNS:<node>`, `DNS:localhost`, `IP:127.0.0.1`, `IP:::1`,
plus every address from `Rke2-Node-Ip`.

**`O=system:nodes, CN=system:node:<node>` is precisely the identity the
Kubernetes Node authorizer expects.** Sign that CSR with the Talos cluster CA
and the resulting agent is an ordinary, fully legitimate node of the Talos
cluster. That single fact is what makes the whole approach work.

### Gotcha: only kubelet certs are node-scoped

`client-kube-proxy.crt` and `client-rke2-controller.crt` are requested with
**no `Rke2-Node-*` headers at all** — they are cluster identities. Demanding a
node name for them makes the agent loop forever on
`Waiting to retrieve agent configuration; server is not ready: ... node name not set`.

### `/v1-rke2/config`

65 keys of rke2's internal `config.Control`. The shim starts from a captured
real response (`shim/reference-config.json`) and overrides the cluster facts:

```
ClusterDNS / ClusterDNSs      10.96.0.10          (Talos default, not rke2's 10.43.0.10)
ClusterIPRange(s)             10.244.0.0/16       {"IP": ..., "Mask": base64(4-byte netmask)}
ServiceIPRange(s)             10.96.0.0/12
FlannelBackend                "none"              Talos already runs flannel cluster-wide
DisableKubeProxy              true                Talos already runs kube-proxy cluster-wide
DisableCCM / NPC / ServiceLB / HelmController  true
```

## What a Talos-backed shim must add on the cluster side

* **RBAC for `system:rke2-controller`** (`shim/rke2-controller-rbac.yaml`). A
  real rke2 server creates this; Talos has never heard of the identity, so the
  agent gets 403s on node labelling without it.
* **One CA where rke2 expects two.** rke2 keeps separate `client-ca` and
  `server-ca`; Talos has a single cluster CA. Returning it for both endpoints
  works, because what actually matters is that the kubelet *client* cert chains
  to the CA the apiserver trusts.

## Where the shim must run

**rke2 assumes the supervisor is co-located with every apiserver.** After
bootstrap the agent stops using the configured `server:` URL for the tunnel and
dials `wss://<apiserver-ip>:9345/v1-rke2/connect`, taking the address from
`/v1-rke2/apiservers`.

So the shim has to listen on the control-plane node's own address. It runs as a
Deployment with `hostNetwork: true` and a control-plane nodeSelector
(`shim/deploy/deployment.yaml`), binding `0.0.0.0:9345` on the Talos node —
without touching the Talos image. Production agents then use an entirely stock
config:

```yaml
server: https://<control-plane-ip>:9345
token:  <token>
```

Note `hostNetwork` is forbidden by PodSecurity `baseline`, which Talos enforces,
so the shim's namespace is labelled `enforce: privileged`.

## Still open: the remotedialer tunnel

The tunnel handshake is a **bare websocket upgrade carrying no `Authorization`
header at all**:

```
GET /v1-rke2/connect
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Key: ...
Sec-WebSocket-Version: 13
```

That means rke2 authenticates it by **mTLS client certificate** — the agent
presents the `client-rke2-controller` / kubelet cert it was issued, and the
server identifies the node from the TLS peer certificate. A shim must therefore
request client certs on the TLS listener (`ssl.CERT_OPTIONAL` with the cluster
CA as verify root) and derive the node identity from the peer cert CN, rather
than looking for a header.

Setting `EgressSelectorMode: "disabled"` in the config payload does **not**
suppress it — the agent connects unconditionally.

Not implementing it is currently harmless: the node is `Ready` and pod
networking, services, DNS, `kubectl logs` and `kubectl exec` all pass, because a
Talos apiserver reaches kubelets directly over the LAN rather than through the
tunnel. The cost is a reconnect error every ~3s in the agent log.

To close it properly: terminate the websocket and speak
[rancher/remotedialer](https://github.com/rancher/remotedialer) session
framing. That is the point at which rewriting the shim in Go — importing
`remotedialer` directly instead of reimplementing it — becomes the cheaper
option.
