# Architecture

## The problem in one picture

An `rke2 agent` will not use Kubernetes' standard kubelet TLS bootstrap. It
fetches its identity from an rke2 server's supervisor on port 9345 and nowhere
else. A Talos control plane has no such thing.

```mermaid
flowchart LR
    subgraph without["Without the shim"]
        A1["rke2 agent"] -. "9345: connection refused" .-> T1["Talos control plane<br/>(no supervisor)"]
    end
    subgraph with["With the shim"]
        A2["rke2 agent"] -- "9345 supervisor" --> S["rke2-supervisor-shim"]
        S -- "signs with cluster CA" --> T2["Talos control plane"]
        A2 -- "6443 ordinary Kubernetes" --> T2
    end
```

`rke2 server` cannot be reduced to a supervisor: its apiserver, controller
manager and scheduler are **static pods run by its own kubelet and containerd**.
Unlike k3s — where they are goroutines in one process, which is why k3s has
`--disable-agent` and RKE2 has no equivalent — you cannot run "just the
supervisor" part.

## Deployment topology

The shim runs **on** the control-plane node with `hostNetwork`, because the
configured `server:` URL is only a seed. After bootstrap the agent builds a
server pool from `/v1-rke2/apiservers`, **substituting port 9345 into each
apiserver address**, and dials those. It therefore assumes every apiserver also
runs a supervisor — so a control-plane node without one becomes a dead backend.
Co-location is a protocol requirement, not a preference.

```mermaid
flowchart TB
    subgraph cp["Talos control-plane node · 10.0.0.245"]
        direction TB
        API["kube-apiserver :6443"]
        ETCD[("etcd")]
        SHIM["rke2-supervisor-shim<br/>hostNetwork :9345 · metrics :9346"]
        API --- ETCD
    end

    subgraph w1["Debian worker (plain kubelet)"]
        K1["kubelet + containerd"]
    end
    subgraph w2["Debian worker (stock rke2 agent)"]
        K2["rke2 agent<br/>own kubelet + containerd"]
    end

    K2 -- "① bootstrap 9345" --> SHIM
    SHIM -- "signs with the Talos cluster CA" --> SHIM
    K2 -- "② normal traffic 6443" --> API
    K1 -- "kubeadm-style bootstrap token" --> API

    style SHIM fill:#2d6cdf,color:#fff
```

The Talos image is never modified: no system extensions, no custom installer.
The shim is an ordinary workload; everything else is machine config.

## Bootstrap sequence

Reverse-engineered by proxying a real agent through a logging MITM to a real
rke2 server. Full details in [protocol.md](protocol.md).

```mermaid
sequenceDiagram
    participant A as rke2 agent
    participant S as shim :9345
    participant K as kube-apiserver

    A->>S: GET /cacerts (unauthenticated)
    S-->>A: Talos cluster CA (pinned by the agent)

    Note over A,S: all later calls: Basic auth, username literally "node"

    A->>S: GET /v1-rke2/config
    S-->>A: captured rke2 config, cluster values overridden
    A->>S: GET /v1-rke2/{client,server}-ca.crt
    S-->>A: Talos-native: same CA for both<br/>adopted RKE2: two DIFFERENT CAs

    Note over A,S: POST, not GET. Body is a DER CSR. No private key ever moves.

    A->>S: POST serving-kubelet.crt + Rke2-Node-{Name,Password,Ip}
    S->>S: verify node password (TOFU, scrypt)
    S-->>A: CN=<node> + SANs, signed by cluster CA
    A->>S: POST client-kubelet.crt
    S-->>A: O=system:nodes, CN=system:node:<node>
    A->>S: POST client-kube-proxy.crt (no node headers)
    A->>S: POST client-rke2-controller.crt (no node headers)

    A->>K: register Node using client-kubelet cert
    K-->>A: accepted — Node authorizer recognises the identity

    Note over A,S: the agent now builds a server pool from /v1-rke2/apiservers,<br/>substituting :9345, and dials a tunnel to EVERY member
    A->>S: WSS /v1-rke2/connect (mTLS, no Authorization header)
```

**The load-bearing fact** is that fourth exchange. `O=system:nodes,
CN=system:node:<node>` is exactly the identity the Kubernetes Node authorizer
expects. Sign that CSR with the Talos cluster CA and the agent is an ordinary,
fully legitimate member of the cluster. Everything else is plumbing around that.

## Trust chain

There are **two** shapes here, and conflating them is the single most expensive
mistake in this project.

### A Talos-native cluster: one CA

Talos keeps a single cluster CA where rke2 keeps three. Collapsing them is safe
*here* because nothing in the cluster was issued by anyone else — what matters is
that the kubelet's client certificate chains to the CA the apiserver trusts.

```mermaid
flowchart TD
    CA["Talos Kubernetes cluster CA<br/>ECDSA P-256 · 10 years"]
    CA --> APISRV["kube-apiserver certs<br/>(managed by Talos)"]
    CA --> SHIMC["shim serving cert<br/>self-issued, 1 year, auto-rotated"]
    CA --> SK["serving-kubelet<br/>CN=node · serverAuth"]
    CA --> CK["client-kubelet<br/>O=system:nodes<br/>CN=system:node:node"]
    CA --> KP["client-kube-proxy<br/>CN=system:kube-proxy"]
    CA --> RC["client-rke2-controller<br/>CN=system:rke2-controller"]

    SK -.->|"1 year, renewed on agent restart"| SK
    style CA fill:#2d6cdf,color:#fff
```

### An adopted RKE2 cluster: two signers, and they are not interchangeable

Existing rke2 agents already pinned `server-ca`, and existing RKE2 apiservers
already trust only `client-ca` for clients. Collapsing them here breaks live
nodes. This is why the shim takes `--serving-ca-cert/--serving-ca-key` as a
**separate** signer from its default CA:

```mermaid
flowchart TD
    SCA["rke2-server-ca<br/><i>(first in the Talos bundle = the signing key)</i>"]
    CCA["rke2-client-ca<br/><i>(in the bundle for trust only)</i>"]

    SCA --> TAPI["Talos kube-apiserver<br/>serving cert"]
    SCA --> SHIMC["shim TLS on :9345<br/>agents pinned this from /cacerts"]
    SCA --> SK["serving-kubelet<br/>RKE2 apiservers verify against server-ca"]
    SCA -.->|"unavoidable side effect"| AKC["Talos apiserver-kubelet-client<br/>❌ RKE2 kubelets reject it → 401"]

    CCA --> CK["client-kubelet<br/>O=system:nodes"]
    CCA --> KP["client-kube-proxy"]
    CCA --> RC["client-rke2-controller"]

    style SCA fill:#2d6cdf,color:#fff
    style CCA fill:#7c3aed,color:#fff
    style AKC fill:#fecaca
```

The dotted edge is the one cost of that ordering: Talos signs its own
`apiserver-kubelet-client` cert with the same key, and RKE2 kubelets validate
client certs against `client-ca` only. Reversing the bundle does not fix it, it
breaks the agents' pin instead. See [kubelet-egress.md](kubelet-egress.md) and
[certificates.md](certificates.md).

The shim holds a CA private key — see [security.md](security.md) for why that
is unavoidable and how it is contained.

## Component map

```mermaid
flowchart LR
    subgraph proc["rke2-supervisor-shim process"]
        SUP["internal/supervisor<br/>routes · auth · agent config"]
        PKI["internal/pki<br/>CSR validation · signing"]
        NP["internal/nodepassword<br/>scrypt · Secret store"]
        CERTS["internal/certs<br/>self-managed serving cert"]
        EXP["internal/expiry<br/>expiry events · metrics"]
        SUP --> PKI
        SUP --> NP
        SUP --> EXP
        CERTS --> PKI
    end
    NP <--> KS[("kube-system Secrets<br/>node.node-password.rke2")]
    EXP --> EV["Kubernetes Events<br/>CertificateExpirationWarning"]
    EXP --> PROM["/metrics :9346"]
```

## Design decisions worth knowing

**The agent config is a captured real response, not hand-written structs.**
`/v1-rke2/config` has 65 keys. The shim loads a JSON document captured from a
real rke2 server and overrides about ten. When RKE2 adds a field, agents get
what the real server sent instead of a zero value. See
[compatibility.md](compatibility.md).

**Unknown endpoints fail loudly.** A 501 plus an ERROR log naming the path, so
protocol drift announces itself rather than degrading quietly.

**Certificate subjects are chosen by the endpoint, never taken from the CSR.**
An agent cannot request an arbitrary identity by crafting its request.

**Node passwords are Secrets, not local state.** Same name, namespace and hash
format as rke2, so they survive rescheduling and an operator can clear one with
familiar tooling. The hash is byte-compatible in **both** directions — verified
by having the shim author one and a stock `rke2-server` accept it — so shims and
real servers can sit behind the same VIP.

**The DaemonSet is pinned by an empty-string label match.** Talos labels control
planes `node-role.kubernetes.io/control-plane: ""`, RKE2 labels them `"true"`.
Selecting on `""` is what keeps the shim off the RKE2 servers, where
`rke2-server` already owns `:9345`. It reads like a typo and is not; see the
comment in `deploy/shim.yaml`.

**The shim is deliberately not load-bearing for a running node.** Agents keep a
persisted server pool and fan their tunnels out to all of it, so an agent that
has bootstrapped once survives the shim being down — verified by restarting one
while its configured server was dead. Only a node's *first* bootstrap needs the
shim specifically, and only if it is the sole supervisor it knows.
