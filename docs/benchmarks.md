# Benchmarks — what the supervisor actually costs

Until now the shim had been exercised with exactly **one** worker. "Does it
survive 200 nodes bootstrapping after a power event" was an opinion. This puts
numbers on it.

Driven by [`hack/loadgen`](../hack/loadgen), which replays the real bootstrap
sequence — same endpoints, same Basic auth (`node:<token>`), same DER CSRs, same
`Rke2-Node-*` headers — so the latencies are what an agent experiences, not what
a server-side counter claims.

```bash
go run ./hack/loadgen -server https://<cp>:9345 -token <token> -nodes 20 -concurrency 16
```

## 📊 The headline: a one-line fix, 7.6× throughput

The first run said **10 req/s**, flat, no matter what we threw at it. That
number turned out to be a client-go default, not a property of the design.

| | before | after |
|---|---|---|
| throughput | 10.0 req/s | **76.3 req/s** |
| 20 nodes, concurrency 16 | 18.07 s | **2.36 s** |
| `client-kubelet` p50 | 6 400 ms | **680 ms** |
| `serving-kubelet` p50 | 7 513 ms | **1 036 ms** |

That is roughly **8.5 node bootstraps per second per control plane**, and
capacity is additive across control planes (measured: two shims driven
simultaneously each sustained full rate).

### How we got there — and the two wrong turns

The original numbers looked exactly like a CPU-bound scrypt bottleneck:

| concurrency | `client-kubelet` p50 | throughput |
|---|---|---|
| 1 | 400 ms | 9.9 req/s |
| 4 | 1 600 ms | 9.0 req/s |
| 16 | 6 398 ms | 9.0 req/s |

Flat throughput, linear latency — textbook saturation. And the cost isolated
cleanly to the two **node-scoped** endpoints: `client-kube-proxy.crt` does the
same POST, the same CSR parse and the same CA signature and returns in 5 ms, so
it had to be the node-password check, which is scrypt at N=15.

Two experiments killed that theory:

- 🧪 **Doubling the control plane's vCPU changed nothing** — 2 cores and 4 cores
  produced identical numbers to the millisecond.
- 🧪 **Setting `GOMAXPROCS` explicitly changed nothing** either.

Meanwhile scrypt N=15 measures **52 ms** on a fast core — nowhere near the
~450 ms per call being observed. The wall clock was also ~18 s *regardless of
concurrency*, which is the signature of a **rate limiter**, not a CPU.

It was: `rest.InClusterConfig()` + `kubernetes.NewForConfig()` uses client-go's
defaults of **QPS 5 / Burst 10**. Every node-scoped request reads (and on first
contact writes) that node's password Secret, so 5 API operations per second was
the ceiling on the whole supervisor.

```go
restCfg.QPS = 50    // was client-go's default 5
restCfg.Burst = 100 // was 10
```

Tunable with `--api-qps` / `--api-burst` (`SHIM_API_QPS`, `SHIM_API_BURST`).

Everything else was always in the noise, before and after:

| endpoint | p50 |
|---|---|
| `GET /cacerts` | 22 ms *(TLS handshake, first contact)* |
| `GET /v1-rke2/config` | 5 ms |
| `GET /v1-rke2/{client,server}-ca.crt` | 5 ms |
| `POST client-kube-proxy.crt` | 5 ms |
| `POST client-rke2-controller.crt` | 5 ms |

The two node-scoped endpoints remain the expensive ones — they still do scrypt —
but at ~680 ms and ~1 036 ms under a load of 16 concurrent bootstraps, rather
than being pinned behind a queue.

## 🌩️ What this means for a thundering herd

A rack-wide power event where *N* agents re-register at once:

- **~8.5 node bootstraps/s per control plane**, and agents fan out across every
  supervisor they know, so 3 control planes ≈ **25/s**
- 200 nodes ≈ **8 seconds**, with individual agents seeing ~1 s waits

That is comfortable. Before the fix the same herd took **~3 minutes**, with
agents seeing multi-second stalls — a cliff nobody had measured because nobody
had run more than one worker.

## 🔧 Levers, in the order we would reach for them

1. **Check `--api-qps` first.** If throughput is flat and latency scales with
   concurrency, you are rate-limited, not CPU-bound. This is worth stating twice
   because it cost us two wrong hypotheses and a VM resize.
2. **More control planes.** Capacity is additive and the agent's fan-out already
   spreads load. Measured, not assumed.
3. **Cache verified passwords in memory**, short TTL, bounded. A bootstrap
   verifies the same password twice, so this halves the remaining scrypt cost.
   *Not implemented* — no longer urgent now the ceiling has moved.
4. **Do not lower the scrypt cost.** The hash encodes its own parameters, so a
   weaker one would still interoperate — which makes it tempting and wrong. It
   guards node identity; the cost is the point.

## 🧪 What this does *not* cover

- **No tunnel load.** `loadgen` bootstraps but does not hold remotedialer
  tunnels. Memory and file descriptors per held tunnel at N=200 are unmeasured,
  and that is the steady-state cost rather than the burst cost.
- **No baseline against a stock `rke2-server`.** The lab's last RKE2 control
  plane was already decommissioned. Note that RKE2 configures its own client-go
  QPS, so the "no worse than RKE2" claim is now **untested in both directions**.
- **No soak.** Minutes, not days. Nothing here says anything about leaks.
- **20 nodes, not 200.** The rate is measured; the extrapolation is arithmetic.

`loadgen` creates a real node-password Secret per synthetic node. Delete them
afterwards, and point it at a lab cluster.
