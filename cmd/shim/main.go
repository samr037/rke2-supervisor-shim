// rke2-supervisor-shim serves the RKE2 supervisor API on :9345, backed by a
// Talos-managed Kubernetes control plane, so that stock `rke2 agent` nodes can
// join it without any bespoke configuration.
//
// It must run on the control-plane node's own address (hostNetwork), because
// after bootstrap an agent dials <apiserver-ip>:9345 for the tunnel.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rancher/remotedialer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/samr037/rke2-supervisor-shim/internal/apiservers"
	"github.com/samr037/rke2-supervisor-shim/internal/certs"
	"github.com/samr037/rke2-supervisor-shim/internal/expiry"
	"github.com/samr037/rke2-supervisor-shim/internal/nodepassword"
	"github.com/samr037/rke2-supervisor-shim/internal/pki"
	"github.com/samr037/rke2-supervisor-shim/internal/supervisor"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func main() {
	var (
		listen        = flag.String("listen", env("SHIM_LISTEN", ":9345"), "listen address")
		apiQPS        = flag.Int("api-qps", envInt("SHIM_API_QPS", 50), "Kubernetes API queries/sec (client-go defaults to 5, which throttles agent bootstrap)")
		apiBurst      = flag.Int("api-burst", envInt("SHIM_API_BURST", 100), "Kubernetes API burst")
		caCert        = flag.String("ca-cert", env("SHIM_CA_CERT", "/pki/cluster-ca.crt"), "cluster CA certificate")
		caKey         = flag.String("ca-key", env("SHIM_CA_KEY", "/pki/cluster-ca.key"), "cluster CA private key")
		servingCACert = flag.String("serving-ca-cert", env("SHIM_SERVING_CA_CERT", ""), "CA for kubelet SERVING certs (RKE2's server-ca); empty = use the cluster CA")
		servingCAKey  = flag.String("serving-ca-key", env("SHIM_SERVING_CA_KEY", ""), "key for --serving-ca-cert")
		tlsCert       = flag.String("tls-cert", env("SHIM_TLS_CERT", ""), "serving certificate (empty = self-managed from the cluster CA)")
		tlsKey        = flag.String("tls-key", env("SHIM_TLS_KEY", ""), "serving key (empty = self-managed)")
		extraSANs     = flag.String("extra-sans", env("SHIM_EXTRA_SANS", ""), "additional IPs/DNS names for the self-managed serving certificate")
		metricsAddr   = flag.String("metrics-listen", env("SHIM_METRICS_LISTEN", ":9346"), "Prometheus metrics address")
		templatePath  = flag.String("agent-config", env("SHIM_AGENT_CONFIG", "/etc/rke2-shim/agent-config.json"), "captured rke2 /v1-rke2/config used as template")
		kubeconfig    = flag.String("kubeconfig", env("KUBECONFIG", ""), "kubeconfig path (empty = in-cluster)")
		token         = flag.String("token", env("SHIM_TOKEN", ""), "cluster join token")
		apiServersCSV = flag.String("apiservers", env("SHIM_APISERVERS", ""), "static ip:6443 list; empty = discover control-plane nodes from the API")
		apiServerPort = flag.Int("apiserver-port", 6443, "port to advertise for discovered control-plane nodes")
		clusterDNS    = flag.String("cluster-dns", env("SHIM_CLUSTER_DNS", "10.96.0.10"), "cluster DNS service IP")
		clusterDomain = flag.String("cluster-domain", env("SHIM_CLUSTER_DOMAIN", "cluster.local"), "cluster domain")
		podCIDR       = flag.String("pod-cidr", env("SHIM_POD_CIDR", "10.244.0.0/16"), "pod CIDR")
		svcCIDR       = flag.String("service-cidr", env("SHIM_SVC_CIDR", "10.96.0.0/12"), "service CIDR")
		enableTunnel  = flag.Bool("tunnel", env("SHIM_TUNNEL", "true") == "true", "serve the remotedialer tunnel")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *token == "" {
		log.Error("no token configured (SHIM_TOKEN)")
		os.Exit(1)
	}
	ca, err := pki.LoadCA(*caCert, *caKey, 365*24*time.Hour)
	if err != nil {
		log.Error("loading cluster CA", "err", err)
		os.Exit(1)
	}

	tmpl, err := os.ReadFile(*templatePath)
	if err != nil {
		log.Error("reading agent config template", "path", *templatePath, "err", err)
		os.Exit(1)
	}
	if !json.Valid(tmpl) {
		log.Error("agent config template is not valid JSON", "path", *templatePath)
		os.Exit(1)
	}

	// Node passwords live as Secrets in kube-system, exactly as a real rke2
	// server stores them, so they survive this pod being rescheduled.
	restCfg, err := kubeClientConfig(*kubeconfig)
	if err != nil {
		log.Error("building Kubernetes client config", "err", err)
		os.Exit(1)
	}
	// client-go defaults to QPS 5 / Burst 10, which is far too low here: every
	// node-scoped certificate request reads (and on first contact writes) that
	// node's password Secret, so the API rate limit — not scrypt, not CPU —
	// becomes the ceiling on how fast agents can bootstrap. Measured: the
	// default pinned the supervisor at ~10 requests/s no matter how many cores
	// or control planes were available. See docs/benchmarks.md.
	//
	// These are small, single-object reads against one namespace; the apiserver
	// does not notice. Lower it only if you are sharing a very busy apiserver.
	restCfg.QPS = float32(*apiQPS)
	restCfg.Burst = *apiBurst

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Error("building Kubernetes client", "err", err)
		os.Exit(1)
	}

	cfg := supervisor.Config{
		Token:          *token,
		APIServers:     splitCSV(*apiServersCSV),
		ClusterDNS:     *clusterDNS,
		ClusterDomain:  *clusterDomain,
		PodCIDR:        *podCIDR,
		ServiceCIDR:    *svcCIDR,
		AgentConfigRaw: tmpl,
	}

	// Discover control-plane nodes unless an explicit list was given. Every
	// advertised address must also run a shim - hence the DaemonSet.
	discover := *apiServersCSV == ""

	tracker := expiry.NewTracker(clientset, log)
	srv := supervisor.New(cfg, ca, nodepassword.NewSecretStore(clientset), tracker, log)

	// Adopted RKE2 clusters verify kubelet serving certs against server-ca and
	// client certs against client-ca, so the two cannot share a signer.
	if *servingCACert != "" && *servingCAKey != "" {
		sca, serr := pki.LoadCA(*servingCACert, *servingCAKey, 365*24*time.Hour)
		if serr != nil {
			log.Error("loading serving CA", "err", serr)
			os.Exit(1)
		}
		srv.SetServingCA(sca)
	}

	reg := prometheus.NewRegistry()
	expiry.MustRegister(reg)
	done := make(chan struct{})
	defer close(done)
	go tracker.Run(done)
	if discover {
		go apiservers.New(clientset, *apiServerPort, log).Run(done, srv.SetAPIServers)
	}
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
		log.Info("metrics listening", "addr", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, mux); err != nil {
			log.Error("metrics server exited", "err", err)
		}
	}()

	var tunnel http.Handler
	if *enableTunnel {
		tunnel = newTunnel(log)
	}

	mux := http.NewServeMux()
	srv.Routes(mux, tunnel)

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if *tlsCert != "" && *tlsKey != "" {
		pair, lerr := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if lerr != nil {
			log.Error("loading serving certificate", "err", lerr)
			os.Exit(1)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
		log.Info("using operator-supplied serving certificate", "cert", *tlsCert)
	} else {
		// Default: mint our own from the cluster CA and rotate it, the way
		// rke2's dynamiclistener does, so SANs always match this node.
		ips, dns := parseSANs(*extraSANs)
		cm, cerr := certs.NewManager(ca, ips, dns, certs.DefaultTTL, log)
		if cerr != nil {
			log.Error("issuing serving certificate", "err", cerr)
			os.Exit(1)
		}
		expiry.ServingCertExpirySeconds.Set(float64(cm.NotAfter().Unix()))
		go cm.Run(done)
		tlsCfg.GetCertificate = cm.GetCertificate
	}
	// The tunnel upgrade carries no Authorization header - rke2 authenticates
	// it by mTLS. Request (but do not require) a client certificate so the
	// tunnel authorizer can identify the node from the TLS peer chain, while
	// the Basic-auth endpoints keep working for clients that send none.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM)
	tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	tlsCfg.ClientCAs = pool

	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		TLSConfig:         tlsCfg,
	}

	log.Info("rke2-supervisor-shim starting",
		"listen", *listen, "apiservers", cfg.APIServers,
		"clusterDNS", cfg.ClusterDNS, "podCIDR", cfg.PodCIDR,
		"serviceCIDR", cfg.ServiceCIDR, "tunnel", *enableTunnel)

	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}

// newTunnel serves /v1-rke2/connect using rancher/remotedialer - the same
// library a real rke2 server uses, so the wire protocol is identical by
// construction rather than by reimplementation.
func newTunnel(log *slog.Logger) http.Handler {
	authorizer := func(req *http.Request) (string, bool, error) {
		// mTLS: identity comes from the verified peer certificate.
		if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
			return "", false, nil
		}
		cn := req.TLS.PeerCertificates[0].Subject.CommonName
		// Require a node identity. Without the prefix check, any client cert we
		// issue (system:kube-proxy, system:rke2-controller) could open a tunnel
		// under its own CN as if it were a node.
		if !strings.HasPrefix(cn, "system:node:") {
			log.Warn("rejecting tunnel from non-node identity", "cn", cn)
			return "", false, nil
		}
		node := strings.TrimPrefix(cn, "system:node:")
		if node == "" {
			return "", false, nil
		}
		log.Info("tunnel connected", "cn", cn, "node", node)
		return node, true, nil
	}
	return remotedialer.New(authorizer, remotedialer.DefaultErrorWriter)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func kubeClientConfig(path string) (*rest.Config, error) {
	if path == "" {
		return rest.InClusterConfig()
	}
	return clientcmd.BuildConfigFromFlags("", path)
}

// parseSANs splits a comma separated list into IPs and DNS names.
func parseSANs(csv string) ([]net.IP, []string) {
	var ips []net.IP
	var dns []string
	for _, p := range splitCSV(csv) {
		if ip := net.ParseIP(p); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, p)
		}
	}
	return ips, dns
}
