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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/samr037/rke2-supervisor-shim/internal/apiservers"
	"github.com/samr037/rke2-supervisor-shim/internal/certs"
	"github.com/samr037/rke2-supervisor-shim/internal/expiry"
	"github.com/samr037/rke2-supervisor-shim/internal/nodepassword"
	"github.com/samr037/rke2-supervisor-shim/internal/pki"
	"github.com/samr037/rke2-supervisor-shim/internal/supervisor"
	shimtunnel "github.com/samr037/rke2-supervisor-shim/internal/tunnel"
)

// options is everything configurable from flags and environment.
type options struct {
	listen, caCert, caKey, servingCACert, servingCAKey        string
	tlsCert, tlsKey, extraSANs, metricsAddr                   string
	templatePath, kubeconfig, token, tokenFile, apiServersCSV string
	clusterDNS, clusterDomain, podCIDR, svcCIDR               string
	apiQPS, apiBurst, apiServerPort                           int
	enableTunnel                                              bool
}

// parseOptions reads flags from args, with defaults from getenv. Usage and
// errors go to output.
func parseOptions(args []string, getenv func(string) string, output io.Writer) (*options, error) {
	env := func(k, def string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return def
	}
	envInt := func(k string, def int) int {
		if v := getenv(k); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
		return def
	}
	o := &options{}
	fs := flag.NewFlagSet("rke2-supervisor-shim", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&o.listen, "listen", env("SHIM_LISTEN", ":9345"), "listen address")
	fs.IntVar(&o.apiQPS, "api-qps", envInt("SHIM_API_QPS", 50), "Kubernetes API queries/sec (client-go defaults to 5, which throttles agent bootstrap)")
	fs.IntVar(&o.apiBurst, "api-burst", envInt("SHIM_API_BURST", 100), "Kubernetes API burst")
	fs.StringVar(&o.caCert, "ca-cert", env("SHIM_CA_CERT", "/pki/cluster-ca.crt"), "cluster CA certificate")
	fs.StringVar(&o.caKey, "ca-key", env("SHIM_CA_KEY", "/pki/cluster-ca.key"), "cluster CA private key")
	fs.StringVar(&o.servingCACert, "serving-ca-cert", env("SHIM_SERVING_CA_CERT", ""), "CA for kubelet SERVING certs (RKE2's server-ca); empty = use the cluster CA")
	fs.StringVar(&o.servingCAKey, "serving-ca-key", env("SHIM_SERVING_CA_KEY", ""), "key for --serving-ca-cert")
	fs.StringVar(&o.tlsCert, "tls-cert", env("SHIM_TLS_CERT", ""), "serving certificate (empty = self-managed from the cluster CA)")
	fs.StringVar(&o.tlsKey, "tls-key", env("SHIM_TLS_KEY", ""), "serving key (empty = self-managed)")
	fs.StringVar(&o.extraSANs, "extra-sans", env("SHIM_EXTRA_SANS", ""), "additional IPs/DNS names for the self-managed serving certificate")
	fs.StringVar(&o.metricsAddr, "metrics-listen", env("SHIM_METRICS_LISTEN", ":9346"), "Prometheus metrics address; empty disables the metrics listener")
	fs.StringVar(&o.templatePath, "agent-config", env("SHIM_AGENT_CONFIG", "/etc/rke2-shim/agent-config.json"), "captured rke2 /v1-rke2/config used as template")
	fs.StringVar(&o.kubeconfig, "kubeconfig", env("KUBECONFIG", ""), "kubeconfig path (empty = in-cluster)")
	// No env-derived default for the token: flag defaults are printed in the
	// usage text, so -h or a mistyped flag would write the join token to the
	// log. SHIM_TOKEN / SHIM_TOKEN_FILE are read after parsing, in resolveToken.
	fs.StringVar(&o.token, "token", "", "cluster join token (prefer --token-file or SHIM_TOKEN; a flag is visible in the process list)")
	fs.StringVar(&o.tokenFile, "token-file", env("SHIM_TOKEN_FILE", ""), "file containing the cluster join token; takes precedence over --token and SHIM_TOKEN")
	fs.StringVar(&o.apiServersCSV, "apiservers", env("SHIM_APISERVERS", ""), "static ip:6443 list; empty = discover control-plane nodes from the API")
	fs.IntVar(&o.apiServerPort, "apiserver-port", 6443, "port to advertise for discovered control-plane nodes")
	fs.StringVar(&o.clusterDNS, "cluster-dns", env("SHIM_CLUSTER_DNS", "10.96.0.10"), "cluster DNS service IP")
	fs.StringVar(&o.clusterDomain, "cluster-domain", env("SHIM_CLUSTER_DOMAIN", "cluster.local"), "cluster domain")
	fs.StringVar(&o.podCIDR, "pod-cidr", env("SHIM_POD_CIDR", "10.244.0.0/16"), "pod CIDR")
	fs.StringVar(&o.svcCIDR, "service-cidr", env("SHIM_SVC_CIDR", "10.96.0.0/12"), "service CIDR")
	fs.BoolVar(&o.enableTunnel, "tunnel", env("SHIM_TUNNEL", "true") == "true", "serve the remotedialer tunnel")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return o, nil
}

// resolveToken picks the join token: --token-file / SHIM_TOKEN_FILE, then
// --token, then SHIM_TOKEN. An empty result is an error - an empty token would
// make Basic auth accept an empty password.
func resolveToken(o *options, getenv func(string) string) (string, error) {
	if o.tokenFile != "" {
		b, err := os.ReadFile(o.tokenFile)
		if err != nil {
			return "", fmt.Errorf("reading token file: %w", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("token file %s is empty", o.tokenFile)
		}
		return tok, nil
	}
	tok := o.token
	if tok == "" {
		tok = getenv("SHIM_TOKEN")
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", errors.New("no token configured (--token-file, SHIM_TOKEN_FILE, --token or SHIM_TOKEN)")
	}
	return tok, nil
}

func main() {
	o, err := parseOptions(os.Args[1:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	token, err := resolveToken(o, os.Getenv)
	if err != nil {
		log.Error("refusing to start without a join token", "err", err)
		os.Exit(1)
	}
	// The service CIDR also bounds which addresses a node serving cert may
	// name, so a typo must stop startup rather than surface per request.
	for name, cidr := range map[string]string{"pod-cidr": o.podCIDR, "service-cidr": o.svcCIDR} {
		if _, _, cerr := net.ParseCIDR(cidr); cerr != nil {
			log.Error("invalid CIDR", "flag", name, "value", cidr, "err", cerr)
			os.Exit(1)
		}
	}
	ca, err := pki.LoadCA(o.caCert, o.caKey, 365*24*time.Hour)
	if err != nil {
		log.Error("loading cluster CA", "err", err)
		os.Exit(1)
	}

	tmpl, err := os.ReadFile(o.templatePath)
	if err != nil {
		log.Error("reading agent config template", "path", o.templatePath, "err", err)
		os.Exit(1)
	}
	if !json.Valid(tmpl) {
		log.Error("agent config template is not valid JSON", "path", o.templatePath)
		os.Exit(1)
	}

	// Node passwords live as Secrets in kube-system, exactly as a real rke2
	// server stores them, so they survive this pod being rescheduled.
	restCfg, err := kubeClientConfig(o.kubeconfig)
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
	restCfg.QPS = float32(o.apiQPS)
	restCfg.Burst = o.apiBurst

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Error("building Kubernetes client", "err", err)
		os.Exit(1)
	}

	cfg := supervisor.Config{
		Token:          token,
		APIServers:     splitCSV(o.apiServersCSV),
		ClusterDNS:     o.clusterDNS,
		ClusterDomain:  o.clusterDomain,
		PodCIDR:        o.podCIDR,
		ServiceCIDR:    o.svcCIDR,
		AgentConfigRaw: tmpl,
	}

	// Discover control-plane nodes unless an explicit list was given. Every
	// advertised address must also run a shim - hence the DaemonSet.
	discover := o.apiServersCSV == ""

	tracker := expiry.NewTracker(clientset, log)
	srv := supervisor.New(cfg, ca, nodepassword.NewSecretStore(clientset), tracker, log)

	// Adopted RKE2 clusters verify kubelet serving certs against server-ca and
	// client certs against client-ca, so the two cannot share a signer.
	if o.servingCACert != "" && o.servingCAKey != "" {
		sca, serr := pki.LoadCA(o.servingCACert, o.servingCAKey, 365*24*time.Hour)
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
		go apiservers.New(clientset, o.apiServerPort, log).Run(done, srv.SetAPIServers)
	}
	if ms := newMetricsServer(o.metricsAddr, reg, log); ms != nil {
		go func() {
			log.Info("metrics listening", "addr", o.metricsAddr)
			if err := ms.ListenAndServe(); err != nil {
				log.Error("metrics server exited", "err", err)
			}
		}()
	} else {
		log.Info("metrics listener disabled (--metrics-listen is empty)")
	}

	var tunnel http.Handler
	if o.enableTunnel {
		tunnel = shimtunnel.New(log)
	}

	mux := http.NewServeMux()
	srv.Routes(mux, tunnel)

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.tlsCert != "" && o.tlsKey != "" {
		pair, lerr := tls.LoadX509KeyPair(o.tlsCert, o.tlsKey)
		if lerr != nil {
			log.Error("loading serving certificate", "err", lerr)
			os.Exit(1)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
		log.Info("using operator-supplied serving certificate", "cert", o.tlsCert)
	} else {
		// Default: mint our own from the cluster CA and rotate it, the way
		// rke2's dynamiclistener does, so SANs always match this node.
		ips, dns := parseSANs(o.extraSANs)
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

	server := newMainServer(o.listen, mux, tlsCfg)

	log.Info("rke2-supervisor-shim starting",
		"listen", o.listen, "apiservers", cfg.APIServers,
		"clusterDNS", cfg.ClusterDNS, "podCIDR", cfg.PodCIDR,
		"serviceCIDR", cfg.ServiceCIDR, "tunnel", o.enableTunnel)

	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func newMainServer(addr string, h http.Handler, tlsCfg *tls.Config) *http.Server {
	// No ReadTimeout/WriteTimeout: /v1-rke2/connect is a websocket that lives
	// as long as the agent does, and those apply to the whole connection. The
	// CSR endpoints set their own deadlines instead.
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// Agent requests carry a handful of short headers.
		MaxHeaderBytes: 64 << 10,
		TLSConfig:      tlsCfg,
	}
}

// newMetricsServer returns nil for an empty address: that disables the
// listener. Passing "" on to http.Server would instead bind ":http", every
// interface on port 80.
func newMetricsServer(addr string, reg *prometheus.Registry, log *slog.Logger) *http.Server {
	if addr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("ok")); err != nil {
			log.Debug("writing healthz response", "err", err)
		}
	})
	// Unauthenticated and on the host network: nothing a client does may hold
	// a connection open indefinitely.
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
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
