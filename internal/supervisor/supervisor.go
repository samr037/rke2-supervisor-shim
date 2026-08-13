// Package supervisor implements the RKE2 supervisor API (port 9345) on top of
// a Talos-managed Kubernetes control plane.
//
// Protocol reference: docs/protocol.md. Verified against the RKE2 versions
// listed in conformance/testdata/.
package supervisor

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samr037/rke2-supervisor-shim/internal/pki"
)

// Header names are Rke2-prefixed, not K3s-prefixed: rke2 rebrands them from
// the vendored k3s code via version.Program.
const (
	hdrNodeName     = "Rke2-Node-Name"
	hdrNodePassword = "Rke2-Node-Password"
	hdrNodeIP       = "Rke2-Node-Ip"
	basicUser       = "node" // literally "node", not the node's name
)

// Keys in the captured agent-config template that must never be forwarded to
// agents, because they are secrets belonging to the cluster it was captured on.
var secretKeysToScrub = []string{"IPSECPSK"}

type Config struct {
	Token          string
	APIServers     []string // "ip:6443", advertised via /v1-rke2/apiservers
	ClusterDNS     string
	ClusterDomain  string
	PodCIDR        string
	ServiceCIDR    string
	AgentConfigRaw []byte // a captured real rke2 /v1-rke2/config, used as template
}

// NodePasswordStore mirrors rke2's trust-on-first-use node passwords. A real
// server keeps them as <node>.node-password.rke2 Secrets in kube-system.
type NodePasswordStore interface {
	// CheckAndSet returns false only if the node is known with a different
	// password.
	CheckAndSet(node, password string) (bool, error)
}

// IssuanceRecorder is notified after every certificate the shim signs, so
// expiry can be tracked and warned about (a real rke2 server does this).
type IssuanceRecorder interface {
	RecordIssued(node, kind string, notAfter time.Time)
}

type Server struct {
	cfg Config
	// Refreshed as control-plane nodes come and go; every address advertised
	// here must also be running a shim (see internal/apiservers).
	apiServers atomic.Pointer[[]string]
	ca         *pki.CA
	// RKE2 splits its PKI: apiservers verify CLIENT certs against client-ca but
	// verify kubelet SERVING certs against server-ca. A single-CA Talos cluster
	// hides this. When servingCA is set, serving certs are signed with it.
	servingCA *pki.CA
	pw        NodePasswordStore
	rec       IssuanceRecorder
	log       *slog.Logger
	once      sync.Once
	agent     map[string]any // parsed + patched agent config
}

func New(cfg Config, ca *pki.CA, pw NodePasswordStore, rec IssuanceRecorder, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, ca: ca, pw: pw, rec: rec, log: log}
	if len(cfg.APIServers) > 0 {
		s.SetAPIServers(cfg.APIServers)
	}
	return s
}

// SetServingCA configures a separate CA for kubelet SERVING certificates.
// Required when adopting an RKE2 cluster, whose apiservers verify kubelet
// serving certs against server-ca while verifying client certs against
// client-ca. Leave unset on a single-CA (Talos-native) cluster.
func (s *Server) SetServingCA(ca *pki.CA) {
	s.servingCA = ca
	if ca != nil {
		s.log.Info("using a separate CA for kubelet serving certificates",
			"subject", ca.Cert.Subject.String())
	}
}

// SetAPIServers replaces the advertised control-plane list.
func (s *Server) SetAPIServers(list []string) {
	if len(list) == 0 {
		return
	}
	cur := s.apiServers.Load()
	if cur != nil && equal(*cur, list) {
		return
	}
	s.apiServers.Store(&list)
	s.log.Info("advertising control-plane endpoints", "apiservers", list)
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Server) Routes(mux *http.ServeMux, tunnel http.Handler) {
	mux.HandleFunc("/cacerts", s.handleCACerts) // unauthenticated by design
	mux.HandleFunc("/v1-rke2/config", s.auth(s.handleConfig))
	mux.HandleFunc("/v1-rke2/readyz", s.auth(s.handleReadyz))
	mux.HandleFunc("/v1-rke2/apiservers", s.auth(s.handleAPIServers))
	mux.HandleFunc("/v1-rke2/client-ca.crt", s.auth(s.handleCA))
	mux.HandleFunc("/v1-rke2/server-ca.crt", s.auth(s.handleCA))
	mux.HandleFunc("/v1-rke2/serving-kubelet.crt", s.auth(s.handleCert))
	mux.HandleFunc("/v1-rke2/client-kubelet.crt", s.auth(s.handleCert))
	mux.HandleFunc("/v1-rke2/client-kube-proxy.crt", s.auth(s.handleCert))
	mux.HandleFunc("/v1-rke2/client-rke2-controller.crt", s.auth(s.handleCert))
	if tunnel != nil {
		// Authenticated by mTLS client certificate, NOT by the Basic auth
		// used everywhere else - the upgrade request carries no
		// Authorization header at all.
		mux.Handle("/v1-rke2/connect", tunnel)
	}
	mux.HandleFunc("/", s.handleUnknown)
}

// auth enforces HTTP Basic with the literal username "node" and the cluster
// token as password.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != basicUser ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(s.cfg.Token)) != 1 {
			s.log.Warn("unauthorized", "path", r.URL.Path, "remote", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleCACerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.ca.PEM)
}

// Talos has a single cluster CA where rke2 keeps separate client-ca and
// server-ca. Returning the same CA for both is correct: what matters is that
// the kubelet client cert chains to the CA the apiserver trusts.
func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(s.ca.PEM)
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleAPIServers(w http.ResponseWriter, r *http.Request) {
	list := []string{}
	if p := s.apiServers.Load(); p != nil {
		list = *p
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list)
}

func (s *Server) handleUnknown(w http.ResponseWriter, r *http.Request) {
	// Loud on purpose: an unknown path means the agent version wants
	// something this shim has never been conformance-tested against.
	s.log.Error("UNIMPLEMENTED supervisor endpoint - possible RKE2 protocol drift",
		"method", r.Method, "path", r.URL.Path)
	http.Error(w, "not implemented: "+r.URL.Path, http.StatusNotImplemented)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	s.once.Do(s.buildAgentConfig)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.agent)
}

// buildAgentConfig starts from a captured real rke2 response and overrides the
// cluster-specific values. Starting from a real capture (rather than hand
// writing 60+ keys) is deliberate: unknown keys keep whatever the real server
// sent, so new fields do not silently become zero values.
func (s *Server) buildAgentConfig() {
	cfg := map[string]any{}
	if len(s.cfg.AgentConfigRaw) > 0 {
		if err := json.Unmarshal(s.cfg.AgentConfigRaw, &cfg); err != nil {
			s.log.Error("agent config template is not valid JSON", "err", err)
		}
	}
	podNet, _ := ipNet(s.cfg.PodCIDR)
	svcNet, _ := ipNet(s.cfg.ServiceCIDR)

	cfg["ClusterDNS"] = s.cfg.ClusterDNS
	cfg["ClusterDNSs"] = []string{s.cfg.ClusterDNS}
	cfg["ClusterDomain"] = s.cfg.ClusterDomain
	cfg["ClusterIPRange"] = podNet
	cfg["ClusterIPRanges"] = []any{podNet}
	cfg["ServiceIPRange"] = svcNet
	cfg["ServiceIPRanges"] = []any{svcNet}

	// The Talos cluster already runs flannel and kube-proxy as DaemonSets for
	// every node; the agent must not try to manage its own.
	cfg["FlannelBackend"] = "none"
	cfg["DisableKubeProxy"] = true
	cfg["DisableServiceLB"] = true
	cfg["DisableCCM"] = true
	cfg["DisableNPC"] = true
	cfg["DisableHelmController"] = true

	// Never relay secret-shaped values from the captured template: it comes
	// from a different (throwaway) rke2 cluster and carries that cluster's
	// IPsec pre-shared key. Nothing here uses IPsec (FlannelBackend is none).
	for _, k := range secretKeysToScrub {
		if _, ok := cfg[k]; ok {
			cfg[k] = ""
		}
	}

	s.agent = cfg
}

// ipNet reproduces Go's net.IPNet JSON shape as rke2 serialises it:
// {"IP": "10.244.0.0", "Mask": "//8AAA=="} where Mask is base64 of the raw mask.
func ipNet(cidr string) (map[string]any, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return map[string]any{"IP": n.IP.String(), "Mask": n.Mask}, nil
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// A GET here is what a naive implementation tries first; rke2 answers
		// 400 "node name not set", which is a very misleading error.
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	csr, err := readCSR(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node := r.Header.Get(hdrNodeName)
	kind := strings.TrimSuffix(pathBase(r.URL.Path), ".crt")

	var req pki.Request
	switch kind {
	case "serving-kubelet", "client-kubelet":
		// Only these two are node-scoped and carry Rke2-Node-* headers.
		if node == "" {
			writeStatus(w, http.StatusBadRequest, "node name not set")
			return
		}
		// The node password is what stops a holder of the join token from
		// minting certificates in an EXISTING node's name. It must be
		// REQUIRED, not merely verified when present - otherwise omitting the
		// header bypasses the check entirely. See internal/supervisor/
		// security_test.go:TestNodeCertRequiresNodePassword.
		pw := r.Header.Get(hdrNodePassword)
		if pw == "" {
			writeStatus(w, http.StatusBadRequest, "node password not set")
			return
		}
		if s.pw != nil {
			ok, err := s.pw.CheckAndSet(node, pw)
			if err != nil {
				s.log.Error("node password store", "node", node, "err", err)
				http.Error(w, "node password store error", http.StatusInternalServerError)
				return
			}
			if !ok {
				s.log.Warn("node password mismatch - refusing to issue",
					"node", node, "remote", r.RemoteAddr)
				http.Error(w, "node password mismatch", http.StatusConflict)
				return
			}
		}
		if kind == "serving-kubelet" {
			req = pki.Request{
				CommonName:  node,
				DNSNames:    []string{node, "localhost"},
				IPAddresses: append([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, parseIPs(r.Header.Get(hdrNodeIP))...),
			}
		} else {
			// Exactly the identity the Kubernetes Node authorizer requires.
			req = pki.Request{
				CommonName:   "system:node:" + node,
				Organization: []string{"system:nodes"},
				ClientAuth:   true,
			}
		}
	case "client-kube-proxy":
		// Cluster-wide identity: sent with NO node headers.
		req = pki.Request{CommonName: "system:kube-proxy", ClientAuth: true}
	case "client-rke2-controller":
		req = pki.Request{CommonName: "system:rke2-controller", ClientAuth: true}
	default:
		s.handleUnknown(w, r)
		return
	}

	// Serving certs go to the serving CA when one is configured; everything
	// else is a client identity and must chain to the client CA.
	signer := s.ca
	if kind == "serving-kubelet" && s.servingCA != nil {
		signer = s.servingCA
	}
	out, err := signer.Sign(csr, req)
	if err != nil {
		s.log.Error("signing failed", "kind", kind, "node", node, "err", err)
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	s.log.Info("issued certificate", "kind", kind, "node", nodeOr(node, "-"), "cn", req.CommonName)
	if s.rec != nil {
		s.rec.RecordIssued(node, kind, time.Now().Add(signer.MaxTTL))
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(out)
}

func writeStatus(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind": "Status", "metadata": map[string]any{}, "status": "Failure",
		"message": msg, "reason": "BadRequest", "code": code,
	})
}

func parseIPs(csv string) []net.IP {
	var out []net.IP
	for _, s := range strings.Split(csv, ",") {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func nodeOr(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

const maxCSRBytes = 64 << 10 // a DER CSR is ~200 bytes; this is generous

func readCSR(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(r.Body, maxCSRBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading CSR: %w", err)
	}
	if len(buf) > maxCSRBytes {
		return nil, fmt.Errorf("CSR too large")
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("empty CSR body")
	}
	return buf, nil
}
