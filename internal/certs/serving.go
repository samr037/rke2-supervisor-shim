// Package certs manages the shim's own TLS serving certificate.
//
// A real rke2 server uses rancher/dynamiclistener, which mints its serving
// certificate from the cluster CA and adds SANs as it observes them, rather
// than requiring an operator to prepare one. This does the equivalent: the
// certificate is issued from the cluster CA at startup, its SANs come from the
// node the shim is running on, and it is rotated before it expires.
//
// That removes a manual setup step and, more importantly, removes the footgun
// where a hand-made certificate has the wrong SANs after a control-plane node
// is added, moved or re-addressed.
package certs

import (
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/samr037/rke2-supervisor-shim/internal/pki"
)

const (
	// Matches the TTL a real rke2 server issues.
	DefaultTTL = 365 * 24 * time.Hour
	// Rotate well before expiry so a long-lived pod never serves a stale cert.
	renewBefore = 30 * 24 * time.Hour
	checkEvery  = 12 * time.Hour
)

type Manager struct {
	ca       *pki.CA
	sans     []net.IP
	dns      []string
	ttl      time.Duration
	log      *slog.Logger
	current  atomic.Pointer[tls.Certificate]
	notAfter atomic.Pointer[time.Time]
}

// NewManager issues the first certificate immediately so the listener can start.
// extraIPs/extraDNS are appended to whatever is discovered from the environment.
func NewManager(ca *pki.CA, extraIPs []net.IP, extraDNS []string, ttl time.Duration, log *slog.Logger) (*Manager, error) {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	m := &Manager{ca: ca, ttl: ttl, log: log}

	ips := map[string]net.IP{}
	add := func(ip net.IP) {
		if ip != nil {
			ips[ip.String()] = ip
		}
	}
	add(net.ParseIP("127.0.0.1"))
	add(net.ParseIP("::1"))
	// Downward API: the address agents will actually dial.
	add(net.ParseIP(os.Getenv("NODE_IP")))
	for _, ip := range extraIPs {
		add(ip)
	}
	// Every address of the host, since hostNetwork means we answer on all of them.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLinkLocalUnicast() {
				add(ipnet.IP)
			}
		}
	}
	for _, ip := range ips {
		m.sans = append(m.sans, ip)
	}

	dns := map[string]struct{}{"localhost": {}}
	if n := os.Getenv("NODE_NAME"); n != "" {
		dns[n] = struct{}{}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		dns[h] = struct{}{}
	}
	for _, d := range extraDNS {
		dns[d] = struct{}{}
	}
	for d := range dns {
		m.dns = append(m.dns, d)
	}

	if err := m.issue(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) issue() error {
	certPEM, keyPEM, notAfter, err := m.ca.IssueSelf(pki.Request{
		CommonName:  "rke2-supervisor-shim",
		DNSNames:    m.dns,
		IPAddresses: m.sans,
	}, m.ttl)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	m.current.Store(&pair)
	m.notAfter.Store(&notAfter)
	m.log.Info("issued serving certificate",
		"notAfter", notAfter.Format(time.RFC3339), "dns", m.dns, "ips", ipStrings(m.sans))
	return nil
}

// GetCertificate is the tls.Config hook, so rotation takes effect without a
// restart and without dropping connections.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.current.Load(), nil
}

func (m *Manager) NotAfter() time.Time {
	if p := m.notAfter.Load(); p != nil {
		return *p
	}
	return time.Time{}
}

// Run rotates the certificate before it expires. Blocks until ctx is done.
func (m *Manager) Run(done <-chan struct{}) {
	t := time.NewTicker(checkEvery)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if time.Until(m.NotAfter()) > renewBefore {
				continue
			}
			m.log.Info("serving certificate approaching expiry, rotating",
				"notAfter", m.NotAfter().Format(time.RFC3339))
			if err := m.issue(); err != nil {
				m.log.Error("rotating serving certificate", "err", err)
			}
		}
	}
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
