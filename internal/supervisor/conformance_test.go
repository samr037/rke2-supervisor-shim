package supervisor

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// These tests replay the contracts captured from real rke2 servers
// (conformance/testdata/<version>/) against the shim's handlers. They need no
// VM and no privileged runner, so they gate every merge.
//
// Regenerate testdata with conformance/capture.sh - see docs/compatibility.md.

const testdata = "../../conformance/testdata"

func versions(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(testdata)
	if err != nil {
		t.Fatalf("no testdata: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	if len(out) == 0 {
		t.Fatal("no captured RKE2 versions in testdata")
	}
	return out
}

func newTestServer(t *testing.T, tmpl []byte) *Server {
	t.Helper()
	return New(Config{
		Token:          "test-token",
		APIServers:     []string{"10.0.0.1:6443"},
		ClusterDNS:     "10.96.0.10",
		ClusterDomain:  "cluster.local",
		PodCIDR:        "10.244.0.0/16",
		ServiceCIDR:    "10.96.0.0/12",
		AgentConfigRaw: tmpl,
	}, nil, nil, nil, slog.New(slog.NewTextHandler(os.Stdout, nil)))
}

// The agent config we serve must keep every key the real server sent, so that
// fields added by future RKE2 versions pass through instead of silently
// becoming zero values.
func TestAgentConfigPreservesAllUpstreamKeys(t *testing.T) {
	for _, v := range versions(t) {
		t.Run(v, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(testdata, v, "config.json"))
			if err != nil {
				t.Skipf("no config.json for %s", v)
			}
			var upstream map[string]any
			if err := json.Unmarshal(raw, &upstream); err != nil {
				t.Fatalf("captured config is not JSON: %v", err)
			}

			s := newTestServer(t, raw)
			s.once.Do(s.buildAgentConfig)

			for k := range upstream {
				if _, ok := s.agent[k]; !ok {
					t.Errorf("key %q present in real rke2 %s but dropped by the shim", k, v)
				}
			}
		})
	}
}

// Values we deliberately override, and the reasons, are part of the contract.
func TestAgentConfigOverrides(t *testing.T) {
	v := versions(t)[0]
	raw, err := os.ReadFile(filepath.Join(testdata, v, "config.json"))
	if err != nil {
		t.Skip("no config.json")
	}
	s := newTestServer(t, raw)
	s.once.Do(s.buildAgentConfig)

	want := map[string]any{
		"ClusterDNS":            "10.96.0.10",
		"ClusterDomain":         "cluster.local",
		"FlannelBackend":        "none", // Talos runs flannel cluster-wide
		"DisableKubeProxy":      true,   // Talos runs kube-proxy cluster-wide
		"DisableHelmController": true,
	}
	for k, exp := range want {
		if got := s.agent[k]; got != exp {
			t.Errorf("%s = %v, want %v", k, got, exp)
		}
	}
}

// net.IPNet must serialise the way Go does it, because that is what the agent
// unmarshals: {"IP":"10.244.0.0","Mask":"//8AAA=="}.
func TestIPNetSerialisation(t *testing.T) {
	n, err := ipNet("10.244.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"IP":"10.244.0.0","Mask":"//8AAA=="}`
	if string(b) != want {
		t.Errorf("got %s, want %s", b, want)
	}
}

// Basic auth uses the literal username "node", not the node's name.
func TestAuthRequiresLiteralNodeUsername(t *testing.T) {
	s := newTestServer(t, []byte(`{}`))
	h := s.auth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	cases := []struct {
		user, pass string
		want       int
	}{
		{"node", "test-token", http.StatusOK},
		{"node", "wrong", http.StatusUnauthorized},
		{"rke2-worker-1", "test-token", http.StatusUnauthorized}, // node NAME must not work
		{"", "", http.StatusUnauthorized},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/v1-rke2/config", nil)
		if c.user != "" || c.pass != "" {
			req.SetBasicAuth(c.user, c.pass)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != c.want {
			t.Errorf("auth(%q,%q) = %d, want %d", c.user, c.pass, rec.Code, c.want)
		}
	}
}

// An endpoint we have never seen must fail loudly rather than be guessed at.
func TestUnknownEndpointReturns501(t *testing.T) {
	s := newTestServer(t, []byte(`{}`))
	rec := httptest.NewRecorder()
	s.handleUnknown(rec, httptest.NewRequest(http.MethodGet, "/v1-rke2/brand-new", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("got %d, want 501", rec.Code)
	}
}
