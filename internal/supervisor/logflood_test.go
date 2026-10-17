package supervisor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func muxFor(s *Server) *http.ServeMux {
	mux := http.NewServeMux()
	s.Routes(mux, http.NotFoundHandler())
	return mux
}

// Regression: any unauthenticated request to an unknown path produced an
// ERROR ("possible RKE2 protocol drift"), so anyone who could reach :9345 could
// flood the log at ERROR level and bury real drift. Only an authenticated
// client - one that holds the token, i.e. an agent - can signal drift.
func TestUnauthenticatedRequestsDoNotLogErrors(t *testing.T) {
	log, logs := capturingLogger()
	s := New(Config{Token: "t"}, testCA(t, "ca"), &recordingStore{allow: true}, nil, log)
	mux := muxFor(s)
	for i := 0; i < 200; i++ {
		for _, p := range []string{"/v1-rke2/brand-new", "/", "/admin", "/v1-rke2/config"} {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			if i%2 == 0 {
				req.SetBasicAuth("node", "wrong")
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: got %d, want 401", p, rec.Code)
			}
		}
	}
	out := logs.String()
	if n := strings.Count(out, "level=ERROR"); n > 0 {
		t.Errorf("%d ERROR lines from unauthenticated requests", n)
	}
	if n := strings.Count(out, "level=WARN"); n > 2 {
		t.Errorf("%d WARN lines from 800 unauthenticated requests, want them rate-limited", n)
	}
}

// The protocol-drift alarm must still fire for an authenticated agent.
func TestAuthenticatedUnknownEndpointStillFailsLoudly(t *testing.T) {
	log, logs := capturingLogger()
	s := New(Config{Token: "t"}, testCA(t, "ca"), &recordingStore{allow: true}, nil, log)
	req := httptest.NewRequest(http.MethodGet, "/v1-rke2/brand-new", nil)
	req.SetBasicAuth("node", "t")
	rec := httptest.NewRecorder()
	muxFor(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("got %d, want 501", rec.Code)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "UNIMPLEMENTED") {
		t.Errorf("no ERROR for an authenticated unknown endpoint:\n%s", logs.String())
	}
}
