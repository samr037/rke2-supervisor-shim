package expiry

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/samr037/rke2-supervisor-shim/internal/nodepassword"
)

func pwSecret(node string, notAfter map[string]time.Time) *corev1.Secret {
	ann := map[string]string{}
	for kind, t := range notAfter {
		ann[annotationPrefix+kind] = t.UTC().Format(time.RFC3339)
	}
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:        nodepassword.SecretName(node),
		Namespace:   nodepassword.Namespace,
		Labels:      map[string]string{"app.kubernetes.io/managed-by": "rke2-supervisor-shim"},
		Annotations: ann,
	}}
}

// Regression: a node's expiry series was never removed, so a deleted node
// kept exporting its last expiry - and, once that date passed, kept firing
// "certificate expired" alerts for a machine that no longer exists.
func TestScanDropsSeriesForDeletedNodes(t *testing.T) {
	CertExpirySeconds.Reset()
	far := time.Now().Add(300 * 24 * time.Hour)
	client := fake.NewClientset(
		pwSecret("n1", map[string]time.Time{"client-kubelet": far}),
		pwSecret("n2", map[string]time.Time{"client-kubelet": far, "serving-kubelet": far}),
	)
	tr := NewTracker(client, slog.New(slog.DiscardHandler))
	tr.scan()
	if n := testutil.CollectAndCount(CertExpirySeconds); n != 3 {
		t.Fatalf("after first scan: %d series, want 3", n)
	}
	if err := client.CoreV1().Secrets(nodepassword.Namespace).Delete(context.Background(),
		nodepassword.SecretName("n2"), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	tr.scan()
	if n := testutil.CollectAndCount(CertExpirySeconds); n != 1 {
		t.Errorf("after n2 was deleted: %d series, want 1", n)
	}
}

func TestEventNameIsAlwaysValid(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, c := range []struct{ node, kind string }{
		{"n1", "client-kubelet"}, {long, "serving-kubelet"}, {"n1", "Bad_Kind"},
	} {
		name := eventName(c.node, c.kind)
		if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
			t.Errorf("eventName(%q, %q) = %q: %v", c.node, c.kind, name, errs)
		}
		if name != eventName(c.node, c.kind) {
			t.Errorf("eventName(%q, %q) is not stable", c.node, c.kind)
		}
	}
	if eventName("n1", "client-kubelet") == eventName("n1", "serving-kubelet") {
		t.Error("two kinds share an event name")
	}
}

// Regression: every hourly scan created a brand-new Event (GenerateName), so
// one expiring certificate produced 24 Events a day per node and kind.
func TestScanReusesOneEventPerNodeAndKind(t *testing.T) {
	CertExpirySeconds.Reset()
	soon := time.Now().Add(10 * 24 * time.Hour)
	client := fake.NewClientset(pwSecret("n1", map[string]time.Time{"client-kubelet": soon, "serving-kubelet": soon}))
	tr := NewTracker(client, slog.New(slog.DiscardHandler))
	for i := 0; i < 3; i++ {
		tr.scan()
	}
	evs, err := client.CoreV1().Events(eventNS).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 2 {
		t.Fatalf("got %d events after 3 scans of 2 expiring certificates, want 2", len(evs.Items))
	}
	for _, e := range evs.Items {
		if e.Name == "" || e.Reason != "CertificateExpirationWarning" || e.InvolvedObject.Name != "n1" {
			t.Errorf("unexpected event %+v", e.ObjectMeta)
		}
	}
}
