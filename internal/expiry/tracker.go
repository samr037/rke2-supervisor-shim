// Package expiry restores the certificate-expiry safety net that a real rke2
// server provides and that replacing it took away.
//
// rke2 emits a Kubernetes Warning event with reason CertificateExpirationWarning
// when a node certificate is within 120 days of expiring (90 before the May
// 2025 releases). That event comes from the server, so a shim-based control
// plane emits nothing and an agent that is never restarted can silently reach
// expiry. Recovery is only a `systemctl restart rke2-agent` - agents
// re-bootstrap with the token, not the old certificate - but you have to know.
//
// Expiries are recorded as annotations on the node-password Secret the shim
// already maintains, so no extra storage is introduced.
package expiry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"

	"github.com/samr037/rke2-supervisor-shim/internal/nodepassword"
)

const (
	annotationPrefix = "rke2-supervisor-shim/not-after."
	// Match rke2's current threshold.
	WarnWithin = 120 * 24 * time.Hour
	scanEvery  = 1 * time.Hour
	eventNS    = "default" // node-scoped events conventionally live here
)

var (
	CertExpirySeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rke2_shim_certificate_expiry_seconds",
		Help: "Unix timestamp at which an issued node certificate expires.",
	}, []string{"node", "kind"})

	CertsIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rke2_shim_certificates_issued_total",
		Help: "Certificates issued by the shim.",
	}, []string{"kind"})

	CertsExpiringSoon = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "rke2_shim_certificates_expiring_soon",
		Help: "Issued node certificates within the expiry warning threshold.",
	})

	ServingCertExpirySeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "rke2_shim_serving_certificate_expiry_seconds",
		Help: "Unix timestamp at which the shim's own serving certificate expires.",
	})
)

func MustRegister(r prometheus.Registerer) {
	r.MustRegister(CertExpirySeconds, CertsIssued, CertsExpiringSoon, ServingCertExpirySeconds)
}

type seriesKey struct{ node, kind string }

type Tracker struct {
	client kubernetes.Interface
	log    *slog.Logger

	// The expiry series this tracker has set, and when, so that series for
	// nodes whose Secret has gone can be removed. A series recorded after a
	// scan's List started is kept: the Secret write may simply not be in it.
	mu     sync.Mutex
	series map[seriesKey]time.Time
}

func NewTracker(client kubernetes.Interface, log *slog.Logger) *Tracker {
	return &Tracker{client: client, log: log, series: map[seriesKey]time.Time{}}
}

func (t *Tracker) setSeries(node, kind string, notAfter time.Time) {
	CertExpirySeconds.WithLabelValues(node, kind).Set(float64(notAfter.Unix()))
	t.mu.Lock()
	t.series[seriesKey{node, kind}] = time.Now()
	t.mu.Unlock()
}

// pruneSeries deletes every series not seen in a scan that started at start.
// Without this a removed node exports its last expiry forever, and alerts
// "certificate expired" for a machine that no longer exists.
func (t *Tracker) pruneSeries(seen map[seriesKey]bool, start time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, at := range t.series {
		if seen[k] || at.After(start) {
			continue
		}
		CertExpirySeconds.DeleteLabelValues(k.node, k.kind)
		delete(t.series, k)
	}
}

// RecordIssued is called by the supervisor after signing. Cluster-wide
// identities (kube-proxy, rke2-controller) have no node and are only counted -
// they are reissued alongside the node certificates anyway.
func (t *Tracker) RecordIssued(node, kind string, notAfter time.Time) {
	CertsIssued.WithLabelValues(kind).Inc()
	if node == "" {
		return
	}
	t.setSeries(node, kind, notAfter)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				annotationPrefix + kind: notAfter.UTC().Format(time.RFC3339),
			},
		},
	})
	if err != nil {
		return
	}
	if _, err := t.client.CoreV1().Secrets(nodepassword.Namespace).Patch(
		ctx, nodepassword.SecretName(node), types.MergePatchType, patch, metav1.PatchOptions{},
	); err != nil {
		// Non-fatal: losing the annotation costs us a warning, not a join.
		t.log.Warn("recording certificate expiry", "node", node, "kind", kind, "err", err)
	}
}

// Run scans recorded expiries hourly, emitting the same event rke2 would.
func (t *Tracker) Run(done <-chan struct{}) {
	t.scan()
	ticker := time.NewTicker(scanEvery)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			t.scan()
		}
	}
}

func (t *Tracker) scan() {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secrets, err := t.client.CoreV1().Secrets(nodepassword.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=rke2-supervisor-shim",
	})
	if err != nil {
		t.log.Error("listing node-password secrets", "err", err)
		return
	}

	var soon int
	seen := map[seriesKey]bool{}
	for _, sec := range secrets.Items {
		node := strings.TrimSuffix(sec.Name, ".node-password.rke2")
		for k, v := range sec.Annotations {
			if !strings.HasPrefix(k, annotationPrefix) {
				continue
			}
			kind := strings.TrimPrefix(k, annotationPrefix)
			notAfter, perr := time.Parse(time.RFC3339, v)
			if perr != nil {
				continue
			}
			t.setSeries(node, kind, notAfter)
			seen[seriesKey{node, kind}] = true
			remaining := time.Until(notAfter)
			if remaining > WarnWithin {
				continue
			}
			soon++
			t.warn(ctx, node, kind, notAfter, remaining)
		}
	}
	CertsExpiringSoon.Set(float64(soon))
	t.pruneSeries(seen, start)
}

func (t *Tracker) warn(ctx context.Context, node, kind string, notAfter time.Time, remaining time.Duration) {
	msg := fmt.Sprintf(
		"Certificate %s for node %s expires in %d days (%s). Restart rke2-agent on the node to renew it.",
		kind, node, int(remaining.Hours()/24), notAfter.UTC().Format(time.RFC3339))
	if remaining <= 0 {
		msg = fmt.Sprintf(
			"Certificate %s for node %s EXPIRED at %s. Restart rke2-agent on the node to renew it.",
			kind, node, notAfter.UTC().Format(time.RFC3339))
	}
	t.log.Warn("certificate expiry warning", "node", node, "kind", kind,
		"notAfter", notAfter.Format(time.RFC3339), "daysRemaining", int(remaining.Hours()/24))

	// One Event per node and kind, refreshed on every scan, instead of a new
	// GenerateName Event each hour. Create, then patch on conflict: the shim's
	// RBAC grants create and patch on events, not get.
	now := metav1.Now()
	name := eventName(node, kind)
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: eventNS},
		// Reason matches rke2's, so existing alerting keeps working.
		Reason:  "CertificateExpirationWarning",
		Message: msg,
		Type:    corev1.EventTypeWarning,
		InvolvedObject: corev1.ObjectReference{
			Kind: "Node", Name: node, APIVersion: "v1",
		},
		Source:         corev1.EventSource{Component: "rke2-supervisor-shim"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	}
	_, err := t.client.CoreV1().Events(eventNS).Create(ctx, ev, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		patch, merr := json.Marshal(map[string]any{
			"message": msg, "lastTimestamp": now, "type": corev1.EventTypeWarning,
		})
		if merr != nil {
			t.log.Error("encoding expiry event patch", "node", node, "err", merr)
			return
		}
		_, err = t.client.CoreV1().Events(eventNS).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	}
	if err != nil {
		t.log.Error("emitting expiry event", "node", node, "err", err)
	}
}

// eventName is stable per node and kind. Node names are DNS-1123 subdomains
// (the supervisor enforces it), but kind comes from an annotation key and the
// pair can exceed 253 characters, so anything that is not a valid name falls
// back to a hash.
func eventName(node, kind string) string {
	name := node + ".cert-expiry." + kind
	if len(validation.IsDNS1123Subdomain(name)) == 0 {
		return name
	}
	sum := sha256.Sum256([]byte(node + "/" + kind))
	return "cert-expiry." + hex.EncodeToString(sum[:8])
}
