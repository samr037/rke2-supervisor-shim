// Package apiservers keeps /v1-rke2/apiservers in step with the actual set of
// control-plane nodes.
//
// This list is not cosmetic. An agent uses it for two things: its client-side
// load balancer for API traffic, and - critically - the address it dials on
// :9345 for the remotedialer tunnel. rke2 assumes a supervisor is co-located
// with every apiserver, so every address advertised here MUST also be running
// the shim. That is why the shim is a DaemonSet over control-plane nodes rather
// than a single-replica Deployment.
//
// A hardcoded single address silently breaks the moment a second control-plane
// node is added: agents keep working against the one they know, and fail over
// to nothing.
package apiservers

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	controlPlaneLabel = "node-role.kubernetes.io/control-plane"
	refreshEvery      = 2 * time.Minute
)

// Discoverer lists control-plane node addresses.
type Discoverer struct {
	client kubernetes.Interface
	port   int
	log    *slog.Logger
}

func New(client kubernetes.Interface, port int, log *slog.Logger) *Discoverer {
	return &Discoverer{client: client, port: port, log: log}
}

// List returns "<ip>:<port>" for every Ready control-plane node, sorted so the
// response is stable across calls.
func (d *Discoverer) List(ctx context.Context) ([]string, error) {
	nodes, err := d.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{
		LabelSelector: controlPlaneLabel,
	})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range nodes.Items {
		if !isReady(&n) {
			continue
		}
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				out = append(out, fmt.Sprintf("%s:%d", a.Address, d.port))
				break
			}
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no ready control-plane nodes found")
	}
	return out, nil
}

func isReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// Run refreshes the list until done is closed, handing each update to set.
// Failures are logged and the previous list is kept: a transient API error must
// not empty the list agents depend on.
func (d *Discoverer) Run(done <-chan struct{}, set func([]string)) {
	apply := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		list, err := d.List(ctx)
		if err != nil {
			d.log.Warn("refreshing control-plane list, keeping previous", "err", err)
			return
		}
		set(list)
	}
	apply()

	t := time.NewTicker(refreshEvery)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			apply()
		}
	}
}
