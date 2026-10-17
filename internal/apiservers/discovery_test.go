package apiservers

import (
	"context"
	"log/slog"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func cpNode(name string, ready bool, addrs ...string) *corev1.Node {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{controlPlaneLabel: ""}},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}},
		},
	}
	for _, a := range addrs {
		n.Status.Addresses = append(n.Status.Addresses, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: a})
	}
	return n
}

// Regression: addresses were formatted with "%s:%d", which yields an
// unusable "fd00::1:6443" for IPv6, and were advertised to every agent
// without being parsed - so a loopback, unspecified or garbage InternalIP
// became an endpoint agents would dial for API traffic and the tunnel.
func TestListFormatsAndFiltersAddresses(t *testing.T) {
	client := fake.NewClientset(
		cpNode("v4", true, "10.0.0.1"),
		cpNode("v6", true, "fd00::1"),
		cpNode("loopback", true, "127.0.0.1"),
		cpNode("unspecified", true, "0.0.0.0"),
		cpNode("unspecified6", true, "::"),
		cpNode("garbage", true, "not-an-ip"),
		cpNode("garbage-then-good", true, "nope", "10.0.0.3"),
		cpNode("not-ready", false, "10.0.0.9"),
	)
	got, err := New(client, 6443, slog.New(slog.DiscardHandler)).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.1:6443", "10.0.0.3:6443", "[fd00::1]:6443"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
