package nodepassword

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const testPassword = "0123456789abcdef0123456789abcdef" // rke2 sends 32 hex chars

// Regression: trust-on-first-use let anyone holding the join token claim the
// name of a node that had never enrolled a password - every Talos control
// plane, for one - and walk away with CN=system:node:<that node>. A name that
// already belongs to a Node must not be enrolled by whoever asks first.
func TestCheckAndSetRefusesExistingNodeWithoutPassword(t *testing.T) {
	client := fake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "talos-cp-1"}})
	s := NewSecretStore(client)

	ok, err := s.CheckAndSet(context.Background(), "talos-cp-1", testPassword)
	if ok {
		t.Fatal("password enrolled for a node that already exists: identity takeover")
	}
	if !errors.Is(err, ErrNodeExistsWithoutPassword) {
		t.Fatalf("got err %v, want ErrNodeExistsWithoutPassword", err)
	}
	if _, gerr := client.CoreV1().Secrets(Namespace).Get(context.Background(),
		SecretName("talos-cp-1"), metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("a password Secret was written for an existing node (get err %v)", gerr)
	}
}

// The ordinary first join - no Secret, no Node yet - must keep working.
func TestCheckAndSetEnrollsNewNode(t *testing.T) {
	client := fake.NewClientset()
	s := NewSecretStore(client)
	ok, err := s.CheckAndSet(context.Background(), "new-worker", testPassword)
	if err != nil || !ok {
		t.Fatalf("first join refused: ok=%v err=%v", ok, err)
	}
	// The kubelet registers its Node after the first certificate; later
	// requests must then verify against the recorded password.
	_, _ = client.CoreV1().Nodes().Create(context.Background(),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "new-worker"}}, metav1.CreateOptions{})
	if ok, err := s.CheckAndSet(context.Background(), "new-worker", testPassword); err != nil || !ok {
		t.Fatalf("re-request by the enrolled node refused: ok=%v err=%v", ok, err)
	}
	if ok, err := s.CheckAndSet(context.Background(), "new-worker", "another-password-entirely"); err != nil || ok {
		t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
	}
}

// An adopted RKE2 worker already has a Secret written by the real rke2 server
// AND a Node object. It must still pass: the Node check applies only when no
// password is on record.
func TestCheckAndSetAcceptsAdoptedRKE2Node(t *testing.T) {
	client := fake.NewClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "rke2-worker"}},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: SecretName("rke2-worker"), Namespace: Namespace},
			Data:       map[string][]byte{dataKey: []byte(realRKE2Hash)},
		},
	)
	ok, err := NewSecretStore(client).CheckAndSet(context.Background(), "rke2-worker", realRKE2Password)
	if err != nil || !ok {
		t.Fatalf("adopted rke2 worker refused: ok=%v err=%v", ok, err)
	}
}

// If we cannot tell whether the Node exists, we must not enrol: fail closed.
func TestCheckAndSetFailsClosedOnNodeLookupError(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("get", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "nodes"}, "x", errors.New("rbac"))
	})
	ok, err := NewSecretStore(client).CheckAndSet(context.Background(), "n1", testPassword)
	if ok || err == nil {
		t.Fatalf("enrolled despite a failed Node lookup: ok=%v err=%v", ok, err)
	}
	if _, gerr := client.CoreV1().Secrets(Namespace).Get(context.Background(),
		SecretName("n1"), metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatal("a password Secret was written despite the failed Node lookup")
	}
}
