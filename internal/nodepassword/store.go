package nodepassword

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Namespace and naming are rke2's, so an operator can find and delete these
// with the commands they already know:
//
//	kubectl -n kube-system delete secret <node>.node-password.rke2
const (
	Namespace  = "kube-system"
	nameSuffix = ".node-password.rke2"
	dataKey    = "hash"
)

// SecretStore keeps node passwords as Secrets in the cluster, the way a real
// rke2 server does, so they survive the shim pod being rescheduled.
type SecretStore struct {
	client  kubernetes.Interface
	timeout time.Duration
}

func NewSecretStore(client kubernetes.Interface) *SecretStore {
	return &SecretStore{client: client, timeout: 10 * time.Second}
}

func SecretName(node string) string { return node + nameSuffix }

// ErrNodeExistsWithoutPassword is returned when a node name has no recorded
// password but a Node object of that name already exists.
var ErrNodeExistsWithoutPassword = errors.New("a Node with this name already exists but has no recorded node password")

// CheckAndSet implements trust-on-first-use: the first password seen for a node
// is recorded, and every later request must match it. "First" means the name is
// not yet a Node: see ErrNodeExistsWithoutPassword.
//
// Returns false (not an error) when a known node presents a different password.
// That is the anti-impersonation case, and it is also what happens legitimately
// when a node is rebuilt - the operator must delete the Secret to let it
// re-register.
func (s *SecretStore) CheckAndSet(ctx context.Context, node, password string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	name := SecretName(node)
	sec, err := s.client.CoreV1().Secrets(Namespace).Get(ctx, name, metav1.GetOptions{})
	switch {
	case err == nil:
		hash := string(sec.Data[dataKey])
		if hash == "" {
			return false, fmt.Errorf("secret %s/%s has no %q key", Namespace, name, dataKey)
		}
		if verr := verifyHash(ctx, hash, password); verr != nil {
			if errors.Is(verr, ErrMismatch) {
				return false, nil
			}
			return false, verr
		}
		return true, nil

	case apierrors.IsNotFound(err):
		// Trust-on-first-use is only sound for a name nobody holds yet. Nodes
		// that never came through a supervisor - every Talos control plane, and
		// any kubelet joined by other means - have a Node object but no
		// password on record, so enrolling here would hand whoever holds the
		// join token CN=system:node:<that node>. Refuse, and make an operator
		// decide. A lookup we cannot complete is treated the same way.
		_, nerr := s.client.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
		switch {
		case nerr == nil:
			return false, fmt.Errorf("%w: node %q", ErrNodeExistsWithoutPassword, node)
		case !apierrors.IsNotFound(nerr):
			return false, fmt.Errorf("checking whether Node %q already exists: %w", node, nerr)
		}
		hash, herr := createHash(ctx, password)
		if herr != nil {
			return false, herr
		}
		_, cerr := s.client.CoreV1().Secrets(Namespace).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: Namespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "rke2-supervisor-shim",
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{dataKey: []byte(hash)},
		}, metav1.CreateOptions{})
		if cerr != nil {
			// Another replica may have won the race; re-check rather than fail.
			if apierrors.IsAlreadyExists(cerr) {
				return s.CheckAndSet(ctx, node, password)
			}
			return false, cerr
		}
		return true, nil

	default:
		return false, err
	}
}
