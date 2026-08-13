package nodepassword

import (
	"context"
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

// CheckAndSet implements trust-on-first-use: the first password seen for a node
// is recorded, and every later request must match it.
//
// Returns false (not an error) when a known node presents a different password.
// That is the anti-impersonation case, and it is also what happens legitimately
// when a node is rebuilt - the operator must delete the Secret to let it
// re-register.
func (s *SecretStore) CheckAndSet(node, password string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	name := SecretName(node)
	sec, err := s.client.CoreV1().Secrets(Namespace).Get(ctx, name, metav1.GetOptions{})
	switch {
	case err == nil:
		hash := string(sec.Data[dataKey])
		if hash == "" {
			return false, fmt.Errorf("secret %s/%s has no %q key", Namespace, name, dataKey)
		}
		if verr := VerifyHash(hash, password); verr != nil {
			if verr == ErrMismatch {
				return false, nil
			}
			return false, verr
		}
		return true, nil

	case apierrors.IsNotFound(err):
		hash, herr := CreateHash(password)
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
				return s.CheckAndSet(node, password)
			}
			return false, cerr
		}
		return true, nil

	default:
		return false, err
	}
}
