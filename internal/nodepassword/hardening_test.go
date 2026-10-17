package nodepassword

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Regression: the scrypt parameters were taken from the stored hash as-is, so
// a hash with N=2^20+ made every verification allocate a gigabyte or more. A
// hash outside the parameters rke2 could have written must be refused as
// malformed, not run and reported as a mismatch.
func TestVerifyHashRefusesOutOfRangeParameters(t *testing.T) {
	dk := base64.RawStdEncoding.EncodeToString(make([]byte, 64))
	for _, h := range []string{
		"$1:0011223344556677:17:8:1:" + dk, // N above 2^16
		"$1:0011223344556677:63:8:1:" + dk,
		"$1:0011223344556677:15:17:1:" + dk, // r above 16
		"$1:0011223344556677:15:8:5:" + dk,  // p above 4
		"$1:0011223344556677:15:0:1:" + dk,
		"$1:0011223344556677:15:8:0:" + dk,
		"$1:0011223344556677:0:8:1:" + dk,
	} {
		start := time.Now()
		err := VerifyHash(h, "whatever-password")
		if err == nil || errors.Is(err, ErrMismatch) {
			t.Errorf("%q: got %v, want a malformed-hash error (took %s)", h, err, time.Since(start))
		}
	}
}

// Regression: a stored derived key of a single byte verified one password in
// 256, so a short dk turned the password check into a coin toss.
func TestVerifyHashRefusesShortDerivedKey(t *testing.T) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	dk, err := scrypt.Key([]byte("the-real-password"), salt, 2, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	h := fmt.Sprintf(hashFormat, version, salt, 1, 1, 1, base64.RawStdEncoding.EncodeToString(dk))
	for i := 0; i < 4096; i++ {
		guess := fmt.Sprintf("guess-%d", i)
		if VerifyHash(h, guess) == nil {
			t.Fatalf("wrong password %q verified against a hash with a 1-byte derived key", guess)
		}
	}
}

// Regression: fmt.Sscanf stops at whitespace, so anything after the encoded
// key was silently ignored. Only the canonical form is a valid hash.
func TestVerifyHashRefusesTrailingJunk(t *testing.T) {
	for _, h := range []string{realRKE2Hash + " extra", realRKE2Hash + "\n", realRKE2Hash + " "} {
		if err := VerifyHash(h, realRKE2Password); err == nil {
			t.Errorf("%q verified despite trailing junk", h)
		}
	}
}

// Regression: every request ran scrypt (32 MiB, tens of ms) with no bound, so
// a burst of requests could exhaust memory. Concurrency must be capped.
func TestScryptConcurrencyIsBounded(t *testing.T) {
	var cur, peak atomic.Int64
	orig := scryptKey
	t.Cleanup(func() { scryptKey = orig })
	scryptKey = func(pw, salt []byte, n, r, p, l int) ([]byte, error) {
		c := cur.Add(1)
		for {
			old := peak.Load()
			if c <= old || peak.CompareAndSwap(old, c) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		cur.Add(-1)
		return make([]byte, l), nil
	}
	limit := int64(2 * runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for i := 0; i < int(limit)*4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = VerifyHash(realRKE2Hash, realRKE2Password)
		}()
	}
	wg.Wait()
	if peak.Load() > limit {
		t.Errorf("%d scrypt operations ran at once, want at most %d", peak.Load(), limit)
	}
}

// Waiting for a scrypt slot must give up when the request does, or a stalled
// queue holds every handler goroutine hostage.
func TestScryptWaitRespectsContext(t *testing.T) {
	for i := 0; i < cap(scryptSlots); i++ {
		scryptSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < cap(scryptSlots); i++ {
			<-scryptSlots
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := verifyHash(ctx, realRKE2Hash, realRKE2Password)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("gave up after %s", d)
	}
}

func TestValidatePassword(t *testing.T) {
	for _, pw := range []string{"", "1234567", string(make([]byte, 257))} {
		if ValidatePassword(pw) == nil {
			t.Errorf("password of %d bytes accepted", len(pw))
		}
	}
	for _, pw := range []string{realRKE2Password, "12345678", string(make([]byte, 256))} {
		if err := ValidatePassword(pw); err != nil {
			t.Errorf("password of %d bytes refused: %v", len(pw), err)
		}
	}
}
