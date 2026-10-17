// Package tunnel serves /v1-rke2/connect using rancher/remotedialer - the same
// library a real rke2 server uses, so the wire protocol is identical by
// construction rather than by reimplementation.
//
// remotedialer v0.6.1 exposes no way to bound what a peer may send: it builds
// its websocket.Upgrader inside Server.ServeHTTP, never calls SetReadLimit on
// the connection, and reads SyncConnections bodies with io.ReadAll. One
// authenticated agent could therefore make the shim buffer a message of any
// size. This package wraps the handler from the outside: it caps sessions per
// node, and caps websocket message size by parsing frame headers on the
// hijacked connection before gorilla/websocket sees the bytes.
package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/rancher/remotedialer"
)

const (
	// The shim never dials through the tunnel, so the agent has no
	// connections to report: legitimate messages are a few varints. 16 KiB
	// still clears remotedialer's own largest frame (MaxRead 8 KiB of data plus
	// header) in case that ever changes.
	maxMessageBytes = 16 << 10
	// An agent opens one tunnel per supervisor address it knows (the fan-out
	// in docs/protocol.md), so one per shim; the second slot absorbs a
	// reconnect that races the old session's teardown.
	maxSessionsPerNode = 2
)

// New returns the tunnel handler, authenticating agents by their mTLS client
// certificate.
func New(log *slog.Logger) http.Handler {
	return newHandler(authorizeNode(log), log)
}

// authorizeNode accepts exactly the identity the Kubernetes Node authorizer
// accepts: CN=system:node:<name> with O=system:nodes. Without the prefix
// check any client cert the shim issues (system:kube-proxy,
// system:rke2-controller) could open a tunnel as if it were a node; without
// the O check, a CN-only certificate could.
func authorizeNode(log *slog.Logger) remotedialer.Authorizer {
	return func(req *http.Request) (string, bool, error) {
		// mTLS: identity comes from the verified peer certificate.
		if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
			return "", false, nil
		}
		subj := req.TLS.PeerCertificates[0].Subject
		node, isNode := strings.CutPrefix(subj.CommonName, "system:node:")
		if !isNode || node == "" || !slices.Contains(subj.Organization, "system:nodes") {
			log.Warn("rejecting tunnel from non-node identity",
				"cn", subj.CommonName, "o", subj.Organization)
			return "", false, nil
		}
		return node, true, nil
	}
}

type nodeKey struct{}

type handler struct {
	auth  remotedialer.Authorizer
	inner http.Handler
	log   *slog.Logger

	mu     sync.Mutex
	active map[string]int
}

func newHandler(auth remotedialer.Authorizer, log *slog.Logger) http.Handler {
	h := &handler{auth: auth, log: log, active: map[string]int{}}
	// Authorization happens once, in ServeHTTP; remotedialer reads the result
	// back from the request context. Unauthenticated requests are handed to
	// remotedialer with no node, so it answers them exactly as it always has.
	h.inner = remotedialer.New(func(r *http.Request) (string, bool, error) {
		node, ok := r.Context().Value(nodeKey{}).(string)
		return node, ok, nil
	}, remotedialer.DefaultErrorWriter)
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	node, ok, err := h.auth(r)
	if err != nil || !ok {
		h.inner.ServeHTTP(w, r)
		return
	}
	if !h.acquire(node) {
		h.log.Warn("refusing tunnel: too many concurrent sessions for this node",
			"node", node, "limit", maxSessionsPerNode, "remote", r.RemoteAddr)
		http.Error(w, "too many tunnel sessions for this node", http.StatusTooManyRequests)
		return
	}
	defer h.release(node)
	h.log.Info("tunnel connected", "node", node, "remote", r.RemoteAddr)
	// ServeHTTP blocks for the life of the session, so the slot is held
	// exactly as long as the session is.
	r = r.WithContext(context.WithValue(r.Context(), nodeKey{}, node))
	h.inner.ServeHTTP(&limitedWriter{ResponseWriter: w, max: maxMessageBytes}, r)
}

func (h *handler) acquire(node string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active[node] >= maxSessionsPerNode {
		return false
	}
	h.active[node]++
	return true
}

func (h *handler) release(node string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active[node]--; h.active[node] <= 0 {
		delete(h.active, node)
	}
}

// limitedWriter hands gorilla/websocket a hijacked connection whose reads pass
// through frameLimitConn. gorilla obtains the connection through
// http.NewResponseController(w).Hijack(), which uses this Hijack.
type limitedWriter struct {
	http.ResponseWriter
	max int64
}

func (w *limitedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *limitedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// Bytes net/http already buffered belong to the websocket stream and must
	// be inspected too, so they are replayed through the limiter.
	var src io.Reader = conn
	if n := brw.Reader.Buffered(); n > 0 {
		pending, _ := brw.Reader.Peek(n)
		src = io.MultiReader(bytes.NewReader(bytes.Clone(pending)), conn)
	}
	lc := &frameLimitConn{Conn: conn, src: src, max: w.max}
	// A fresh reader over the limiter: gorilla adopts it as its read buffer
	// (or wraps the conn), and either way every byte it reads went through lc.
	return lc, bufio.NewReadWriter(bufio.NewReaderSize(lc, 4096), brw.Writer), nil
}

var errMessageTooLarge = errors.New("tunnel: websocket message exceeds size limit")

// frameLimitConn follows RFC 6455 framing on the client-to-server stream and
// fails the read once a data message (a frame plus its continuations) exceeds
// max payload bytes. Writes pass through untouched.
type frameLimitConn struct {
	net.Conn
	src io.Reader
	max int64

	hdr     []byte // header bytes of the frame being parsed
	payload uint64 // payload bytes of the current frame still to pass
	msg     int64  // payload bytes in the current data message so far
	err     error
}

func (c *frameLimitConn) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.src.Read(p)
	if ierr := c.inspect(p[:n]); ierr != nil {
		c.err = ierr
		_ = c.Conn.Close()
		return 0, ierr
	}
	return n, err
}

func (c *frameLimitConn) inspect(b []byte) error {
	for len(b) > 0 {
		if c.payload > 0 {
			k := min(c.payload, uint64(len(b)))
			c.payload -= k
			b = b[k:]
			continue
		}
		c.hdr = append(c.hdr, b[0])
		b = b[1:]
		need, ok := headerLen(c.hdr)
		if !ok || len(c.hdr) < need {
			continue
		}
		opcode := c.hdr[0] & 0x0f
		length := payloadLen(c.hdr)
		c.hdr = c.hdr[:0]
		switch {
		case opcode >= 0x8:
			// Control frames are capped at 125 bytes by RFC 6455 and
			// gorilla enforces it; they do not belong to a data message.
		case opcode == 0x0:
			if length > uint64(c.max) || c.msg+int64(length) > c.max {
				return fmt.Errorf("%w (%d bytes)", errMessageTooLarge, c.max)
			}
			c.msg += int64(length)
		default:
			if length > uint64(c.max) {
				return fmt.Errorf("%w (%d bytes)", errMessageTooLarge, c.max)
			}
			c.msg = int64(length)
		}
		c.payload = length
	}
	return nil
}

// headerLen reports the full header length of a frame once enough of it is
// known to tell (the first two bytes).
func headerLen(h []byte) (int, bool) {
	if len(h) < 2 {
		return 0, false
	}
	n := 2
	switch h[1] & 0x7f {
	case 126:
		n += 2
	case 127:
		n += 8
	}
	if h[1]&0x80 != 0 { // masked, as every client frame must be
		n += 4
	}
	return n, true
}

func payloadLen(h []byte) uint64 {
	switch l := h[1] & 0x7f; l {
	case 126:
		return uint64(binary.BigEndian.Uint16(h[2:4]))
	case 127:
		return binary.BigEndian.Uint64(h[2:10])
	default:
		return uint64(l)
	}
}
