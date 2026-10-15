package api_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// pgFaultProxy is the in-test TCP proxy of the multi-writer matrix (no toxiproxy). It sits between
// one averin process and PostgreSQL and understands just enough of the wire protocol to find the
// COMMIT of a project write transaction, which pgx sends as a simple-protocol 'Q' message. A write
// transaction is recognised by its first statement, SET LOCAL lock_timeout, which only
// WithProjectWrite issues; read transactions and everything else pass untouched. Armed with a cut
// the proxy loses the acknowledgment of exactly one such COMMIT:
//
//	pgCutBeforeCommit: the COMMIT never reaches the server. The connection is closed, so the server
//	                   rolls the transaction back; the process sees an unknown outcome.
//	pgCutAfterCommit:  the COMMIT is forwarded and the server commits. The reply (up to and
//	                   including ReadyForQuery) is swallowed and the connection is closed; the
//	                   process again sees an unknown outcome, but the transaction is durable.
//
// Only the frontend direction needs typed framing after the startup packet, and only the backend
// direction needs it to find ReadyForQuery, so both are framed. TLS is not proxied: the DSN given to
// the process always carries sslmode=disable.
type pgFaultProxy struct {
	ln       net.Listener
	upstream string
	mode     atomic.Int32
	fired    atomic.Int32
	mu       sync.Mutex
	conns    []net.Conn
}

const (
	pgCutOff          = 0
	pgCutBeforeCommit = 1
	pgCutAfterCommit  = 2
)

func newPGFaultProxy(t *testing.T, upstreamDSN string) (*pgFaultProxy, string) {
	t.Helper()
	u, err := url.Parse(upstreamDSN)
	if err != nil {
		t.Fatalf("parse upstream dsn: %v", err)
	}
	upstream := u.Host
	if u.Port() == "" {
		upstream = net.JoinHostPort(u.Hostname(), "5432")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &pgFaultProxy{ln: ln, upstream: upstream}
	t.Cleanup(p.close)
	go p.accept()
	q := u.Query()
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()
	u.Host = ln.Addr().String()
	return p, u.String()
}

// arm makes the next COMMIT through the proxy take the given cut and resets the fired counter.
func (p *pgFaultProxy) arm(mode int32) {
	p.fired.Store(0)
	p.mode.Store(mode)
}

func (p *pgFaultProxy) close() {
	_ = p.ln.Close()
	p.mu.Lock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
}

func (p *pgFaultProxy) track(c net.Conn) {
	p.mu.Lock()
	p.conns = append(p.conns, c)
	p.mu.Unlock()
}

func (p *pgFaultProxy) accept() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *pgFaultProxy) handle(client net.Conn) {
	server, err := net.Dial("tcp", p.upstream)
	if err != nil {
		_ = client.Close()
		return
	}
	p.track(client)
	p.track(server)
	var once sync.Once
	closeBoth := func() { once.Do(func() { _ = client.Close(); _ = server.Close() }) }
	var swallow atomic.Bool
	go func() {
		defer closeBoth()
		p.backend(server, client, &swallow, closeBoth)
	}()
	defer closeBoth()
	p.frontend(client, server, &swallow, closeBoth)
}

// frontend forwards client messages, cutting at the armed COMMIT.
func (p *pgFaultProxy) frontend(client, server net.Conn, swallow *atomic.Bool, closeBoth func()) {
	var head [4]byte
	if _, err := io.ReadFull(client, head[:]); err != nil { // startup packet: length, then payload
		return
	}
	n := binary.BigEndian.Uint32(head[:])
	if n < 4 || n > 1<<20 {
		return
	}
	startup := make([]byte, int(n)-4)
	if _, err := io.ReadFull(client, startup); err != nil {
		return
	}
	if _, err := server.Write(append(head[:], startup...)); err != nil {
		return
	}
	writeTx := false
	for {
		var typ [1]byte
		if _, err := io.ReadFull(client, typ[:]); err != nil {
			return
		}
		if _, err := io.ReadFull(client, head[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(head[:])
		if n < 4 || n > 1<<26 {
			return
		}
		payload := make([]byte, int(n)-4)
		if _, err := io.ReadFull(client, payload); err != nil {
			return
		}
		if typ[0] == 'Q' && isBegin(payload) {
			writeTx = false
		}
		if typ[0] == 'Q' && isSetLockTimeout(payload) {
			writeTx = true
		}
		if typ[0] == 'Q' && isCommitQuery(payload) {
			armed := writeTx
			writeTx = false
			if armed && p.mode.CompareAndSwap(pgCutBeforeCommit, pgCutOff) {
				p.fired.Add(1)
				closeBoth()
				return
			}
			if armed && p.mode.CompareAndSwap(pgCutAfterCommit, pgCutOff) {
				p.fired.Add(1)
				swallow.Store(true)
			}
		}
		msg := append(append(typ[:], head[:]...), payload...)
		if _, err := server.Write(msg); err != nil {
			return
		}
	}
}

// backend forwards server messages. After an after-commit cut it discards everything through the
// ReadyForQuery that ends the COMMIT and closes both sides, so the client never sees the result.
func (p *pgFaultProxy) backend(server, client net.Conn, swallow *atomic.Bool, closeBoth func()) {
	var hdr [5]byte
	for {
		if _, err := io.ReadFull(server, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[1:])
		if n < 4 || n > 1<<26 {
			return
		}
		payload := make([]byte, int(n)-4)
		if _, err := io.ReadFull(server, payload); err != nil {
			return
		}
		if swallow.Load() {
			if hdr[0] == 'Z' {
				closeBoth()
				return
			}
			continue
		}
		if _, err := client.Write(append(hdr[:], payload...)); err != nil {
			return
		}
	}
}

func isBegin(payload []byte) bool {
	sql := strings.ToLower(strings.TrimSpace(string(bytes.TrimRight(payload, "\x00"))))
	return strings.HasPrefix(sql, "begin") || strings.HasPrefix(sql, "start transaction")
}

func isSetLockTimeout(payload []byte) bool {
	sql := strings.ToLower(strings.TrimSpace(string(bytes.TrimRight(payload, "\x00"))))
	return strings.HasPrefix(sql, "set local lock_timeout")
}

func isCommitQuery(payload []byte) bool {
	sql := strings.ToLower(strings.TrimSpace(string(bytes.TrimRight(payload, "\x00"))))
	return sql == "commit" || sql == "commit;" || sql == "end"
}
