package api_test

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// The multi-writer matrix runs real averin HTTP servers as separate operating-system processes
// (this test binary re-executed), all on one PostgreSQL schema. A process can be told to hold at one
// named point inside its open project transaction, with the project guard row locked, until the
// parent releases it or kills it. The hold is a store wrapper compiled into this test binary only:
// no fault point exists in the shipped server, so there is nothing to put behind a build tag.
//
// Hold points (AVERIN_MW_POINT), each matched against AVERIN_MW_KEY when that is set:
//
//	use_after_revocation_read  IsRevoked answered "not revoked" for grant KEY (inside a use)
//	after_put_record           a record under idempotency key KEY was inserted, uncommitted
//	after_pending_put          the pending grant row of prepare under key KEY was inserted, uncommitted
//	after_revocation_event     the revocation event of grant KEY was inserted, uncommitted
//	after_recovery_fence_commit the recovery fence transaction has committed (between the two transactions)
//	after_recovery_result_put  the terminal recovery result was inserted, uncommitted
type mwFault struct {
	Point, Key, Marker, Release string
}

type mwStore struct {
	store.Store
	f       mwFault
	mu      sync.Mutex
	held    bool
	matched bool
}

type mwBound struct {
	store.Store
	root *mwStore
}

func (m *mwStore) want(point, key string) bool {
	return m.f.Point == point && (m.f.Key == "" || m.f.Key == key)
}

// hold blocks at most once per process: it writes the marker file, then waits for the release file.
func (m *mwStore) hold(point string) {
	m.mu.Lock()
	if m.held {
		m.mu.Unlock()
		return
	}
	m.held = true
	m.mu.Unlock()
	if err := os.WriteFile(m.f.Marker, []byte(point), 0o600); err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(m.f.Release); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (m *mwStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	err := m.Store.WithProjectWrite(ctx, projectID, func(bound store.Store) error { return fn(&mwBound{Store: bound, root: m}) })
	m.mu.Lock()
	matched := m.matched
	m.mu.Unlock()
	if err == nil && matched && m.f.Point == "after_recovery_fence_commit" {
		m.hold(m.f.Point)
	}
	return err
}

func (b *mwBound) IsRevoked(projectID, grantID string) (bool, error) {
	revoked, err := b.Store.IsRevoked(projectID, grantID)
	if err == nil && !revoked && b.root.want("use_after_revocation_read", grantID) {
		b.root.hold("use_after_revocation_read")
	}
	return revoked, err
}

func (b *mwBound) PutRecord(projectID, idem string, rec store.Record) (store.Record, bool, error) {
	stored, created, err := b.Store.PutRecord(projectID, idem, rec)
	if err == nil && created && b.root.want("after_put_record", idem) {
		b.root.hold("after_put_record")
	}
	return stored, created, err
}

func (b *mwBound) PutPendingGrant(projectID, idem string, row store.PendingGrant) (store.PendingGrant, bool, error) {
	stored, created, err := b.Store.PutPendingGrant(projectID, idem, row)
	if err == nil && created && b.root.want("after_pending_put", idem) {
		b.root.hold("after_pending_put")
	}
	return stored, created, err
}

func (b *mwBound) PutRevocationEvent(ev store.RevocationEvent) (store.RevocationEvent, bool, error) {
	stored, created, err := b.Store.PutRevocationEvent(ev)
	if err == nil && created && b.root.want("after_revocation_event", ev.GrantID) {
		b.root.hold("after_revocation_event")
	}
	return stored, created, err
}

func (b *mwBound) PutRecoveryFence(f store.RecoveryFence) (store.RecoveryFence, bool, error) {
	stored, created, err := b.Store.PutRecoveryFence(f)
	if err == nil && created && b.root.f.Point == "after_recovery_fence_commit" {
		b.root.mu.Lock()
		b.root.matched = true
		b.root.mu.Unlock()
	}
	return stored, created, err
}

func (b *mwBound) PutRecoveryResult(r store.RecoveryResult) (store.RecoveryResult, bool, error) {
	stored, created, err := b.Store.PutRecoveryResult(r)
	if err == nil && created && b.root.want("after_recovery_result_put", "") {
		b.root.hold("after_recovery_result_put")
	}
	return stored, created, err
}

// TestMultiWriterChildProcess is the server half: when launched by the matrix with the child marker
// it becomes one independent averin replica and serves until it is killed.
func TestMultiWriterChildProcess(t *testing.T) {
	if os.Getenv("AVERIN_MW_CHILD") != "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := store.NewPostgres(ctx, os.Getenv("AVERIN_MW_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fs, err := content.NewFSStore(os.Getenv("AVERIN_MW_CONTENT"))
	if err != nil {
		t.Fatal(err)
	}
	recordingCore, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	resourceCore, err := core.New(resourceSeed)
	if err != nil {
		t.Fatal(err)
	}
	approver := seedKey(40)
	var projectStore store.Store = st
	if point := os.Getenv("AVERIN_MW_POINT"); point != "" {
		projectStore = &mwStore{Store: st, f: mwFault{Point: point, Key: os.Getenv("AVERIN_MW_KEY"), Marker: os.Getenv("AVERIN_MW_MARKER"), Release: os.Getenv("AVERIN_MW_RELEASE")}}
	}
	srv := api.New(recordingCore, projectStore, "k0").WithContent(fs).WithBroker(brokerIssuingKey()).
		WithCosigPolicy(1, []ed25519.PublicKey{approver.Public().(ed25519.PublicKey)}).
		WithResource(resourceCore, "orders-db").WithRevocation(revocationKey()).WithRevocationExportV2().
		WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("AVERIN_MW_ADDR_FILE"), []byte(listener.Addr().String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := http.Serve(listener, srv.Routes()); err != nil {
		t.Fatal(err)
	}
}

// startMW launches one replica. dsn may point at a pgFaultProxy. A zero fault runs without a hold.
func startMW(t *testing.T, dsn, contentDir string, f mwFault) *projectTxProcess {
	t.Helper()
	addrFile := filepath.Join(t.TempDir(), "address")
	cmd := exec.Command(os.Args[0], "-test.run=^TestMultiWriterChildProcess$", "-test.count=1", "-test.timeout=30m")
	cmd.Env = append(os.Environ(), "AVERIN_MW_CHILD=1", "AVERIN_MW_DSN="+dsn, "AVERIN_MW_CONTENT="+contentDir, "AVERIN_MW_ADDR_FILE="+addrFile,
		"AVERIN_MW_POINT="+f.Point, "AVERIN_MW_KEY="+f.Key, "AVERIN_MW_MARKER="+f.Marker, "AVERIN_MW_RELEASE="+f.Release)
	logs := &lockedProcessLog{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	process := &projectTxProcess{cmd: cmd, logs: logs}
	t.Cleanup(process.stop)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(addrFile); err == nil {
			process.addr = string(raw)
			conn, err := net.DialTimeout("tcp", process.addr, 200*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return process
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	process.stop()
	t.Fatalf("multi-writer child did not listen: %s", logs.String())
	return nil
}

// mwHold is a started replica that will hold at fault.Point; the parent waits for reached(), then
// calls release() to let it continue, or kills the process to model a crash at that point.
type mwHold struct {
	*projectTxProcess
	marker, release string
}

func startMWHold(t *testing.T, dsn, contentDir, point, key string) *mwHold {
	t.Helper()
	dir := t.TempDir()
	h := &mwHold{marker: filepath.Join(dir, "reached"), release: filepath.Join(dir, "release")}
	h.projectTxProcess = startMW(t, dsn, contentDir, mwFault{Point: point, Key: key, Marker: h.marker, Release: h.release})
	return h
}

func (h *mwHold) waitReached(t *testing.T) {
	t.Helper()
	waitProjectTxPause(t, h.projectTxProcess, h.marker)
}

func (h *mwHold) letGo(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(h.release, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
}
