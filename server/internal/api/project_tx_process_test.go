package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// pauseProjectStore is a child-process-only fault hook. It blocks either after
// PutRecord inside the uncommitted transaction or after the whole transaction
// committed. The parent kills the process at the observed marker.
type pauseProjectStore struct {
	store.Store
	stage, idem, marker string
	mu                  sync.Mutex
	matched             bool
}
type pauseBoundStore struct {
	store.Store
	root *pauseProjectStore
}

func (p *pauseBoundStore) PutRecord(projectID, idem string, rec store.Record) (store.Record, bool, error) {
	stored, created, err := p.Store.PutRecord(projectID, idem, rec)
	if err == nil && created && idem == p.root.idem {
		p.root.mu.Lock()
		p.root.matched = true
		p.root.mu.Unlock()
		if p.root.stage == "after_put" {
			p.root.pause()
		}
	}
	return stored, created, err
}
func (p *pauseBoundStore) PutRecoveryFence(f store.RecoveryFence) (store.RecoveryFence, bool, error) {
	stored, created, err := p.Store.PutRecoveryFence(f)
	if err == nil && created && p.root.stage == "after_recovery_fence" {
		p.root.mu.Lock()
		p.root.matched = true
		p.root.mu.Unlock()
	}
	return stored, created, err
}
func (p *pauseBoundStore) PutRecoveryResult(r store.RecoveryResult) (store.RecoveryResult, bool, error) {
	stored, created, err := p.Store.PutRecoveryResult(r)
	if err == nil && created {
		switch p.root.stage {
		case "before_recovery_terminal":
			p.root.pause()
		case "after_recovery_terminal":
			p.root.mu.Lock()
			p.root.matched = true
			p.root.mu.Unlock()
		}
	}
	return stored, created, err
}
func (p *pauseProjectStore) pause() {
	if err := os.WriteFile(p.marker, []byte(p.stage), 0600); err != nil {
		panic(err)
	}
	select {}
}
func (p *pauseProjectStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	err := p.Store.WithProjectWrite(ctx, projectID, func(bound store.Store) error { return fn(&pauseBoundStore{Store: bound, root: p}) })
	if err == nil && (p.stage == "after_commit" || p.stage == "after_recovery_fence" || p.stage == "after_recovery_terminal") {
		p.mu.Lock()
		matched := p.matched
		p.mu.Unlock()
		if matched {
			p.pause()
		}
	}
	return err
}

// This test executable becomes a real independent HTTP server process when
// launched with the child marker. Parent tests kill it at durability boundaries.
func TestProjectTxChildProcess(t *testing.T) {
	if os.Getenv("AVERIN_PROJECT_TX_CHILD") != "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := store.NewPostgres(ctx, os.Getenv("AVERIN_PROJECT_TX_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fs, err := content.NewFSStore(os.Getenv("AVERIN_PROJECT_TX_CONTENT"))
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
	if stage := os.Getenv("AVERIN_PROJECT_TX_PAUSE_STAGE"); stage != "" {
		projectStore = &pauseProjectStore{Store: st, stage: stage, idem: os.Getenv("AVERIN_PROJECT_TX_PAUSE_IDEM"), marker: os.Getenv("AVERIN_PROJECT_TX_PAUSE_MARKER")}
	}
	handler := api.New(recordingCore, projectStore, "k0").WithContent(fs).WithBroker(brokerIssuingKey()).WithCosigPolicy(1, []ed25519.PublicKey{approver.Public().(ed25519.PublicKey)}).WithResource(resourceCore, "orders-db").WithRevocation(revocationKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("AVERIN_PROJECT_TX_ADDR_FILE"), []byte(listener.Addr().String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := http.Serve(listener, handler); err != nil {
		t.Fatal(err)
	}
}

type projectTxProcess struct {
	cmd  *exec.Cmd
	addr string
	logs *lockedProcessLog
	once sync.Once
}

type lockedProcessLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedProcessLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}
func (l *lockedProcessLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.buf.String() }

func (p *projectTxProcess) stop() {
	p.once.Do(func() {
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
			_ = p.cmd.Wait()
		}
	})
}
func startProjectTxProcess(t *testing.T, dsn, contentDir string) *projectTxProcess {
	return startProjectTxPausedProcess(t, dsn, contentDir, "", "", "")
}
func startProjectTxPausedProcess(t *testing.T, dsn, contentDir, stage, idem, marker string) *projectTxProcess {
	t.Helper()
	addrFile := filepath.Join(t.TempDir(), "address")
	cmd := exec.Command(os.Args[0], "-test.run=^TestProjectTxChildProcess$")
	cmd.Env = append(os.Environ(), "AVERIN_PROJECT_TX_CHILD=1", "AVERIN_PROJECT_TX_DSN="+dsn, "AVERIN_PROJECT_TX_CONTENT="+contentDir, "AVERIN_PROJECT_TX_ADDR_FILE="+addrFile,
		"AVERIN_PROJECT_TX_PAUSE_STAGE="+stage, "AVERIN_PROJECT_TX_PAUSE_IDEM="+idem, "AVERIN_PROJECT_TX_PAUSE_MARKER="+marker)
	logs := &lockedProcessLog{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	process := &projectTxProcess{cmd: cmd, logs: logs}
	t.Cleanup(process.stop)
	deadline := time.Now().Add(10 * time.Second)
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
	t.Fatalf("child did not listen: %s", logs.String())
	return nil
}
func callProjectTxProcess(t *testing.T, process *projectTxProcess, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+process.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(path, "/v2/broker-seq/void") {
		req.Header.Set("Authorization", "Bearer test-recovery-token")
	}
	client := http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("child request: %v; logs: %s", err, process.logs.String())
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(data)
}

func TestProjectTransactionsProcessRestartBoundaries(t *testing.T) {
	pg, admin := newVoidTestPostgres(t)
	dsn := admin.Config().ConnConfig.ConnString()
	contentDir := t.TempDir()
	first := startProjectTxProcess(t, dsn, contentDir)
	second := startProjectTxProcess(t, dsn, contentDir)
	ak := grantAgentKey()
	request := grantBody("idem-process", "read:orders", ak, ak)
	code, body := callProjectTxProcess(t, first, "POST", "/v2/grants/prepare", request)
	if code != http.StatusOK {
		t.Fatalf("prepare (%d): %s", code, body)
	}
	var prepared prepareResp
	if err := json.Unmarshal([]byte(body), &prepared); err != nil {
		t.Fatal(err)
	}
	first.stop() // durable pending row survives issuer death
	approver := seedKey(40)
	kid := broker.KeyID(approver.Public().(ed25519.PublicKey))
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(approver, broker.CosigApprovalChallenge(prepared.GrantID, kid, prepared.CredentialBinding, 1, prepared.Exp)))
	final := finalizeBody(request, map[string]any{"cosignatures": []broker.Cosignature{{ApproverKid: kid, Sig: sig}}})
	code, body = callProjectTxProcess(t, second, "POST", "/v2/grants/finalize", final)
	if code != http.StatusCreated {
		t.Fatalf("finalize after issuer death (%d): %s", code, body)
	}
	var grant struct {
		GrantID    string `json:"grant_id"`
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal([]byte(body), &grant); err != nil || grant.GrantID != prepared.GrantID || grant.Capability == "" {
		t.Fatalf("grant mismatch: %v %s", err, body)
	}
	second.stop() // committed grant and descriptor survive finalizer death
	first = startProjectTxProcess(t, dsn, contentDir)
	if code, response := callProjectTxProcess(t, first, "POST", "/v2/grants/finalize", final); code != http.StatusCreated || !strings.Contains(response, `"created":false`) {
		t.Fatalf("exact retry after finalizer death (%d): %s", code, response)
	}
	revoke, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": grant.GrantID})
	if code, response := callProjectTxProcess(t, first, "POST", "/v2/revoke?project=p1", string(revoke)); code != http.StatusCreated {
		t.Fatalf("revoke (%d): %s", code, response)
	}
	first.stop() // revocation survives the acknowledging process death
	second = startProjectTxProcess(t, dsn, contentDir)
	if code, response := callProjectTxProcess(t, second, "POST", "/v2/use", useBody(t, "idem-use-process", grant.Capability, grant.GrantID, ak, "SELECT 1", "nonce-process")); code == http.StatusCreated {
		t.Fatalf("restarted replica admitted revoked grant: %s", response)
	}
	first = startProjectTxProcess(t, dsn, contentDir)
	var wg sync.WaitGroup
	errors := make(chan string, 2)
	for _, process := range []*projectTxProcess{first, second} {
		wg.Add(1)
		go func(p *projectTxProcess) {
			defer wg.Done()
			c, r := callProjectTxProcess(t, p, "POST", "/v2/checkpoints?project=p1", "")
			if c != http.StatusCreated {
				errors <- fmt.Sprintf("%d %s", c, r)
			}
		}(process)
	}
	wg.Wait()
	close(errors)
	for failure := range errors {
		t.Fatal(failure)
	}
	if cps, err := pg.Checkpoints("p1"); err != nil || len(cps) != 2 || cps[0].Seq == cps[1].Seq {
		t.Fatalf("process checkpoint chain: %+v %v", cps, err)
	}
	first.stop()
	second.stop() // checkpoint history survives both writers dying
	first = startProjectTxProcess(t, dsn, contentDir)
	if seq := reserveGrantSeq(t, pg, "idem-process-orphan"); seq != 2 {
		t.Fatalf("orphan seq=%d", seq)
	}
	if code, response := callProjectTxProcess(t, first, "POST", "/v2/broker-seq/void?project=p1", voidBody(2)); code != http.StatusCreated {
		t.Fatalf("void after checkpoint restarts (%d): %s", code, response)
	}
	first.stop() // tombstone and marker must survive together
	second = startProjectTxProcess(t, dsn, contentDir)
	if res := reservation(t, pg, 2); !res.Voided {
		t.Fatalf("marker lost on restart: %+v", res)
	}
	if _, found, err := pg.RecordByIdem("p1", "grant-void:2"); err != nil || !found {
		t.Fatalf("tombstone lost on restart: found=%v err=%v", found, err)
	}
	if code, response := callProjectTxProcess(t, second, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint after void restart (%d): %s", code, response)
	}
	if cps, err := pg.Checkpoints("p1"); err != nil || len(cps) != 3 {
		t.Fatalf("post-void checkpoint history: %+v %v", cps, err)
	}
}

type processReply struct {
	code int
	body string
	err  error
}

func sendProjectTxAsync(process *projectTxProcess, path, body string) <-chan processReply {
	done := make(chan processReply, 1)
	go func() {
		client := http.Client{Timeout: 15 * time.Second}
		req, err := http.NewRequest(http.MethodPost, "http://"+process.addr+path, strings.NewReader(body))
		if err != nil {
			done <- processReply{err: err}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if strings.HasPrefix(path, "/v2/broker-seq/void") {
			req.Header.Set("Authorization", "Bearer test-recovery-token")
		}
		response, err := client.Do(req)
		if err != nil {
			done <- processReply{err: err}
			return
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		done <- processReply{code: response.StatusCode, body: string(raw), err: err}
	}()
	return done
}
func waitProjectTxPause(t *testing.T, process *projectTxProcess, marker string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	process.stop()
	t.Fatalf("transaction cut point not reached: %s", process.logs.String())
}
func preparedProcessGrant(t *testing.T, process *projectTxProcess, idem string, ak ed25519.PrivateKey) (string, string) {
	t.Helper()
	request := grantBody(idem, "read:orders", ak, ak)
	code, body := callProjectTxProcess(t, process, "POST", "/v2/grants/prepare", request)
	if code != http.StatusOK {
		t.Fatalf("prepare %s (%d): %s", idem, code, body)
	}
	var prepared prepareResp
	if err := json.Unmarshal([]byte(body), &prepared); err != nil {
		t.Fatal(err)
	}
	approver := seedKey(40)
	kid := broker.KeyID(approver.Public().(ed25519.PublicKey))
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(approver, broker.CosigApprovalChallenge(prepared.GrantID, kid, prepared.CredentialBinding, 1, prepared.Exp)))
	return finalizeBody(request, map[string]any{"cosignatures": []broker.Cosignature{{ApproverKid: kid, Sig: sig}}}), prepared.GrantID
}
func processGrantResult(t *testing.T, body string) (string, string) {
	t.Helper()
	var result struct {
		GrantID    string `json:"grant_id"`
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil || result.GrantID == "" || result.Capability == "" {
		t.Fatalf("grant response: %v %s", err, body)
	}
	return result.GrantID, result.Capability
}

func TestProjectTransactionProcessCuts(t *testing.T) {
	pg, admin := newVoidTestPostgres(t)
	dsn, dir := admin.Config().ConnConfig.ConnString(), t.TempDir()
	peer := startProjectTxProcess(t, dsn, dir)
	ak := grantAgentKey()

	// Kill after an INSERT inside the open transaction: the grant record and
	// broker sequence must both roll back, and the peer must acquire the guard.
	finalize, grantID := preparedProcessGrant(t, peer, "idem-rollback-grant", ak)
	marker := filepath.Join(t.TempDir(), "after-put-grant")
	child := startProjectTxPausedProcess(t, dsn, dir, "after_put", "idem-rollback-grant", marker)
	inFlight := sendProjectTxAsync(child, "/v2/grants/finalize", finalize)
	waitProjectTxPause(t, child, marker)
	child.stop()
	<-inFlight
	if _, found, err := pg.RecordByIdem("p1", "idem-rollback-grant"); err != nil || found {
		t.Fatalf("uncommitted grant survived kill: %v %v", found, err)
	}
	if max, err := pg.MaxBrokerSeq("p1"); err != nil || max != 0 {
		t.Fatalf("uncommitted seq survived kill: %d %v", max, err)
	}
	if code, body := callProjectTxProcess(t, peer, "POST", "/v2/grants/finalize", finalize); code != http.StatusCreated {
		t.Fatalf("peer could not finalize after rollback (%d): %s", code, body)
	} else {
		gotID, capability := processGrantResult(t, body)
		if gotID != grantID {
			t.Fatalf("grant changed identity: %s != %s", gotID, grantID)
		}
		// Kill a use receipt after its INSERT; nonce/JTI claims share its rollback.
		use := useBody(t, "idem-rollback-use", capability, grantID, ak, "SELECT 1", "nonce-rollback")
		marker = filepath.Join(t.TempDir(), "after-put-use")
		child = startProjectTxPausedProcess(t, dsn, dir, "after_put", "idem-rollback-use", marker)
		inFlight = sendProjectTxAsync(child, "/v2/use", use)
		waitProjectTxPause(t, child, marker)
		child.stop()
		<-inFlight
		if _, found, err := pg.RecordByIdem("p1", "idem-rollback-use"); err != nil || found {
			t.Fatalf("uncommitted use survived kill: %v %v", found, err)
		}
		if code, response := callProjectTxProcess(t, peer, "POST", "/v2/use", use); code != http.StatusCreated {
			t.Fatalf("rolled-back nonce/JTI blocked exact retry (%d): %s", code, response)
		}
	}

	// Kill after COMMIT but before the response: the peer must return the
	// original grant under the exact idempotency key, with one durable seq.
	finalize, grantID = preparedProcessGrant(t, peer, "idem-committed-grant", ak)
	marker = filepath.Join(t.TempDir(), "after-commit-grant")
	child = startProjectTxPausedProcess(t, dsn, dir, "after_commit", "idem-committed-grant", marker)
	inFlight = sendProjectTxAsync(child, "/v2/grants/finalize", finalize)
	waitProjectTxPause(t, child, marker)
	child.stop()
	<-inFlight
	stored, found, err := pg.RecordByIdem("p1", "idem-committed-grant")
	if err != nil || !found {
		t.Fatalf("committed grant missing after kill: %v %v", found, err)
	}
	code, body := callProjectTxProcess(t, peer, "POST", "/v2/grants/finalize", finalize)
	if code != http.StatusCreated || !strings.Contains(body, `"created":false`) || !strings.Contains(body, stored.ContentHash) {
		t.Fatalf("exact grant retry did not return committed result (%d): %s", code, body)
	}
	gotID, capability := processGrantResult(t, body)
	if gotID != grantID {
		t.Fatalf("replayed grant changed identity: %s", gotID)
	}
	if max, err := pg.MaxBrokerSeq("p1"); err != nil || max != 2 {
		t.Fatalf("duplicate or lost seq after commit cut: %d %v", max, err)
	}

	// The same post-commit cut on /v2/use must preserve its consumed claims
	// and return the one original receipt on exact retry.
	use := useBody(t, "idem-committed-use", capability, grantID, ak, "SELECT 2", "nonce-committed")
	marker = filepath.Join(t.TempDir(), "after-commit-use")
	child = startProjectTxPausedProcess(t, dsn, dir, "after_commit", "idem-committed-use", marker)
	inFlight = sendProjectTxAsync(child, "/v2/use", use)
	waitProjectTxPause(t, child, marker)
	child.stop()
	<-inFlight
	stored, found, err = pg.RecordByIdem("p1", "idem-committed-use")
	if err != nil || !found {
		t.Fatalf("committed use missing after kill: %v %v", found, err)
	}
	code, body = callProjectTxProcess(t, peer, "POST", "/v2/use", use)
	if code != http.StatusCreated || !strings.Contains(body, `"idempotent":true`) || !strings.Contains(body, stored.ContentHash) {
		t.Fatalf("exact use retry did not return original receipt (%d): %s", code, body)
	}
	if count, err := pg.RecordCount("p1"); err != nil || count != 4 {
		t.Fatalf("unexpected record count after cuts: %d %v", count, err)
	}
}

func TestBrokerSeqRecoveryProcessCrashCutsPostgres(t *testing.T) {
	for _, tc := range []struct {
		stage          string
		terminalBefore bool
	}{
		{"after_recovery_fence", false},
		{"before_recovery_terminal", false},
		{"after_recovery_terminal", true},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			pg, admin := newVoidTestPostgres(t)
			reserveGrantSeq(t, pg, "crash-orphan")
			dsn, dir := admin.Config().ConnConfig.ConnString(), t.TempDir()
			marker := filepath.Join(t.TempDir(), "recovery-cut")
			child := startProjectTxPausedProcess(t, dsn, dir, tc.stage, "", marker)
			inFlight := sendProjectTxAsync(child, "/v2/broker-seq/void?project=p1", voidBody(1))
			waitProjectTxPause(t, child, marker)
			child.stop()
			<-inFlight // the lost HTTP response is never treated as a rollback proof.
			if f, found, err := pg.RecoveryFenceAt("p1", 1); err != nil || !found || f.OperationID != "recovery-test-1" {
				t.Fatalf("fence did not survive process kill: %+v %v %v", f, found, err)
			}
			result, found, err := pg.RecoveryResultAt("p1", 1)
			if err != nil || found != tc.terminalBefore || (found && result.Outcome != "voided") {
				t.Fatalf("wrong terminal state across process kill: %+v %v %v", result, found, err)
			}
			if res := reservation(t, pg, 1); res.Voided != tc.terminalBefore {
				t.Fatalf("marker survived independently of terminal transaction: %+v", res)
			}
			if _, found, err := pg.RecordByIdem("p1", "grant-void:1"); err != nil || found != tc.terminalBefore {
				t.Fatalf("tombstone survived independently of terminal transaction: %v %v", found, err)
			}
			grantID := reservation(t, pg, 1).GrantID
			if ids, err := pg.RevokedGrantIDs("p1"); err != nil || len(ids) != btoi(tc.terminalBefore) || (tc.terminalBefore && ids[0] != grantID) {
				t.Fatalf("revocation survived independently of terminal transaction: %v %v", ids, err)
			}
			peer := startProjectTxProcess(t, dsn, dir)
			code, body := callProjectTxProcess(t, peer, http.MethodPost, "/v2/broker-seq/void?project=p1", voidBody(1))
			want := http.StatusCreated
			if tc.terminalBefore {
				want = http.StatusOK
			}
			if code != want || !strings.Contains(body, `"outcome":"voided"`) || !strings.Contains(body, `"winning_record_hash":"sha256:`) {
				t.Fatalf("new process did not converge after %s: %d %s", tc.stage, code, body)
			}
			if result, found, err := pg.RecoveryResultAt("p1", 1); err != nil || !found || result.Outcome != "voided" {
				t.Fatalf("new process left recovery incomplete: %+v %v %v", result, found, err)
			}
			if ids, err := pg.RevokedGrantIDs("p1"); err != nil || len(ids) != 1 || ids[0] != grantID {
				t.Fatalf("new process did not publish one durable revoke: %v %v", ids, err)
			}
		})
	}
}
