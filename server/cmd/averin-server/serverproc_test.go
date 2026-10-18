package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Every test that executes averin-server (or re-executes this test binary as a stand-in) goes through
// this file, so a server that wrongly keeps running can neither hang the test nor outlive it
// (feir-ops#13: servers were found running for days, reparented to PID 1, after a mutant run).
//
// The child stays in the test binary's process group on purpose: the formal mutant runner starts each
// detector in its own session and kills that whole session after the detector exits, whatever the exit
// (normal, non-zero, timeout, or an interrupt of the runner), so a child in the same group is reaped
// even when go test's own timeout kills this binary before any cleanup runs. On Linux the child also
// gets PDEATHSIG (serverproc_linux_test.go) so it dies with the test binary regardless. Outside the
// mutant runner, off Linux, a plain "go test" that dies before cleanup can still orphan the server.

// refusalBound is how long a server that is meant to refuse to start may run before the test fails it.
const refusalBound = 30 * time.Second

// httpBound caps every single HTTP request a test makes to a live server, so the loop deadline around it
// is a real bound and not a hope (a handler that never answers must not hang the test).
const httpBound = 5 * time.Second

// serverClient is the HTTP client for tests that talk to a live server.
var serverClient = &http.Client{Timeout: httpBound}

// refusalResult is what a refuse-to-start run did.
type refusalResult struct {
	Out      string
	Err      error // nil when the process exited zero; *exec.ExitError for a non-zero exit
	TimedOut bool  // still running at the bound: it did not refuse, it was killed
	Pid      int
}

// runRefusal runs bin with env until it exits or the bound passes. The context kills a process still
// running at the bound and Wait reaps it, so when this returns the process is dead and reaped.
func runRefusal(t testing.TB, bin string, args, env []string, bound time.Duration) refusalResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	confineChild(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	pid := cmd.Process.Pid
	// If the test dies between Start and Wait, the cleanup still kills what is running.
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	err := cmd.Wait()
	return refusalResult{Out: buf.String(), Err: err, TimedOut: ctx.Err() != nil, Pid: pid}
}

// requireRefusal fails the test unless res is a log.Fatal refusal: it did not time out, it exited with
// code 1 (not a signal, not a Go panic which exits 2), and its output carries no crash marker.
func requireRefusal(t testing.TB, res refusalResult) {
	t.Helper()
	if res.TimedOut {
		t.Fatalf("the process did not refuse to start within %s (it kept running and was killed)\n%s", refusalBound, res.Out)
	}
	var ee *exec.ExitError
	if !errors.As(res.Err, &ee) {
		t.Fatalf("expected a refusal (exit code 1), got %v\n%s", res.Err, res.Out)
	}
	if ee.ExitCode() != 1 {
		t.Fatalf("expected exit code 1 from log.Fatal, got %v (a signal reports -1, a Go panic 2)\n%s", ee, res.Out)
	}
	for _, crash := range []string{"panic:", "fatal error:", "SIGSEGV", "goroutine 1 ["} {
		if strings.Contains(res.Out, crash) {
			t.Fatalf("the refusal looks like a crash (%q in the output)\n%s", crash, res.Out)
		}
	}
}

// startServerExpectRefusal is the helper refuse-to-start tests use: it fails the test unless the
// process refuses (see requireRefusal) within the bound, and returns its combined output for the
// caller's assertions on the refusal text.
func startServerExpectRefusal(t testing.TB, bin string, args, env []string) string {
	t.Helper()
	res := runRefusal(t, bin, args, env, refusalBound)
	requireRefusal(t, res)
	return res.Out
}

// startServerProc starts a long-running server for a test and registers its kill; the returned stop
// is idempotent and may be called early.
func startServerProc(t testing.TB, bin string, env []string) (stop func()) {
	t.Helper()
	stop, _ = startServerProcArgs(t, bin, nil, env)
	return stop
}

func startServerProcArgs(t testing.TB, bin string, args, env []string) (stop func(), pid int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	confineChild(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid = cmd.Process.Pid
	stop = sync.OnceFunc(func() {
		if !killAndReap(cmd) {
			t.Errorf("averin-server pid %d was not reaped within 10s of SIGKILL", pid)
		}
	})
	t.Cleanup(stop)
	return stop, pid
}

// killAndReap kills cmd's process and waits for it, reporting whether it was reaped within 10s. It
// must be called at most once per cmd (Wait is single-use).
func killAndReap(cmd *exec.Cmd) (reaped bool) {
	_ = cmd.Process.Kill()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(10 * time.Second):
		return false
	}
}

func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// TestHelperHangingServer is the stand-in for a server that wrongly does not refuse: it only runs when
// re-executed by TestRunRefusal_*, and never exits on its own.
func TestHelperHangingServer(t *testing.T) {
	if os.Getenv("AVERIN_TEST_HANGING_SERVER") != "1" {
		t.Skip("helper process for TestRunRefusal_*")
	}
	time.Sleep(time.Hour)
}

// A server that keeps running is reported within the bound, and what the harness did is a kill.
func TestRunRefusal_NonRefusingServerIsBoundedAndKilled(t *testing.T) {
	start := time.Now()
	res := runRefusal(t, os.Args[0], []string{"-test.run=^TestHelperHangingServer$"},
		[]string{"AVERIN_TEST_HANGING_SERVER=1"}, 2*time.Second)
	if !res.TimedOut {
		t.Fatalf("a never-exiting process must be reported as not having refused: %+v", res)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("the bound was not honoured: took %s", took)
	}
	var ee *exec.ExitError
	if !errors.As(res.Err, &ee) {
		t.Fatalf("a process killed at the bound must report an ExitError: %v", res.Err)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("the process must have been SIGKILLed at the bound: %v", ee)
	}
	// requireRefusal must not accept it as a refusal.
	ft := &fakeT{}
	func() {
		defer func() { _ = recover() }()
		requireRefusal(ft, res)
	}()
	if !ft.failed {
		t.Fatal("requireRefusal accepted a process that was killed at the bound")
	}
}

// requireRefusal accepts exactly a log.Fatal refusal: a signal death and a Go panic are not one.
func TestRequireRefusal_RejectsSignalsAndPanics(t *testing.T) {
	cases := []struct {
		name   string
		script string
		accept bool
	}{
		{"fatal", "echo 'boom' >&2; exit 1", true},
		{"panic-exit-2", "echo 'panic: boom' >&2; exit 2", false},
		{"crash-text-at-exit-1", "echo 'panic: boom' >&2; exit 1", false},
		{"killed-by-signal", "kill -KILL $$", false},
		{"clean-exit", "exit 0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runRefusal(t, "sh", []string{"-c", tc.script}, []string{"PATH=" + os.Getenv("PATH")}, 10*time.Second)
			ft := &fakeT{}
			func() {
				defer func() { _ = recover() }()
				requireRefusal(ft, res)
			}()
			if ft.failed == tc.accept {
				t.Fatalf("accept=%v but requireRefusal failed=%v for %+v", tc.accept, ft.failed, res)
			}
		})
	}
}

// fakeT records a Fatalf from requireRefusal without failing the real test.
type fakeT struct {
	testing.TB
	failed bool
}

func (f *fakeT) Helper() {}
func (f *fakeT) Fatalf(string, ...any) {
	f.failed = true
	panic("fatal")
}

// A process that does refuse is passed through untouched with its output.
func TestRunRefusal_RefusingProcessIsReportedAsExited(t *testing.T) {
	res := runRefusal(t, "sh", []string{"-c", "echo no-keys >&2; exit 3"}, []string{"PATH=" + os.Getenv("PATH")}, 10*time.Second)
	var ee *exec.ExitError
	if res.TimedOut || !errors.As(res.Err, &ee) || ee.ExitCode() != 3 || res.Out != "no-keys\n" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func hangingServerEnv() []string { return []string{"AVERIN_TEST_HANGING_SERVER=1"} }

var hangingServerArgs = []string{"-test.run=^TestHelperHangingServer$"}

// startServerProc's stop kills the child, is safe to call twice, and does not report an error.
func TestStartServerProc_StopKillsAndIsIdempotent(t *testing.T) {
	var pid int
	ok := t.Run("inner", func(t *testing.T) {
		var stop func()
		stop, pid = startServerProcArgs(t, os.Args[0], hangingServerArgs, hangingServerEnv())
		if !pidAlive(pid) {
			t.Fatal("child should be running")
		}
		stop()
		if pidAlive(pid) {
			t.Fatalf("pid %d alive after stop", pid)
		}
		stop() // the second call must be a no-op, not a second Wait or an error
	})
	if !ok {
		t.Fatal("stop called twice must not fail the test")
	}
	if pidAlive(pid) {
		t.Fatalf("pid %d leaked", pid)
	}
}

// Without an explicit stop, the t.Cleanup registered by startServerProc kills the child when the
// test ends (the posture test relies on exactly this).
func TestStartServerProc_CleanupKillsWithoutExplicitStop(t *testing.T) {
	var pid int
	ok := t.Run("inner", func(t *testing.T) {
		_, pid = startServerProcArgs(t, os.Args[0], hangingServerArgs, hangingServerEnv())
		if !pidAlive(pid) {
			t.Fatal("child should be running")
		}
	})
	if !ok {
		t.Fatal("the inner test must pass")
	}
	if pidAlive(pid) {
		t.Fatalf("pid %d outlived the test that started it: the cleanup is missing", pid)
	}
}

// A server that accepts but never answers cannot stall a poll past httpBound.
func TestServerClient_IsBoundedAgainstAHandlerThatNeverAnswers(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	start := time.Now()
	resp, err := serverClient.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("a handler that never answers must time out")
	}
	if took := time.Since(start); took > httpBound+3*time.Second {
		t.Fatalf("request not bounded: took %s", took)
	}
}
