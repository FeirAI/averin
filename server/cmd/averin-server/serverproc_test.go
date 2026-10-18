package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
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
// detector in its own session and kills that whole group on timeout, so a child in the same group is
// reaped even when go test's own timeout SIGKILLs this binary before any cleanup runs. On Linux the
// child also gets PDEATHSIG (serverproc_linux_test.go) so it dies with the test binary regardless.

// refusalBound is how long a server that is meant to refuse to start may run before the test fails it.
const refusalBound = 30 * time.Second

// refusalResult is what a refuse-to-start run did.
type refusalResult struct {
	Out      string
	Err      error // nil when the process exited zero; *exec.ExitError for a non-zero exit
	TimedOut bool  // still running at the bound: it did not refuse, it was killed
	Pid      int
	Leaked   bool // still alive after the kill (must never be true)
}

// runRefusal runs bin with env until it exits or the bound passes, then guarantees the process is dead.
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
	res := refusalResult{Pid: cmd.Process.Pid}
	reap := sync.OnceValue(func() bool { return killAndConfirm(cmd) })
	t.Cleanup(func() {
		if reap() {
			t.Errorf("averin-server pid %d is still alive after the kill", res.Pid)
		}
	})
	res.Err = cmd.Wait()
	res.TimedOut = ctx.Err() != nil
	res.Out = buf.String()
	res.Leaked = reap()
	return res
}

// startServerExpectRefusal is the helper refuse-to-start tests use: it fails the test unless the
// process exits non-zero within the bound, and returns its combined output for the caller's
// assertions on the refusal text.
func startServerExpectRefusal(t testing.TB, bin string, args, env []string) string {
	t.Helper()
	res := runRefusal(t, bin, args, env, refusalBound)
	if res.Leaked {
		t.Fatalf("pid %d outlived its kill\n%s", res.Pid, res.Out)
	}
	if res.TimedOut {
		t.Fatalf("the process did not refuse to start within %s (it kept running and was killed)\n%s", refusalBound, res.Out)
	}
	var ee *exec.ExitError
	if !errors.As(res.Err, &ee) || ee.Success() {
		t.Fatalf("expected a non-zero exit (refusal), got %v\n%s", res.Err, res.Out)
	}
	return res.Out
}

// startServerProc starts a long-running server for a test and registers its kill; the returned stop
// is idempotent and may be called early.
func startServerProc(t testing.TB, bin string, env []string) (stop func()) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = env
	confineChild(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	stop = sync.OnceFunc(func() {
		if killAndConfirm(cmd) {
			t.Errorf("averin-server pid %d is still alive after the kill", pid)
		}
	})
	t.Cleanup(stop)
	return stop
}

// killAndConfirm kills and reaps cmd's process, then reports whether it is somehow still alive.
func killAndConfirm(cmd *exec.Cmd) (alive bool) {
	_ = cmd.Process.Kill()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	return pidAlive(cmd.Process.Pid)
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

// A server that keeps running is reported within the bound and leaves no process behind.
func TestRunRefusal_NonRefusingServerIsBoundedAndNotLeaked(t *testing.T) {
	start := time.Now()
	res := runRefusal(t, os.Args[0], []string{"-test.run=^TestHelperHangingServer$"},
		[]string{"AVERIN_TEST_HANGING_SERVER=1"}, 2*time.Second)
	if !res.TimedOut {
		t.Fatalf("a never-exiting process must be reported as not having refused: %+v", res)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("the bound was not honoured: took %s", took)
	}
	if res.Leaked || pidAlive(res.Pid) {
		t.Fatalf("pid %d is still alive after runRefusal returned", res.Pid)
	}
}

// A process that does refuse is passed through untouched with its output.
func TestRunRefusal_RefusingProcessIsReportedAsExited(t *testing.T) {
	res := runRefusal(t, "sh", []string{"-c", "echo no-keys >&2; exit 3"}, []string{"PATH=" + os.Getenv("PATH")}, 10*time.Second)
	var ee *exec.ExitError
	if res.TimedOut || !errors.As(res.Err, &ee) || ee.ExitCode() != 3 || res.Out != "no-keys\n" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if pidAlive(res.Pid) {
		t.Fatalf("pid %d still alive", res.Pid)
	}
}

// startServerProc's stop kills the child and is safe to call twice.
func TestStartServerProc_StopKillsAndIsIdempotent(t *testing.T) {
	var pid int
	t.Run("inner", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHangingServer$")
		cmd.Env = []string{"AVERIN_TEST_HANGING_SERVER=1"}
		confineChild(cmd)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid = cmd.Process.Pid
		if !pidAlive(pid) {
			t.Fatal("child should be running")
		}
		if killAndConfirm(cmd) {
			t.Fatal("child alive after kill")
		}
	})
	if pidAlive(pid) {
		t.Fatalf("pid %d leaked", pid)
	}
}
