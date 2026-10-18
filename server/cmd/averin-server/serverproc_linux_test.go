//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// confineChild makes the kernel kill the child if this test binary dies first (go test's timeout
// SIGKILLs the binary without running t.Cleanup).
func confineChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
