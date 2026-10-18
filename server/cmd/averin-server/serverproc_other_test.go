//go:build !linux

package main

import "os/exec"

// confineChild is a no-op off Linux: the child stays in the test binary's process group, which the
// formal mutant runner kills as a whole on timeout.
func confineChild(cmd *exec.Cmd) {}
