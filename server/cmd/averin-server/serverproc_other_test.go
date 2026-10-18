//go:build !linux

package main

import "os/exec"

// confineChild is a no-op off Linux, where there is no PDEATHSIG. The child stays in the test binary's
// process group; the formal mutant runner kills that whole session when the detector exits, whatever
// the exit. A plain "go test" run off Linux that dies before t.Cleanup (go test's own -timeout panic)
// can still orphan the server: the bounded waits in these tests keep that from happening on a hang.
func confineChild(cmd *exec.Cmd) {}
