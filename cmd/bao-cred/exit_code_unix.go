//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func commandExitCode(processExit *exec.ExitError) int {
	if status, ok := processExit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}

	return processExit.ExitCode()
}
