package main

import "os/exec"

func commandExitCode(processExit *exec.ExitError) int {
	return processExit.ExitCode()
}
