package main

import (
	"os"
	"testing"
)

// TestMain clears the agent session variables of the shell running the tests,
// such as opencode's OPENCODE_SESSION_ID; tests that need a session set them.
func TestMain(m *testing.M) {
	for _, name := range []string{"BAO_SESSION_ID", "OPENCODE_SESSION_ID", "BAO_NO_SESSION", "BAO_SESSION_ROLE", "BAO_IDENTITY"} {
		_ = os.Unsetenv(name)
	}

	os.Exit(m.Run())
}
