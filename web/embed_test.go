package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedDistributionContainsApplicationShell(t *testing.T) {
	t.Parallel()

	index, err := fs.ReadFile(Dist, "index.html")
	if err != nil {
		t.Fatalf("read embedded index: %v", err)
	}
	if !strings.Contains(string(index), `id="root"`) {
		t.Fatal("embedded index is not the application shell")
	}
}
