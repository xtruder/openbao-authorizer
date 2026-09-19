//go:build linux

package openbao

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseReleaseChecksumRequiresOneExactArchiveEntry(t *testing.T) {
	const archive = "openbao_2.7.0-beta20260909_linux_amd64.tar.gz"
	const digest = "7531048975e8f669b83c28f0f949e11fde0587d1064ea77d612f88cd0713fd11"

	got, err := parseReleaseChecksum([]byte(digest+"  "+archive+"\n"), archive)
	if err != nil {
		t.Fatalf("parse valid checksum: %v", err)
	}
	if got != digest {
		t.Fatalf("digest = %q, want %q", got, digest)
	}

	for name, input := range map[string]string{
		"missing":   digest + "  another.tar.gz\n",
		"duplicate": digest + "  " + archive + "\n" + digest + "  " + archive + "\n",
		"malformed": "not-a-sha256  " + archive + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseReleaseChecksum([]byte(input), archive); err == nil {
				t.Fatal("expected checksum input to be rejected")
			}
		})
	}
}

func TestValidateArchiveAcceptsOnlyExpectedRegularFiles(t *testing.T) {
	expected := map[string]bool{
		"bao":          true,
		"LICENSE":      true,
		"README.md":    true,
		"CHANGELOG.md": true,
	}

	good := makeArchive(t, []archiveFixture{
		{name: "bao", body: "binary"},
		{name: "LICENSE", body: "license"},
		{name: "README.md", body: "readme"},
		{name: "CHANGELOG.md", body: "changes"},
	})
	if err := validateArchive(bytes.NewReader(good), expected); err != nil {
		t.Fatalf("validate safe archive: %v", err)
	}

	cases := map[string][]archiveFixture{
		"unexpected": {
			{name: "bao"}, {name: "LICENSE"}, {name: "README.md"}, {name: "surprise"},
		},
		"traversal": {
			{name: "bao"}, {name: "LICENSE"}, {name: "README.md"}, {name: "../CHANGELOG.md"},
		},
		"symlink": {
			{name: "bao", typeflag: tar.TypeSymlink, linkname: "/bin/true"},
			{name: "LICENSE"}, {name: "README.md"}, {name: "CHANGELOG.md"},
		},
		"duplicate": {
			{name: "bao"}, {name: "bao"}, {name: "LICENSE"}, {name: "README.md"}, {name: "CHANGELOG.md"},
		},
	}
	for name, fixtures := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateArchive(bytes.NewReader(makeArchive(t, fixtures)), expected); err == nil {
				t.Fatal("expected archive to be rejected")
			}
		})
	}
}

func TestBinaryReportsExactVersion(t *testing.T) {
	directory := t.TempDir()
	writeStub := func(name, output string) string {
		path := filepath.Join(directory, name)
		contents := "#!/bin/sh\nprintf '%s\\n' '" + output + "'\n"
		if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const version = "2.7.0-beta20260909"
	good := writeStub("good", "OpenBao v2.7.0-beta20260909 (revision), committed 2026-09-09T14:28:33Z")
	if err := binaryReportsExactVersion(good, version); err != nil {
		t.Fatalf("exact version rejected: %v", err)
	}
	for name, output := range map[string]string{
		"suffix":    "OpenBao v2.7.0-beta20260909-evil (revision)",
		"multiline": "OpenBao v2.7.0-beta20260909 (revision)\nunexpected",
		"product":   "Vault v2.7.0-beta20260909 (revision)",
	} {
		t.Run(name, func(t *testing.T) {
			if err := binaryReportsExactVersion(writeStub(name, output), version); err == nil {
				t.Fatal("expected version output to be rejected")
			}
		})
	}
}

func TestManagedProcessDiscoversListenerAndStopsWholeGroup(t *testing.T) {
	directory := t.TempDir()
	childPIDPath := filepath.Join(directory, "child.pid")
	process, err := startManagedProcess(
		filepath.Join(directory, "helper.log"),
		"",
		append(os.Environ(), "GO_E2E_HELPER_PROCESS=1", "GO_E2E_CHILD_PID_PATH="+childPIDPath),
		os.Args[0],
		"-test.run=TestE2EHelperProcess",
	)
	if err != nil {
		t.Fatalf("start managed process: %v", err)
	}
	t.Cleanup(func() { _ = process.stop(time.Second) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port, err := waitForOwnedListener(ctx, process, 0)
	if err != nil {
		t.Fatalf("discover listener: %v", err)
	}
	if err := process.assertOwnsLoopbackPort(port); err != nil {
		t.Fatalf("verify listener ownership: %v", err)
	}
	if err := process.stop(2 * time.Second); err != nil {
		t.Fatalf("stop managed process: %v", err)
	}
	if processGroupHasLiveMembers(process.pid) {
		t.Fatal("process group still has live members after stop")
	}
}

func TestEnvironmentWithRemovesSecretsAndOverridesExactlyOnce(t *testing.T) {
	result := environmentWith(
		[]string{
			"PATH=/bin",
			"OPENBAO_E2E_BOB_TOKEN=must-not-leak",
			"OPENBAO_SCANNER_TOKEN_FILE=/old/secret",
			"LISTEN_ADDRESS=127.0.0.1:9999",
		},
		map[string]string{"LISTEN_ADDRESS": "127.0.0.1:0"},
		[]string{"OPENBAO_E2E_BOB_TOKEN", "OPENBAO_SCANNER_TOKEN_FILE"},
	)
	if strings.Join(result, "\n") != "PATH=/bin\nLISTEN_ADDRESS=127.0.0.1:0" {
		t.Fatalf("sanitized environment = %q", result)
	}
}

func TestE2EHelperProcess(_ *testing.T) {
	if os.Getenv("GO_E2E_HELPER_PROCESS") != "1" {
		return
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	child := exec.CommandContext(context.Background(), "sleep", "300")
	if err := child.Start(); err != nil {
		_ = listener.Close()
		os.Exit(3)
	}
	if err := os.WriteFile(os.Getenv("GO_E2E_CHILD_PID_PATH"), []byte("started"), 0o600); err != nil {
		_ = listener.Close()
		os.Exit(4)
	}
	select {}
}

type archiveFixture struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

func makeArchive(t *testing.T, fixtures []archiveFixture) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, fixture := range fixtures {
		typeflag := fixture.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name: fixture.name, Mode: 0o644, Size: int64(len(fixture.body)),
			Typeflag: typeflag, Linkname: fixture.linkname,
		}
		if typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write([]byte(fixture.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
