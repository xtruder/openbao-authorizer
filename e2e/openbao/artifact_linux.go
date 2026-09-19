//go:build linux

// Package openbao contains the real-process OpenBao end-to-end harness.
package openbao

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	openBaoVersion = "2.7.0-beta20260909"
	openBaoTag     = "v" + openBaoVersion
	releaseBaseURL = "https://github.com/openbao/openbao/releases/download/" + openBaoTag
	maxArchiveFile = int64(512 << 20)
	maxArchiveSize = int64(1 << 30)
)

var (
	pinnedArchiveSHA256 = map[string]string{
		"amd64": "7531048975e8f669b83c28f0f949e11fde0587d1064ea77d612f88cd0713fd11",
		"arm64": "96558560ab53008a9b03d1872d7b219a2133b2fc5b9fa9fd5501abbdcf63271b",
	}
	expectedArchiveEntries = map[string]bool{
		"bao": true, "LICENSE": true, "README.md": true, "CHANGELOG.md": true,
	}
)

type releaseArtifact struct {
	archiveName string
	archiveSHA  string
}

func currentReleaseArtifact() (releaseArtifact, error) {
	if runtime.GOOS != "linux" {
		return releaseArtifact{}, fmt.Errorf("OpenBao E2E requires Linux, got %s", runtime.GOOS)
	}
	digest, ok := pinnedArchiveSHA256[runtime.GOARCH]
	if !ok {
		return releaseArtifact{}, fmt.Errorf("unsupported Linux architecture %q (expected amd64 or arm64)", runtime.GOARCH)
	}
	return releaseArtifact{
		archiveName: fmt.Sprintf("openbao_%s_linux_%s.tar.gz", openBaoVersion, runtime.GOARCH),
		archiveSHA:  digest,
	}, nil
}

func parseReleaseChecksum(contents []byte, archive string) (string, error) {
	var matches []string
	for line := range strings.SplitSeq(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name != archive {
			continue
		}
		digest := strings.ToLower(fields[0])
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size {
			return "", fmt.Errorf("invalid SHA-256 entry for %s", archive)
		}
		matches = append(matches, digest)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("checksums.txt contains %d entries for %s, want exactly one", len(matches), archive)
	}
	return matches[0], nil
}

func validateArchive(reader io.Reader, expected map[string]bool) error {
	_, err := inspectArchive(reader, expected)
	return err
}

func inspectArchive(reader io.Reader, expected map[string]bool) (map[string]string, error) {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()

	tarReader := tar.NewReader(gzipReader)
	seen := make(map[string]bool, len(expected))
	digests := make(map[string]string, len(expected))
	var total int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar archive: %w", err)
		}
		name := header.Name
		if filepath.IsAbs(name) || filepath.Base(name) != name || name == "." || name == ".." || strings.Contains(name, "\\") {
			return nil, fmt.Errorf("archive entry is not a safe top-level filename: %q", name)
		}
		if !expected[name] {
			return nil, fmt.Errorf("archive contains unexpected entry %q", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("archive contains duplicate entry %q", name)
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("archive entry %q is not a regular file", name)
		}
		if header.Size < 0 || header.Size > maxArchiveFile || total > maxArchiveSize-header.Size {
			return nil, fmt.Errorf("archive entry %q has unsafe size %d", name, header.Size)
		}
		total += header.Size
		hash := sha256.New()
		written, err := io.Copy(hash, io.LimitReader(tarReader, header.Size+1))
		if err != nil {
			return nil, fmt.Errorf("hash archive entry %q: %w", name, err)
		}
		if written != header.Size {
			return nil, fmt.Errorf("archive entry %q size is %d, read %d", name, header.Size, written)
		}
		seen[name] = true
		digests[name] = hex.EncodeToString(hash.Sum(nil))
	}
	if len(seen) != len(expected) {
		missing := make([]string, 0)
		for name := range expected {
			if !seen[name] {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("archive is missing expected entries: %s", strings.Join(missing, ", "))
	}
	return digests, nil
}

func binaryReportsExactVersion(binary, expectedVersion string) error {
	info, err := os.Stat(binary)
	if err != nil {
		return fmt.Errorf("stat binary: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("binary is not an executable regular file")
	}
	output, err := exec.CommandContext(context.Background(), binary, "version").Output() // #nosec G204,G702 -- path is repository-controlled cache state.
	if err != nil {
		return fmt.Errorf("run binary version: %w", err)
	}
	text := strings.TrimSuffix(string(output), "\n")
	if text == "" || strings.ContainsAny(text, "\r\n") {
		return errors.New("version output must contain exactly one non-empty line")
	}
	fields := strings.Fields(text)
	if len(fields) < 2 || fields[0] != "OpenBao" || fields[1] != "v"+expectedVersion {
		return fmt.Errorf("unexpected version output %q", text)
	}
	return nil
}

func ensureOpenBao(ctx context.Context, cacheRoot string, logger func(string, ...any)) (string, error) {
	artifact, err := currentReleaseArtifact()
	if err != nil {
		return "", err
	}
	downloadDirectory := filepath.Join(cacheRoot, "downloads", openBaoTag)
	if err := os.MkdirAll(downloadDirectory, 0o750); err != nil {
		return "", fmt.Errorf("create download cache: %w", err)
	}
	checksumsPath := filepath.Join(downloadDirectory, "checksums.txt")
	archivePath := filepath.Join(downloadDirectory, artifact.archiveName)
	client := &http.Client{Timeout: 10 * time.Minute}

	verifyChecksums := func(path string) error {
		contents, err := os.ReadFile(path) // #nosec G304 -- path is the fixed checksums cache entry.
		if err != nil {
			return err
		}
		digest, err := parseReleaseChecksum(contents, artifact.archiveName)
		if err != nil {
			return err
		}
		if digest != artifact.archiveSHA {
			return fmt.Errorf("release checksum %s does not match repository pin %s", digest, artifact.archiveSHA)
		}
		return nil
	}
	if err := ensureDownload(ctx, client, releaseBaseURL+"/checksums.txt", checksumsPath, 10<<20, verifyChecksums, logger); err != nil {
		return "", fmt.Errorf("obtain release checksums: %w", err)
	}

	var manifest map[string]string
	verifyArchive := func(path string) error {
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		if digest != artifact.archiveSHA {
			return fmt.Errorf("archive SHA-256 %s does not match repository pin %s", digest, artifact.archiveSHA)
		}
		file, err := os.Open(path) // #nosec G304 -- path is built beneath the repository cache.
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		manifest, err = inspectArchive(file, expectedArchiveEntries)
		return err
	}
	if err := ensureDownload(ctx, client, releaseBaseURL+"/"+artifact.archiveName, archivePath, maxArchiveSize, verifyArchive, logger); err != nil {
		return "", fmt.Errorf("obtain OpenBao archive: %w", err)
	}
	logger("verified repository-pinned SHA-256 for %s", artifact.archiveName)

	installDirectory := filepath.Join(cacheRoot, "bin", openBaoTag, "linux_"+runtime.GOARCH)
	binary := filepath.Join(installDirectory, "bao")
	if digest, digestErr := hashFile(binary); digestErr == nil && digest == manifest["bao"] {
		if versionErr := binaryReportsExactVersion(binary, openBaoVersion); versionErr == nil {
			return binary, nil
		}
	}
	if err := extractArchive(archivePath, installDirectory, expectedArchiveEntries); err != nil {
		return "", err
	}
	if digest, err := hashFile(binary); err != nil || digest != manifest["bao"] {
		return "", fmt.Errorf("installed binary does not match verified archive")
	}
	if err := binaryReportsExactVersion(binary, openBaoVersion); err != nil {
		return "", fmt.Errorf("verify extracted OpenBao version: %w", err)
	}
	return binary, nil
}

func ensureDownload(ctx context.Context, client *http.Client, url, destination string, maximum int64, verify func(string) error, logger func(string, ...any)) error {
	if info, err := os.Stat(destination); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
		if err := verify(destination); err == nil {
			return nil
		}
		if err := os.Remove(destination); err != nil {
			return fmt.Errorf("remove invalid cache entry: %w", err)
		}
	}
	logger("downloading %s", filepath.Base(destination))
	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		lastErr = downloadFile(ctx, client, url, destination, maximum)
		if lastErr == nil {
			lastErr = verify(destination)
		}
		if lastErr == nil {
			return nil
		}
		_ = os.Remove(destination)
		if attempt < 4 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
			}
		}
	}
	return lastErr
}

func downloadFile(ctx context.Context, client *http.Client, url, destination string, maximum int64) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "openbao-authorizer-e2e/1")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("GET %s: HTTP %d", url, response.StatusCode)
	}
	if response.ContentLength > maximum {
		return fmt.Errorf("download is too large: %d bytes", response.ContentLength)
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".download-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	written, copyErr := io.Copy(temporary, io.LimitReader(response.Body, maximum+1))
	closeErr := temporary.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written == 0 || written > maximum {
		return fmt.Errorf("download has unsafe size %d", written)
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return err
	}
	return os.Rename(temporaryPath, destination)
}

func extractArchive(archivePath, destination string, expected map[string]bool) error {
	temporary, err := os.MkdirTemp(filepath.Dir(destination), ".extract-*")
	if err != nil {
		return fmt.Errorf("create extraction directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	file, err := os.Open(archivePath) // #nosec G304 -- path is built beneath the repository cache.
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	written := make(map[string]bool, len(expected))
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if !expected[header.Name] || written[header.Name] || filepath.Base(header.Name) != header.Name || header.Typeflag != tar.TypeReg {
			return fmt.Errorf("archive changed after validation at entry %q", header.Name)
		}
		mode := os.FileMode(0o644)
		if header.Name == "bao" {
			mode = 0o755
		}
		output, err := os.OpenFile(filepath.Join(temporary, header.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) // #nosec G304,G305 -- filename is an exact allowlisted basename.
		if err != nil {
			return err
		}
		copied, copyErr := io.Copy(output, io.LimitReader(tarReader, header.Size+1))
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if copied != header.Size {
			return fmt.Errorf("archive entry %q changed size", header.Name)
		}
		written[header.Name] = true
	}
	if len(written) != len(expected) {
		return errors.New("archive changed after validation: missing entries")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return err
	}
	if err := os.RemoveAll(destination); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	return nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- callers provide repository-controlled paths.
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
