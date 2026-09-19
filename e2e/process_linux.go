//go:build linux

// Package e2e contains the real-process end-to-end harness.
package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type managedProcess struct {
	cmd     *exec.Cmd
	pid     int
	logPath string
	done    chan struct{}
	waitErr error
	stopMu  sync.Mutex
}

func startManagedProcess(logPath, directory string, environment []string, executable string, arguments ...string) (*managedProcess, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- caller creates the runtime path.
	if err != nil {
		return nil, fmt.Errorf("open process log: %w", err)
	}

	command := exec.CommandContext(context.Background(), executable, arguments...) // #nosec G204,G702 -- executable and arguments are fixed by the E2E harness.
	command.Dir = directory
	command.Env = environment
	command.Stdout = logFile
	command.Stderr = logFile
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if startErr := command.Start(); startErr != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("start %s: %w", filepath.Base(executable), startErr)
	}

	if closeErr := logFile.Close(); closeErr != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return nil, fmt.Errorf("close process log: %w", closeErr)
	}

	process := &managedProcess{
		cmd: command, pid: command.Process.Pid, logPath: logPath, done: make(chan struct{}),
	}
	go func() {
		process.waitErr = command.Wait()
		close(process.done)
	}()
	processGroup, err := syscall.Getpgid(process.pid)
	if err != nil || processGroup != process.pid {
		_ = process.stop(time.Second)
		if err != nil {
			return nil, fmt.Errorf("verify process group: %w", err)
		}

		return nil, fmt.Errorf("process %d entered group %d, expected its own group", process.pid, processGroup)
	}

	return process, nil
}

func (p *managedProcess) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *managedProcess) exitError() error {
	select {
	case <-p.done:
		return p.waitErr
	default:
		return nil
	}
}

func (p *managedProcess) stop(grace time.Duration) error {
	p.stopMu.Lock()
	defer p.stopMu.Unlock()

	_ = syscall.Kill(-p.pid, syscall.SIGTERM)
	deadline := time.Now().Add(grace)
	for processGroupHasLiveMembers(p.pid) && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}

	if processGroupHasLiveMembers(p.pid) {
		_ = syscall.Kill(-p.pid, syscall.SIGKILL)
		killDeadline := time.Now().Add(2 * time.Second)
		for processGroupHasLiveMembers(p.pid) && time.Now().Before(killDeadline) {
			time.Sleep(25 * time.Millisecond)
		}
	}

	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		return fmt.Errorf("process %d was not reaped", p.pid)
	}

	if processGroupHasLiveMembers(p.pid) {
		return fmt.Errorf("process group %d still has live members", p.pid)
	}

	return nil
}

func waitForOwnedListener(ctx context.Context, process *managedProcess, expectedPort int) (int, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !process.running() {
			return 0, processExitedError(process.pid, "before opening its listener", process.exitError())
		}

		ports, err := ownedLoopbackListenerPorts(process.pid)
		if err == nil {
			if expectedPort == 0 && len(ports) == 1 {
				return ports[0], nil
			}

			for _, port := range ports {
				if port == expectedPort {
					return port, nil
				}
			}
		}

		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("wait for process %d listener: %w", process.pid, ctx.Err())
		case <-process.done:
			return 0, processExitedError(process.pid, "before opening its listener", process.waitErr)
		case <-ticker.C:
		}
	}
}

func waitForOwnedHTTPListener(ctx context.Context, process *managedProcess, healthPath string) (int, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	client := &http.Client{Timeout: 250 * time.Millisecond}
	for {
		if !process.running() {
			return 0, processExitedError(process.pid, "before opening its HTTP listener", process.exitError())
		}

		ports, err := ownedLoopbackListenerPorts(process.pid)
		if err == nil {
			for _, port := range ports {
				url := fmt.Sprintf("http://127.0.0.1:%d%s", port, healthPath)
				request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				if requestErr != nil {
					return 0, fmt.Errorf("construct listener probe: %w", requestErr)
				}

				response, probeErr := client.Do(request)
				if probeErr == nil {
					_ = response.Body.Close()
					return port, nil
				}
			}
		}

		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("wait for process %d HTTP listener: %w", process.pid, ctx.Err())
		case <-process.done:
			return 0, processExitedError(process.pid, "before opening its HTTP listener", process.waitErr)
		case <-ticker.C:
		}
	}
}

func (p *managedProcess) assertOwnsLoopbackPort(port int) error {
	if !p.running() {
		return processExitedError(p.pid, "and is not running", p.exitError())
	}

	ports, err := ownedLoopbackListenerPorts(p.pid)
	if err != nil {
		return fmt.Errorf("inspect process %d listeners: %w", p.pid, err)
	}

	if slices.Contains(ports, port) {
		return nil
	}

	return fmt.Errorf("process %d does not own 127.0.0.1:%d", p.pid, port)
}

func ownedLoopbackListenerPorts(pid int) ([]int, error) {
	descriptors, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return nil, err
	}

	inodes := make(map[string]bool)
	for _, descriptor := range descriptors {
		target, readlinkErr := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", descriptor.Name()))
		if readlinkErr != nil {
			continue
		}

		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}

	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, err
	}

	defer func() { _ = file.Close() }()
	ports := make(map[int]bool)
	scanner := bufio.NewScanner(file)
	_ = scanner.Scan() // Skip the header.
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != "0A" || !inodes[fields[9]] {
			continue
		}

		address := strings.Split(fields[1], ":")
		if len(address) != 2 || address[0] != "0100007F" {
			continue
		}

		port, err := strconv.ParseInt(address[1], 16, 32)
		if err != nil || port < 1 || port > 65535 {
			continue
		}

		ports[int(port)] = true
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}

	sort.Ints(result)
	return result, nil
}

func processGroupHasLiveMembers(processGroup int) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		contents, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat")) // #nosec G304 -- proc PID entries are validated decimal names.
		if err != nil {
			continue
		}

		closingParenthesis := strings.LastIndexByte(string(contents), ')')
		if closingParenthesis < 0 || closingParenthesis+2 >= len(contents) {
			continue
		}

		fields := strings.Fields(string(contents[closingParenthesis+2:]))
		if len(fields) < 3 || fields[0] == "Z" {
			continue
		}

		group, err := strconv.Atoi(fields[2])
		if err == nil && group == processGroup {
			return true
		}
	}

	return false
}

func readProcessLog(path string) string {
	contents, err := os.ReadFile(path) // #nosec G304 -- caller passes a harness-created process log path.
	if err != nil {
		return fmt.Sprintf("<cannot read %s: %v>", path, err)
	}

	const maximum = 32 << 10
	if len(contents) > maximum {
		contents = contents[len(contents)-maximum:]
	}

	lines := strings.Split(string(contents), "\n")
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, label := range []string{"Unseal Key:", "Root Token:"} {
			if strings.HasPrefix(trimmed, label) {
				indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
				lines[index] = indent + label + " [REDACTED]"
			}
		}
	}

	return strings.Join(lines, "\n")
}

func processExitedError(pid int, state string, cause error) error {
	if cause != nil {
		return fmt.Errorf("process %d exited %s: %w", pid, state, cause)
	}

	return fmt.Errorf("process %d exited %s without an exit error", pid, state)
}
