// Package config loads and validates runtime configuration.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/xtruder/openbao-authorizer/internal/approvalcontext"
)

// Config is the complete validated server configuration.
type Config struct {
	ListenAddress       string
	PublicOrigin        string
	InsecureCookies     bool
	DatabasePath        string
	EncryptionKey       []byte
	OpenBaoAddress      string
	OpenBaoNamespace    string
	OpenBaoScannerToken string
	OpenBaoCAFile       string
	ApproverPolicy      string
	ExposeRequestData   bool
	ScanInterval        time.Duration
	ScanConcurrency     int
	StaticDirectory     string
	VAPIDPublicKey      string
	VAPIDPrivateKey     string
	VAPIDSubject        string
	PushAllowedHosts    []string
	ApprovalContext     *approvalcontext.Resolver
}

type fileConfig struct {
	Server           serverConfig           `hcl:"server,block"`
	Storage          storageConfig          `hcl:"storage,block"`
	OpenBao          openBaoConfig          `hcl:"openbao,block"`
	Scanner          scannerConfig          `hcl:"scanner,block"`
	Requests         requestsConfig         `hcl:"requests,block"`
	WebPush          []webPushConfig        `hcl:"web_push,block"`
	ApprovalContexts []approvalcontext.Rule `hcl:"approval_context,block"`
}

type serverConfig struct {
	ListenAddress   string `hcl:"listen_address"`
	PublicOrigin    string `hcl:"public_origin"`
	InsecureCookies bool   `hcl:"insecure_cookies"`
	StaticDirectory string `hcl:"static_directory"`
}

type storageConfig struct {
	DatabasePath      string `hcl:"database_path"`
	EncryptionKeyFile string `hcl:"encryption_key_file"`
}

type openBaoConfig struct {
	Address          string `hcl:"address"`
	Namespace        string `hcl:"namespace"`
	CAFile           string `hcl:"ca_file"`
	ScannerTokenFile string `hcl:"scanner_token_file"`
	ApproverPolicy   string `hcl:"approver_policy"`
}

type scannerConfig struct {
	Interval    string `hcl:"interval"`
	Concurrency int    `hcl:"concurrency"`
}

type requestsConfig struct {
	ExposeData bool `hcl:"expose_data"`
}

type webPushConfig struct {
	PublicKeyFile       string   `hcl:"public_key_file"`
	PrivateKeyFile      string   `hcl:"private_key_file"`
	Subject             string   `hcl:"subject"`
	AllowedHostSuffixes []string `hcl:"allowed_host_suffixes"`
}

// Load reads one HCL configuration and its referenced secret files.
func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, errors.New("configuration file path is required")
	}

	parser := hclparse.NewParser()
	file, diagnostics := parser.ParseHCLFile(path)
	if diagnostics.HasErrors() {
		return Config{}, fmt.Errorf("parse configuration: %s", diagnostics.Error())
	}

	var raw fileConfig
	if diagnostics := gohcl.DecodeBody(file.Body, nil, &raw); diagnostics.HasErrors() {
		return Config{}, fmt.Errorf("decode configuration: %s", diagnostics.Error())
	}

	baseDirectory, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return Config{}, fmt.Errorf("resolve configuration directory: %w", err)
	}

	resolvePath := func(value string) string {
		if value == "" || filepath.IsAbs(value) {
			return value
		}

		return filepath.Join(baseDirectory, value)
	}

	encryptionKeyText, err := readFile(resolvePath(raw.Storage.EncryptionKeyFile), "storage.encryption_key_file")
	if err != nil {
		return Config{}, err
	}

	encryptionKey, err := base64.StdEncoding.DecodeString(encryptionKeyText)
	if err != nil || len(encryptionKey) != 32 {
		return Config{}, errors.New("storage.encryption_key_file must contain base64 encoding of exactly 32 bytes")
	}

	scannerToken, err := readFile(resolvePath(raw.OpenBao.ScannerTokenFile), "openbao.scanner_token_file")
	if err != nil {
		return Config{}, err
	}

	scanInterval, err := time.ParseDuration(raw.Scanner.Interval)
	if err != nil || scanInterval < time.Second {
		return Config{}, errors.New("scanner.interval must be a duration of at least one second")
	}

	if raw.Scanner.Concurrency < 1 || raw.Scanner.Concurrency > 64 {
		return Config{}, errors.New("scanner.concurrency must be between 1 and 64")
	}

	if strings.TrimSpace(raw.OpenBao.ApproverPolicy) == "" {
		return Config{}, errors.New("openbao.approver_policy is required")
	}

	if !raw.Server.InsecureCookies && strings.TrimSpace(raw.Server.PublicOrigin) == "" {
		return Config{}, errors.New("server.public_origin is required unless insecure_cookies is true")
	}

	contextResolver, err := approvalcontext.New(raw.ApprovalContexts)
	if err != nil {
		return Config{}, err
	}

	result := Config{
		ListenAddress:       raw.Server.ListenAddress,
		PublicOrigin:        strings.TrimSuffix(raw.Server.PublicOrigin, "/"),
		InsecureCookies:     raw.Server.InsecureCookies,
		DatabasePath:        resolvePath(raw.Storage.DatabasePath),
		EncryptionKey:       encryptionKey,
		OpenBaoAddress:      raw.OpenBao.Address,
		OpenBaoNamespace:    raw.OpenBao.Namespace,
		OpenBaoScannerToken: scannerToken,
		OpenBaoCAFile:       resolvePath(raw.OpenBao.CAFile),
		ApproverPolicy:      strings.TrimSpace(raw.OpenBao.ApproverPolicy),
		ExposeRequestData:   raw.Requests.ExposeData,
		ScanInterval:        scanInterval,
		ScanConcurrency:     raw.Scanner.Concurrency,
		StaticDirectory:     resolvePath(raw.Server.StaticDirectory),
		ApprovalContext:     contextResolver,
	}

	if len(raw.WebPush) > 1 {
		return Config{}, errors.New("only one web_push block may be configured")
	}

	if len(raw.WebPush) == 1 {
		webPush := raw.WebPush[0]
		result.VAPIDPublicKey, err = readFile(resolvePath(webPush.PublicKeyFile), "web_push.public_key_file")
		if err != nil {
			return Config{}, err
		}

		result.VAPIDPrivateKey, err = readFile(resolvePath(webPush.PrivateKeyFile), "web_push.private_key_file")
		if err != nil {
			return Config{}, err
		}

		result.VAPIDSubject = webPush.Subject
		result.PushAllowedHosts = webPush.AllowedHostSuffixes
		if result.VAPIDSubject == "" || len(result.PushAllowedHosts) == 0 {
			return Config{}, errors.New("web_push.subject and allowed_host_suffixes are required when web_push is configured")
		}
	}

	return result, nil
}

func readFile(path, field string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s is required", field)
	}

	contents, err := os.ReadFile(path) // #nosec G304 -- paths come from operator configuration.
	if err != nil {
		return "", fmt.Errorf("read %s: %w", field, err)
	}

	return strings.TrimSpace(string(contents)), nil
}
