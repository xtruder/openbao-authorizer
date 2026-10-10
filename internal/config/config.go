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

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/xtruder/openbao-authorizer/internal/grants"
	"github.com/zclconf/go-cty/cty"
)

const (
	defaultGrantTTL         = 72 * time.Hour
	defaultPendingTTL       = 24 * time.Hour
	defaultSessionTTL       = 168 * time.Hour
	defaultSessionTokenRole = "opencode-session"
)

// Config is the complete validated server configuration.
type Config struct {
	ListenAddress          string
	PublicOrigin           string
	InsecureCookies        bool
	SessionTTL             time.Duration
	DatabasePath           string
	EncryptionKey          []byte
	OpenBaoAddress         string
	OpenBaoNamespace       string
	OpenBaoAuthorizerToken string
	OpenBaoCAFile          string
	ApproverPolicy         string
	SessionTokenRole       string
	GrantPolicy            grants.Policy
	PendingTTL             time.Duration
	StaticDirectory        string
	VAPIDPublicKey         string
	VAPIDPrivateKey        string
	VAPIDSubject           string
	PushAllowedHosts       []string
}

type fileConfig struct {
	Server    serverConfig      `hcl:"server,block"`
	Storage   storageConfig     `hcl:"storage,block"`
	OpenBao   openBaoConfig     `hcl:"openbao,block"`
	Grants    *grantsConfig     `hcl:"grants,block"`
	Grantable []grantableConfig `hcl:"grantable,block"`
	WebPush   []webPushConfig   `hcl:"web_push,block"`
}

type serverConfig struct {
	ListenAddress   string `hcl:"listen_address"`
	PublicOrigin    string `hcl:"public_origin"`
	InsecureCookies bool   `hcl:"insecure_cookies"`
	StaticDirectory string `hcl:"static_directory"`
	SessionTTL      string `hcl:"session_ttl,optional"`
}

type storageConfig struct {
	DatabasePath      string `hcl:"database_path"`
	EncryptionKeyFile string `hcl:"encryption_key_file"`
}

type openBaoConfig struct {
	Address             string `hcl:"address"`
	Namespace           string `hcl:"namespace,optional"`
	CAFile              string `hcl:"ca_file,optional"`
	AuthorizerTokenFile string `hcl:"authorizer_token_file"`
	ApproverPolicy      string `hcl:"approver_policy"`
	SessionTokenRole    string `hcl:"session_token_role,optional"`
}

type grantsConfig struct {
	DefaultTTL string `hcl:"default_ttl,optional"`
	PendingTTL string `hcl:"pending_ttl,optional"`
}

type grantableConfig struct {
	Name         string   `hcl:"name,label"`
	Path         string   `hcl:"path"`
	Capabilities []string `hcl:"capabilities"`
	MaxTTL       string   `hcl:"max_ttl,optional"`
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
	if diagnostics := gohcl.DecodeBody(file.Body, environmentEvalContext(), &raw); diagnostics.HasErrors() {
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

	authorizerToken, err := readFile(resolvePath(raw.OpenBao.AuthorizerTokenFile), "openbao.authorizer_token_file")
	if err != nil {
		return Config{}, err
	}

	if strings.TrimSpace(raw.OpenBao.ApproverPolicy) == "" {
		return Config{}, errors.New("openbao.approver_policy is required")
	}

	if !raw.Server.InsecureCookies && strings.TrimSpace(raw.Server.PublicOrigin) == "" {
		return Config{}, errors.New("server.public_origin is required unless insecure_cookies is true")
	}

	sessionTTL := defaultSessionTTL
	if raw.Server.SessionTTL != "" {
		if sessionTTL, err = parsePositiveDuration(raw.Server.SessionTTL, "server.session_ttl"); err != nil {
			return Config{}, err
		}
	}

	sessionTokenRole := strings.TrimSpace(raw.OpenBao.SessionTokenRole)
	if sessionTokenRole == "" {
		sessionTokenRole = defaultSessionTokenRole
	}

	grantPolicy, pendingTTL, err := loadGrants(raw.Grants, raw.Grantable)
	if err != nil {
		return Config{}, err
	}

	result := Config{
		ListenAddress:          raw.Server.ListenAddress,
		PublicOrigin:           strings.TrimSuffix(raw.Server.PublicOrigin, "/"),
		InsecureCookies:        raw.Server.InsecureCookies,
		SessionTTL:             sessionTTL,
		DatabasePath:           resolvePath(raw.Storage.DatabasePath),
		EncryptionKey:          encryptionKey,
		OpenBaoAddress:         raw.OpenBao.Address,
		OpenBaoNamespace:       raw.OpenBao.Namespace,
		OpenBaoAuthorizerToken: authorizerToken,
		OpenBaoCAFile:          resolvePath(raw.OpenBao.CAFile),
		ApproverPolicy:         strings.TrimSpace(raw.OpenBao.ApproverPolicy),
		SessionTokenRole:       sessionTokenRole,
		GrantPolicy:            grantPolicy,
		PendingTTL:             pendingTTL,
		StaticDirectory:        resolvePath(raw.Server.StaticDirectory),
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

func loadGrants(raw *grantsConfig, grantable []grantableConfig) (grants.Policy, time.Duration, error) {
	policy := grants.Policy{DefaultTTL: defaultGrantTTL, Rules: make([]grants.Rule, 0, len(grantable))}
	pendingTTL := defaultPendingTTL
	if raw != nil {
		var err error
		if raw.DefaultTTL != "" {
			if policy.DefaultTTL, err = parsePositiveDuration(raw.DefaultTTL, "grants.default_ttl"); err != nil {
				return grants.Policy{}, 0, err
			}
		}

		if raw.PendingTTL != "" {
			if pendingTTL, err = parsePositiveDuration(raw.PendingTTL, "grants.pending_ttl"); err != nil {
				return grants.Policy{}, 0, err
			}
		}
	}

	names := make(map[string]bool, len(grantable))
	for _, entry := range grantable {
		if names[entry.Name] {
			return grants.Policy{}, 0, fmt.Errorf("grantable %q is defined more than once", entry.Name)
		}

		names[entry.Name] = true
		rule := grants.Rule{Name: entry.Name, Path: entry.Path, Capabilities: entry.Capabilities}
		if entry.MaxTTL != "" {
			maxTTL, err := parsePositiveDuration(entry.MaxTTL, fmt.Sprintf("grantable %q max_ttl", entry.Name))
			if err != nil {
				return grants.Policy{}, 0, err
			}

			rule.MaxTTL = maxTTL
		}

		if err := grants.ValidateRule(rule); err != nil {
			return grants.Policy{}, 0, err
		}

		policy.Rules = append(policy.Rules, rule)
	}

	return policy, pendingTTL, nil
}

func parsePositiveDuration(value, field string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration < time.Second {
		return 0, fmt.Errorf("%s must be a duration of at least one second", field)
	}

	return duration, nil
}

func environmentEvalContext() *hcl.EvalContext {
	values := make(map[string]cty.Value)
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = cty.StringVal(value)
	}

	return &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"env": cty.ObjectVal(values),
		},
	}
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
