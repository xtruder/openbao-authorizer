// Package config loads and validates runtime configuration from the environment.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the complete server configuration.
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
}

// Load reads configuration from environment variables and fails closed on missing secrets.
func Load() (Config, error) {
	result := Config{
		ListenAddress:    envOr("LISTEN_ADDRESS", "127.0.0.1:8080"),
		PublicOrigin:     strings.TrimSuffix(os.Getenv("PUBLIC_ORIGIN"), "/"),
		DatabasePath:     envOr("DATABASE_PATH", "openbao-authorizer.db"),
		OpenBaoAddress:   envOr("OPENBAO_ADDRESS", "http://127.0.0.1:8200"),
		OpenBaoNamespace: os.Getenv("OPENBAO_NAMESPACE"),
		OpenBaoCAFile:    os.Getenv("OPENBAO_CA_FILE"),
		ApproverPolicy:   strings.TrimSpace(os.Getenv("APPROVER_POLICY")),
		StaticDirectory:  strings.TrimSpace(os.Getenv("STATIC_DIRECTORY")),
		VAPIDPublicKey:   os.Getenv("VAPID_PUBLIC_KEY"),
		VAPIDPrivateKey:  os.Getenv("VAPID_PRIVATE_KEY"),
		VAPIDSubject:     os.Getenv("VAPID_SUBJECT"),
		PushAllowedHosts: splitCSV(os.Getenv("PUSH_ALLOWED_HOST_SUFFIXES")),
	}
	var err error
	result.InsecureCookies, err = strconv.ParseBool(envOr("INSECURE_COOKIES", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse INSECURE_COOKIES: %w", err)
	}
	result.ExposeRequestData, err = strconv.ParseBool(envOr("EXPOSE_REQUEST_DATA", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse EXPOSE_REQUEST_DATA: %w", err)
	}
	result.ScanInterval, err = time.ParseDuration(envOr("SCAN_INTERVAL", "15s"))
	if err != nil || result.ScanInterval < time.Second {
		return Config{}, errors.New("SCAN_INTERVAL must be a duration of at least one second")
	}
	result.ScanConcurrency, err = strconv.Atoi(envOr("SCAN_CONCURRENCY", "8"))
	if err != nil || result.ScanConcurrency < 1 || result.ScanConcurrency > 64 {
		return Config{}, errors.New("SCAN_CONCURRENCY must be between 1 and 64")
	}

	encodedKey := os.Getenv("APP_ENCRYPTION_KEY")
	if encodedKey == "" {
		return Config{}, errors.New("APP_ENCRYPTION_KEY is required (base64-encoded 32-byte key)")
	}
	result.EncryptionKey, err = base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(result.EncryptionKey) != 32 {
		return Config{}, errors.New("APP_ENCRYPTION_KEY must be valid base64 encoding exactly 32 bytes")
	}

	result.OpenBaoScannerToken, err = readSecret("OPENBAO_SCANNER_TOKEN", "OPENBAO_SCANNER_TOKEN_FILE")
	if err != nil {
		return Config{}, err
	}
	if result.OpenBaoScannerToken == "" {
		return Config{}, errors.New("OPENBAO_SCANNER_TOKEN_FILE or OPENBAO_SCANNER_TOKEN is required")
	}
	if result.ApproverPolicy == "" {
		return Config{}, errors.New("APPROVER_POLICY is required")
	}
	vapidCount := 0
	for _, value := range []string{result.VAPIDPublicKey, result.VAPIDPrivateKey, result.VAPIDSubject} {
		if value != "" {
			vapidCount++
		}
	}
	if vapidCount != 0 && vapidCount != 3 {
		return Config{}, errors.New("VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, and VAPID_SUBJECT must be configured together")
	}
	if vapidCount == 3 && len(result.PushAllowedHosts) == 0 {
		return Config{}, errors.New("PUSH_ALLOWED_HOST_SUFFIXES is required when Web Push is enabled")
	}
	if !result.InsecureCookies && result.PublicOrigin == "" {
		return Config{}, errors.New("PUBLIC_ORIGIN is required unless INSECURE_COOKIES=true")
	}
	return result, nil
}

func readSecret(valueName, fileName string) (string, error) {
	value := strings.TrimSpace(os.Getenv(valueName))
	file := strings.TrimSpace(os.Getenv(fileName))
	if value != "" && file != "" {
		return "", fmt.Errorf("configure only one of %s or %s", valueName, fileName)
	}
	if file != "" {
		// #nosec G304,G703 -- the secret-file path is trusted operator configuration.
		contents, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", fileName, err)
		}
		return strings.TrimSpace(string(contents)), nil
	}
	return value, nil
}

func splitCSV(value string) []string {
	result := make([]string, 0)
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
