package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	openbao "github.com/openbao/openbao/api/v2"
)

type progressFunc func(string)

var errRequestClosed = errors.New("request rejected or expired")

type credentialRequest struct {
	spec      requestSpec
	wrapToken string
	accessor  string
	done      bool
}

func readCredentialRequests(ctx context.Context, client *openbao.Client, requesterToken string, specs []requestSpec, authorizerAddress, reason string, allowPartial bool, pollInterval time.Duration, progress progressFunc) (map[string]any, []error) {
	data := make(map[string]any, len(specs))
	pending := make([]credentialRequest, 0, len(specs))
	var requestErrors []error
	for _, spec := range specs {
		secret, err := client.Logical().ReadWithContext(ctx, spec.Path)
		if err != nil {
			requestErrors = append(requestErrors, fmt.Errorf("read %q: %w", spec.Path, err))
			continue
		}

		if secret == nil {
			requestErrors = append(requestErrors, fmt.Errorf("read %q: empty response", spec.Path))
			continue
		}

		if secret.WrapInfo == nil || secret.WrapInfo.Token == "" {
			data[spec.Alias] = secret.Data
			continue
		}

		if secret.WrapInfo.Accessor == "" {
			requestErrors = append(requestErrors, fmt.Errorf("read %q: wrapped response has no accessor", spec.Path))
			continue
		}

		pending = append(pending, credentialRequest{spec: spec, wrapToken: secret.WrapInfo.Token, accessor: secret.WrapInfo.Accessor})
	}

	if len(requestErrors) > 0 && !allowPartial {
		return data, requestErrors
	}

	if len(pending) == 0 {
		return data, requestErrors
	}

	if authorizerAddress == "" {
		return data, append(requestErrors, errors.New("-authorizer-address or BAO_AUTHORIZER_ADDR is required for approval requests"))
	}

	accessors := make([]string, len(pending))
	for index := range pending {
		accessors[index] = pending[index].accessor
	}

	if err := submitApprovalGroup(ctx, http.DefaultClient, authorizerAddress, requesterToken, reason, accessors); err != nil {
		return data, append(requestErrors, err)
	}

	if progress != nil {
		progress(fmt.Sprintf("approval requested for %d credential request(s); waiting", len(pending)))
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	attempt := 0
	remaining := len(pending)
	for remaining > 0 {
		attempt++
		for index := range pending {
			item := &pending[index]
			if item.done {
				continue
			}

			approved, err := controlGroupStatus(ctx, client, item.accessor)
			if err != nil {
				item.done = true
				remaining--
				requestErrors = append(requestErrors, fmt.Errorf("request %q: %w", item.spec.Path, err))
				if !allowPartial {
					return data, requestErrors
				}

				continue
			}

			if !approved {
				continue
			}

			unwrapped, err := client.Logical().UnwrapWithContext(ctx, item.wrapToken)
			item.wrapToken = ""
			item.done = true
			remaining--
			if err != nil {
				requestErrors = append(requestErrors, fmt.Errorf("unwrap %q: %w", item.spec.Path, err))
				if !allowPartial {
					return data, requestErrors
				}

				continue
			}

			if unwrapped == nil {
				requestErrors = append(requestErrors, fmt.Errorf("unwrap %q: empty response", item.spec.Path))
				continue
			}

			data[item.spec.Alias] = unwrapped.Data
		}

		if remaining == 0 {
			break
		}

		select {
		case <-ctx.Done():
			return data, append(requestErrors, ctx.Err())
		case <-ticker.C:
			if progress != nil && attempt%12 == 0 {
				progress("still waiting for approval")
			}
		}
	}

	if progress != nil {
		progress("approved")
	}

	return data, requestErrors
}

func submitApprovalGroup(ctx context.Context, client *http.Client, address, requesterToken, reason string, accessors []string) error {
	baseURL, err := url.Parse(address)
	if err != nil || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" {
		return errors.New("authorizer address must be an absolute HTTP or HTTPS URL")
	}

	idempotency := make([]byte, 16)
	if _, randomErr := rand.Read(idempotency); randomErr != nil {
		return fmt.Errorf("generate submission idempotency key: %w", randomErr)
	}

	payload, err := json.Marshal(map[string]any{
		"idempotencyKey": hex.EncodeToString(idempotency),
		"reason":         reason,
		"accessors":      accessors,
	})
	if err != nil {
		return fmt.Errorf("encode approval group: %w", err)
	}

	var submissionErr error
	for range 3 {
		retry, attemptErr := submitApprovalGroupAttempt(ctx, client, baseURL, requesterToken, payload)
		if attemptErr == nil {
			return nil
		}

		submissionErr = attemptErr
		if !retry || ctx.Err() != nil {
			return attemptErr
		}
	}

	return submissionErr
}

func submitApprovalGroupAttempt(ctx context.Context, client *http.Client, baseURL *url.URL, requesterToken string, payload []byte) (bool, error) {
	endpoint := baseURL.ResolveReference(&url.URL{Path: "/api/v1/request-groups"})
	//nolint:gosec // The authorizer URL is an explicit CLI/deployment setting.
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return false, fmt.Errorf("create approval group request: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Vault-Token", requesterToken)
	//nolint:gosec // Requests are intentionally sent to the configured authorizer.
	response, err := client.Do(request)
	if err != nil {
		return true, fmt.Errorf("submit approval group: %w", err)
	}

	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusCreated {
		return false, nil
	}

	var failure struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&failure)
	if failure.Error == "" {
		failure.Error = http.StatusText(response.StatusCode)
	}

	return response.StatusCode >= http.StatusInternalServerError, fmt.Errorf("submit approval group: HTTP %d: %s", response.StatusCode, failure.Error)
}

func readCredentials(ctx context.Context, client *openbao.Client, path string, pollInterval time.Duration, progress progressFunc) (map[string]any, error) {
	data, errs := readCredentialRequests(ctx, client, client.Token(), []requestSpec{{Path: path}}, os.Getenv("BAO_AUTHORIZER_ADDR"), "", false, pollInterval, progress)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	result, _ := data[""].(map[string]any)
	return result, nil
}

func controlGroupStatus(ctx context.Context, client *openbao.Client, accessor string) (bool, error) {
	secret, err := client.Logical().WriteWithContext(ctx, "sys/control-group/request", map[string]any{"accessor": accessor})
	if err != nil {
		var responseErr *openbao.ResponseError
		if errors.As(err, &responseErr) && (responseErr.StatusCode == http.StatusBadRequest || responseErr.StatusCode == http.StatusNotFound) {
			return false, errRequestClosed
		}

		return false, err
	}

	if secret == nil {
		return false, errors.New("empty control-group status response")
	}

	approved, ok := secret.Data["approved"].(bool)
	if !ok {
		return false, fmt.Errorf("control-group status has invalid approved value %T", secret.Data["approved"])
	}

	return approved, nil
}

type mapping struct {
	Name string
	Path string
}

func parseMapping(value string) (mapping, error) {
	name, path, ok := strings.Cut(value, "=")
	if !ok || !validName(name) || path == "" {
		return mapping{}, fmt.Errorf("mapping must be NAME=dot.path with a valid environment name: %q", value)
	}

	return mapping{Name: name, Path: path}, nil
}

func resolveMappings(data map[string]any, mappings []mapping) ([]string, error) {
	seen := make(map[string]struct{}, len(mappings))
	values := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		if _, duplicate := seen[mapping.Name]; duplicate {
			return nil, fmt.Errorf("duplicate mapping %q", mapping.Name)
		}

		seen[mapping.Name] = struct{}{}
		value, err := selectValue(data, mapping.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", mapping.Name, err)
		}

		scalar, err := scalar(value)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", mapping.Name, err)
		}

		if strings.IndexByte(scalar, 0) >= 0 {
			return nil, fmt.Errorf("resolve %s: value contains NUL", mapping.Name)
		}

		values = append(values, mapping.Name+"="+scalar)
	}

	return values, nil
}

func selectValue(data map[string]any, path string) (any, error) {
	segments, err := splitPath(path)
	if err != nil {
		return nil, err
	}

	var current any = data
	for _, segment := range segments {
		switch value := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = value[segment]
			if !ok {
				return nil, fmt.Errorf("field %q does not exist", path)
			}
		case []any:
			index, parseErr := strconv.Atoi(segment)
			if parseErr != nil || index < 0 || index >= len(value) {
				return nil, fmt.Errorf("array index %q is invalid in field %q", segment, path)
			}

			current = value[index]
		default:
			return nil, fmt.Errorf("field %q traverses a scalar", path)
		}
	}

	return current, nil
}

func scalar(value any) (string, error) {
	switch value := value.(type) {
	case nil:
		return "null", nil
	case string:
		return value, nil
	case bool:
		return strconv.FormatBool(value), nil
	case json.Number:
		return value.String(), nil
	case float64:
		return strconv.FormatFloat(value, 'g', -1, 64), nil
	case float32:
		return strconv.FormatFloat(float64(value), 'g', -1, 32), nil
	case int:
		return strconv.Itoa(value), nil
	case int64:
		return strconv.FormatInt(value, 10), nil
	case int32:
		return strconv.FormatInt(int64(value), 10), nil
	case uint:
		return strconv.FormatUint(uint64(value), 10), nil
	case uint64:
		return strconv.FormatUint(value, 10), nil
	case uint32:
		return strconv.FormatUint(uint64(value), 10), nil
	default:
		return "", fmt.Errorf("value is not a scalar (%T)", value)
	}
}

func renderJSON(data map[string]any) ([]byte, error) {
	result, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode JSON: %w", err)
	}

	return append(result, '\n'), nil
}

func renderField(data map[string]any, path string) ([]byte, error) {
	value, err := selectValue(data, path)
	if err != nil {
		return nil, err
	}

	scalar, err := scalar(value)
	if err != nil {
		return nil, err
	}

	return []byte(scalar), nil
}

func renderTemplate(data map[string]any, source string) ([]byte, error) {
	tmpl, err := template.New("credentials").Option("missingkey=error").Parse(source)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	var output bytes.Buffer
	if err := tmpl.Execute(&output, data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	return output.Bytes(), nil
}

func renderDotenv(values []string) []byte {
	var output strings.Builder
	for _, value := range values {
		name, raw, _ := strings.Cut(value, "=")
		replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
		fmt.Fprintf(&output, "%s=\"%s\"\n", name, replacer.Replace(raw))
	}

	return []byte(output.String())
}

func renderShell(values []string) []byte {
	var output strings.Builder
	for _, value := range values {
		name, raw, _ := strings.Cut(value, "=")
		fmt.Fprintf(&output, "export %s='%s'\n", name, strings.ReplaceAll(raw, "'", `'"'"'`))
	}

	return []byte(output.String())
}

func writeFile(path string, contents []byte) error {
	directory := filepath.Dir(path)
	temporary, err := createSecureTemp(directory)
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}

	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	if _, err := io.Copy(temporary, bytes.NewReader(contents)); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write output: %w", err)
	}

	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync output: %w", err)
	}

	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}

	if err := replaceFile(temporaryPath, path); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}

	return nil
}

func splitPath(path string) ([]string, error) {
	if path == "" {
		return nil, errors.New("field path is empty")
	}

	var segments []string
	var segment strings.Builder
	escaped := false
	for _, character := range path {
		if escaped {
			segment.WriteRune(character)
			escaped = false
			continue
		}

		if character == '\\' {
			escaped = true
			continue
		}

		if character == '.' {
			if segment.Len() == 0 {
				return nil, fmt.Errorf("field path %q contains an empty segment", path)
			}

			segments = append(segments, segment.String())
			segment.Reset()
			continue
		}

		segment.WriteRune(character)
	}

	if escaped {
		return nil, fmt.Errorf("field path %q ends with an escape", path)
	}

	if segment.Len() == 0 {
		return nil, fmt.Errorf("field path %q contains an empty segment", path)
	}

	return append(segments, segment.String()), nil
}

func validName(name string) bool {
	if name == "" || !isNameStart(name[0]) {
		return false
	}

	for index := 1; index < len(name); index++ {
		if !isNameStart(name[index]) && (name[index] < '0' || name[index] > '9') {
			return false
		}
	}

	return true
}

func isNameStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
