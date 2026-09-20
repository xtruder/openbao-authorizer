package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	openbao "github.com/openbao/openbao/api/v2"
)

type progressFunc func(string)

func readCredentials(ctx context.Context, client *openbao.Client, path string, pollInterval time.Duration, progress progressFunc) (map[string]any, error) {
	secret, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	if secret == nil {
		return nil, fmt.Errorf("read %q: empty response", path)
	}

	if secret.WrapInfo == nil || secret.WrapInfo.Token == "" {
		return secret.Data, nil
	}

	if secret.WrapInfo.Accessor == "" {
		return nil, errors.New("wrapped response has no accessor")
	}

	if progress != nil {
		progress("approval requested; waiting")
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	attempt := 0
	for {
		attempt++
		approved, statusErr := controlGroupStatus(ctx, client, secret.WrapInfo.Accessor)
		if statusErr != nil {
			return nil, fmt.Errorf("check approval: %w", statusErr)
		}

		if approved {
			unwrapped, unwrapErr := client.Logical().UnwrapWithContext(ctx, secret.WrapInfo.Token)
			if unwrapErr != nil {
				return nil, fmt.Errorf("unwrap approved response: %w", unwrapErr)
			}

			if unwrapped == nil {
				return nil, errors.New("unwrap approved response: empty response")
			}

			if progress != nil {
				progress("approved")
			}

			return unwrapped.Data, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if progress != nil && attempt%12 == 0 {
				progress("still waiting for approval")
			}
		}
	}
}

func controlGroupStatus(ctx context.Context, client *openbao.Client, accessor string) (bool, error) {
	secret, err := client.Logical().WriteWithContext(ctx, "sys/control-group/request", map[string]any{"accessor": accessor})
	if err != nil {
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
