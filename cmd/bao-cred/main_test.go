package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestParseOutputAndExecModes(t *testing.T) {
	output, err := parseOptions([]string{"-field", "database.username", "secret/path"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	if output.path != "secret/path" || output.field != "database.username" {
		t.Fatalf("unexpected options: %#v", output)
	}

	execOptions, err := parseOptions([]string{"-map", "TOKEN=token", "secret/path", "--", "tool", "arg"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(execOptions.command, []string{"tool", "arg"}) || execOptions.mappings[0].Name != "TOKEN" {
		t.Fatalf("unexpected options: %#v", execOptions)
	}
}

func TestParseRejectsMixedDeliveryModes(t *testing.T) {
	_, err := parseOptions([]string{"-field", "token", "-map", "TOKEN=token", "secret/path", "--", "tool"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("mixed delivery modes unexpectedly succeeded")
	}
}

func TestParseRejectsDuplicateMappings(t *testing.T) {
	_, err := parseOptions([]string{"-format", "dotenv", "-map", "TOKEN=one", "-map", "TOKEN=two", "secret/path"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("duplicate mappings unexpectedly succeeded")
	}
}

func TestRequestTokenPriority(t *testing.T) {
	directory := t.TempDir()
	explicit := filepath.Join(directory, "explicit")
	if err := os.WriteFile(explicit, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BAO_TOKEN", "environment-token")
	got, err := requestToken(explicit)
	if err != nil || got != "file-token" {
		t.Fatalf("explicit file: got %q, %v", got, err)
	}

	got, err = requestToken("")
	if err != nil || got != "environment-token" {
		t.Fatalf("environment: got %q, %v", got, err)
	}
}

func TestMergeEnvironmentReplacesMappedValues(t *testing.T) {
	got := mergeEnvironment([]string{"PATH=/bin", "TOKEN=old", "BAO_TOKEN=requester"}, []string{"TOKEN=new", "USER=alice"})
	want := []string{"PATH=/bin", "TOKEN=new", "USER=alice"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestLoginStoresTokenAndLogoutRemovesIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/v1/auth/userpass/login/agent" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}

		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}

		if body["password"] != "login-secret" {
			t.Fatalf("password = %q", body["password"])
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"auth":{"client_token":"stored-token","renewable":true,"lease_duration":3600}}`))
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "config", "agent-token")
	var stdout bytes.Buffer
	if err := runWithInput(
		[]string{"login", "-address", server.URL, "-username", "agent", "-password-stdin", "-token-file", tokenPath},
		bytes.NewBufferString("login-secret\n"), &stdout, &bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(contents) != "stored-token\n" {
		t.Fatalf("token file = %q", contents)
	}

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(tokenPath)
		if statErr != nil {
			t.Fatal(statErr)
		}

		if info.Mode().Perm() != 0o600 {
			t.Fatalf("token mode = %o", info.Mode().Perm())
		}
	}

	if stdout.String() != "Logged in as agent.\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}

	address, err := os.ReadFile(filepath.Join(filepath.Dir(tokenPath), "address"))
	if err != nil {
		t.Fatal(err)
	}

	if string(address) != server.URL+"\n" {
		t.Fatalf("address file = %q", address)
	}

	stdout.Reset()
	if err := runWithInput([]string{"logout", "-token-file", tokenPath}, &bytes.Buffer{}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("token file still exists: %v", err)
	}

	if stdout.String() != "Logged out.\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
