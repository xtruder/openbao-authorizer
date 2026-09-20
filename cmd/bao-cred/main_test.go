package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
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
