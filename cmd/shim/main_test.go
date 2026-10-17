package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secretToken = "K10-this-is-the-join-token-0123456789"

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// Regression: the -token flag's default was the value of SHIM_TOKEN, and the
// flag package prints defaults in its usage text - so -h, or any mistyped
// flag, wrote the cluster join token to the pod log.
func TestUsageNeverContainsTheToken(t *testing.T) {
	getenv := envOf(map[string]string{"SHIM_TOKEN": secretToken})
	for _, args := range [][]string{{"-h"}, {"--help"}, {"-no-such-flag"}, {"-api-qps", "not-a-number"}} {
		var out bytes.Buffer
		_, _ = parseOptions(args, getenv, &out)
		if out.Len() == 0 {
			t.Errorf("%v: expected usage output", args)
		}
		if strings.Contains(out.String(), secretToken) {
			t.Errorf("%v: usage output contains the join token", args)
		}
	}
}

func TestTokenResolution(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  from-file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		args    []string
		env     map[string]string
		want    string
		wantErr bool
	}{
		{"env", nil, map[string]string{"SHIM_TOKEN": "from-env"}, "from-env", false},
		{"flag", []string{"-token", "from-flag"}, nil, "from-flag", false},
		{"file flag, trimmed", []string{"-token-file", file}, nil, "from-file-token", false},
		{"file env", nil, map[string]string{"SHIM_TOKEN_FILE": file}, "from-file-token", false},
		{"file wins over env", nil, map[string]string{"SHIM_TOKEN_FILE": file, "SHIM_TOKEN": "from-env"}, "from-file-token", false},
		{"nothing", nil, nil, "", true},
		{"empty file", []string{"-token-file", empty}, map[string]string{"SHIM_TOKEN": "from-env"}, "", true},
		{"missing file", []string{"-token-file", filepath.Join(dir, "nope")}, nil, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			getenv := envOf(c.env)
			o, err := parseOptions(c.args, getenv, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := resolveToken(o, getenv)
			if c.wantErr {
				if err == nil {
					t.Fatalf("got token %q, want an error", got)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}
