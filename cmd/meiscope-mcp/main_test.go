package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunFlags(t *testing.T) {
	tests := []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{[]string{"-version"}, 0, "meiscope-mcp 0.0.0-dev", ""},
		{[]string{"-no-such-flag"}, 2, "", "flag provided but not defined"},
		{[]string{"-log-level", "loud"}, 2, "", "invalid -log-level"},
	}
	for _, tc := range tests {
		var out, errb bytes.Buffer
		if code := run(context.Background(), tc.args, &out, &errb); code != tc.code {
			t.Fatalf("%v: code %d, stderr %q", tc.args, code, errb.String())
		}
		if !strings.Contains(out.String(), tc.stdout) || !strings.Contains(errb.String(), tc.stderr) {
			t.Fatalf("%v: stdout %q stderr %q", tc.args, out.String(), errb.String())
		}
	}
}
