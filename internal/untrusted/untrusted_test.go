package untrusted_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/uvamai/meiscope-mcp/internal/untrusted"
)

func TestClean(t *testing.T) {
	tests := []struct{ in, want string }{
		{"www.example.com", "www.example.com"},
		{"a\x00b\nc", "a\uFFFDb\uFFFDc"},
		{"evil\u202Egnp.exe", "evil\uFFFDgnp.exe"}, // right-to-left override
		{"zero\u200Bwidth", "zero\uFFFDwidth"},
		{"bad\xffutf8", "bad\uFFFDutf8"},
		{"Ünïcödé ok", "Ünïcödé ok"},
	}
	for _, tc := range tests {
		if got := untrusted.Clean(tc.in); got != tc.want {
			t.Errorf("Clean(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := untrusted.Clean(strings.Repeat("x", 1000))
	if utf8.RuneCountInString(long) > untrusted.MaxStringLen+20 || !strings.HasSuffix(long, "[truncated]") {
		t.Fatalf("long string not truncated: %d runes", utf8.RuneCountInString(long))
	}
}

func TestCleanAll(t *testing.T) {
	out, dropped := untrusted.CleanAll([]string{"a", "b", "c"}, 2)
	if len(out) != 2 || dropped != 1 {
		t.Fatalf("out=%v dropped=%d", out, dropped)
	}
	out, dropped = untrusted.CleanAll([]string{"a"}, 5)
	if len(out) != 1 || dropped != 0 {
		t.Fatalf("out=%v dropped=%d", out, dropped)
	}
}
