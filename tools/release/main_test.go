package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fakeBins writes a stand-in binary for every target.
func fakeBins(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, tg := range targets {
		d := filepath.Join(dir, tg.goos+"_"+tg.goarch)
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, tg.exe()), []byte("binary for "+tg.goos+"/"+tg.goarch), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type serverDoc struct {
	Schema      string `json:"$schema"`
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Repository  struct {
		URL    string `json:"url"`
		Source string `json:"source"`
	} `json:"repository"`
	Packages []struct {
		RegistryType string            `json:"registryType"`
		Identifier   string            `json:"identifier"`
		FileSha256   string            `json:"fileSha256"`
		Transport    map[string]string `json:"transport"`
	} `json:"packages"`
}

func readDoc(t *testing.T, path string) serverDoc {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test temp path
	if err != nil {
		t.Fatal(err)
	}
	var d serverDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// checkRegistryConstraints applies the 2025-12-11 server.schema.json limits.
func checkRegistryConstraints(t *testing.T, d serverDoc) {
	t.Helper()
	if !regexp.MustCompile(`^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$`).MatchString(d.Name) || len(d.Name) > 200 {
		t.Errorf("name %q breaks the registry pattern", d.Name)
	}
	if n := len(d.Description); n < 1 || n > 100 {
		t.Errorf("description is %d characters; the registry allows 1 to 100", n)
	}
	if n := len(d.Title); n < 1 || n > 100 {
		t.Errorf("title is %d characters", n)
	}
	if d.Repository.URL == "" || d.Repository.Source != "github" {
		t.Errorf("repository %+v", d.Repository)
	}
	sha := regexp.MustCompile(`^[a-f0-9]{64}$`)
	if len(d.Packages) != len(targets) {
		t.Fatalf("%d packages, want %d", len(d.Packages), len(targets))
	}
	for _, p := range d.Packages {
		if p.RegistryType != "mcpb" || p.Transport["type"] != "stdio" || !sha.MatchString(p.FileSha256) {
			t.Errorf("package %+v", p)
		}
		if !strings.HasPrefix(p.Identifier, "https://github.com/uvamai/meiscope-mcp/releases/download/v"+d.Version+"/") || !strings.Contains(p.Identifier, "mcp") {
			t.Errorf("identifier %q must be a GitHub release asset whose URL contains \"mcp\"", p.Identifier)
		}
	}
}

func TestBundlesAndServerJSON(t *testing.T) {
	bin := fakeBins(t)
	out := t.TempDir()
	if err := run([]string{"-version", "0.1.0", "-bin", bin, "-out", out}, io.Discard); err != nil {
		t.Fatal(err)
	}
	doc := readDoc(t, filepath.Join(out, "server.json"))
	checkRegistryConstraints(t, doc)
	for i, tg := range targets {
		b, err := os.ReadFile(filepath.Join(out, tg.bundleName())) //nolint:gosec // test temp path
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != doc.Packages[i].FileSha256 {
			t.Errorf("%s: server.json hash %s, file hash %s", tg.bundleName(), doc.Packages[i].FileSha256, got)
		}
		zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			t.Fatal(err)
		}
		if len(zr.File) != 2 || zr.File[0].Name != "manifest.json" || zr.File[1].Name != "server/"+tg.exe() {
			t.Fatalf("%s entries %v", tg.bundleName(), zr.File)
		}
		if zr.File[1].Mode().Perm()&0o111 == 0 {
			t.Errorf("%s: binary is not executable in the bundle", tg.bundleName())
		}
		rc, err := zr.File[0].Open()
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.NewDecoder(rc).Decode(&m); err != nil {
			t.Fatal(err)
		}
		_ = rc.Close()
		srv, _ := m["server"].(map[string]any)
		cfg, _ := srv["mcp_config"].(map[string]any)
		if m["manifest_version"] != "0.3" || m["version"] != "0.1.0" || srv["type"] != "binary" || srv["entry_point"] != "server/"+tg.exe() ||
			cfg["command"] != "${__dirname}/server/"+tg.exe() {
			t.Errorf("%s manifest %v", tg.bundleName(), m)
		}
		plats, _ := m["compatibility"].(map[string]any)["platforms"].([]any)
		if len(plats) != 1 || plats[0] != tg.mcpbPlatform() {
			t.Errorf("%s platforms %v", tg.bundleName(), plats)
		}
	}
	// Deterministic: a second build gives identical bytes.
	out2 := t.TempDir()
	if err := run([]string{"-version", "0.1.0", "-bin", bin, "-out", out2}, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server.json", targets[0].bundleName()} {
		a, _ := os.ReadFile(filepath.Join(out, name))  //nolint:gosec // test temp path
		b, _ := os.ReadFile(filepath.Join(out2, name)) //nolint:gosec // test temp path
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs between two builds", name)
		}
	}
}

// TestCommittedServerJSONIsCurrent: the repository's server.json is exactly
// what the tool writes in placeholder mode, so it never drifts from the
// release workflow's output.
func TestCommittedServerJSONIsCurrent(t *testing.T) {
	committed := filepath.Join("..", "..", "server.json")
	doc := readDoc(t, committed)
	checkRegistryConstraints(t, doc)
	out := filepath.Join(t.TempDir(), "server.json")
	if err := run([]string{"-version", doc.Version, "-placeholder", "-server-json", out}, io.Discard); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(out)       //nolint:gosec // test temp path
	got, _ := os.ReadFile(committed) //nolint:gosec // repository file
	if !bytes.Equal(got, want) {
		t.Fatalf("server.json is stale; run: go run ./tools/release -version %s -placeholder -server-json server.json", doc.Version)
	}
	for _, p := range doc.Packages {
		if p.FileSha256 != placeholderSHA {
			t.Errorf("committed server.json must carry placeholder hashes; the release fills them in")
		}
	}
}

func TestRunErrors(t *testing.T) {
	for _, args := range [][]string{
		{"-version", "v0.1.0"},
		{"-version", ""},
		{"-version", "0.1.0", "-bin", t.TempDir(), "-out", t.TempDir()}, // no binaries
		{"-no-such-flag"},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Errorf("run(%v) succeeded", args)
		}
	}
	if _, err := serverDocument("0.1.0", map[target]string{}); err == nil {
		t.Error("missing hashes accepted")
	}
}
