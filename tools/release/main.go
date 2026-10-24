// Command release packages built meiscope-mcp binaries as MCP Bundles
// (.mcpb, https://github.com/modelcontextprotocol/mcpb) and writes the
// server.json for the official MCP registry with each bundle's SHA-256.
//
//	go run ./tools/release -version 0.1.0 -bin bin -out release
//	go run ./tools/release -version 0.1.0 -placeholder -server-json server.json
//
// Bundles are deterministic: fixed timestamps and modes, files in a fixed
// order, so a rebuild of the same binaries gives the same bytes and hashes.
// The tool never contacts the registry.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	binary     = "meiscope-mcp"
	repository = "https://github.com/uvamai/meiscope-mcp"
	// RegistryName is the server's name in the MCP registry (GitHub namespace).
	registryName = "io.github.uvamai/meiscope-mcp"
	schemaURL    = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
	description  = "Inspect X.509 certificates and TLS endpoints, and assess expiry risk against the CA/B Forum 200/100/47-day schedule. Read-only; never authenticates."
	// registryDescription fits the registry's 100-character limit.
	registryDescription = "Inspect X.509 certificates and TLS endpoints; expiry risk vs the CA/B 200/100/47-day schedule."
	// PlaceholderSHA marks a hash the release workflow fills in.
	placeholderSHA = "0000000000000000000000000000000000000000000000000000000000000000"
)

// target is one release platform.
type target struct{ goos, goarch string }

var targets = []target{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
}

func (t target) exe() string {
	if t.goos == "windows" {
		return binary + ".exe"
	}
	return binary
}

func (t target) bundleName() string { return fmt.Sprintf("%s_%s_%s.mcpb", binary, t.goos, t.goarch) }

// mcpbPlatform maps GOOS to the MCPB compatibility platform name.
func (t target) mcpbPlatform() string {
	if t.goos == "windows" {
		return "win32"
	}
	return t.goos
}

// bundleTime is the fixed modification time of every bundle entry.
var bundleTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

var semver = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		slog.Error("release", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.String("version", "", "release version without the v, e.g. 0.1.0")
	binDir := fs.String("bin", "bin", "directory with <os>_<arch>/meiscope-mcp[.exe] from task build")
	outDir := fs.String("out", "release", "directory for the bundles and server.json")
	placeholder := fs.Bool("placeholder", false, "write only server.json, with placeholder hashes (the committed template)")
	serverJSON := fs.String("server-json", "", "server.json path (default <out>/server.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !semver.MatchString(*version) {
		return fmt.Errorf("-version %q is not a semantic version like 0.1.0", *version)
	}
	sjPath := *serverJSON
	if sjPath == "" {
		sjPath = filepath.Join(*outDir, "server.json")
	}
	hashes := map[target]string{}
	if *placeholder {
		for _, t := range targets {
			hashes[t] = placeholderSHA
		}
	} else {
		if err := os.MkdirAll(*outDir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", *outDir, err)
		}
		for _, t := range targets {
			h, err := writeBundle(t, *version, *binDir, *outDir)
			if err != nil {
				return err
			}
			hashes[t] = h
		}
	}
	b, err := serverDocument(*version, hashes)
	if err != nil {
		return err
	}
	if err := os.WriteFile(sjPath, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", sjPath, err)
	}
	return nil
}

// manifest is an MCPB manifest (manifest_version 0.3) for the binary server.
func manifest(t target, version string) map[string]any {
	entry := "server/" + t.exe()
	return map[string]any{
		"manifest_version": "0.3",
		"name":             binary,
		"display_name":     "Meiscope certificate inspector",
		"version":          version,
		"description":      description,
		"author":           map[string]any{"name": "UVAMAI", "url": "https://meiscope.com"},
		"repository":       map[string]any{"type": "git", "url": repository},
		"homepage":         repository,
		"license":          "Apache-2.0",
		"server": map[string]any{
			"type":        "binary",
			"entry_point": entry,
			"mcp_config": map[string]any{
				"command": "${__dirname}/" + entry,
				"args":    []string{},
				"env": map[string]string{
					"MEISCOPE_MCP_MAX_PROBES_PER_MINUTE": "${user_config.max_probes_per_minute}",
					"MEISCOPE_MCP_ALLOW":                 "${user_config.allow}",
				},
			},
		},
		"user_config": map[string]any{
			"max_probes_per_minute": map[string]any{
				"type": "number", "title": "Probes per minute",
				"description": "Endpoint probes allowed per rolling minute (1 to 120).",
				"default":     30, "min": 1, "max": 120, "required": false,
			},
			"allow": map[string]any{
				"type": "string", "title": "Allow list",
				"description": "Optional comma-separated DNS suffixes and CIDRs; when set, only these may be probed.",
				"default":     "", "required": false,
			},
		},
		"tools": []map[string]string{
			{"name": "inspect_certificate", "description": "Parse and describe X.509 certificates"},
			{"name": "inspect_tls_endpoint", "description": "One TLS handshake to a host; report the served chain"},
			{"name": "assess_expiry_risk", "description": "Expiry risk against the CA/B Forum lifetime schedule"},
			{"name": "compare_certificates", "description": "Judge whether a replacement is a legitimate renewal"},
		},
		"compatibility": map[string]any{"platforms": []string{t.mcpbPlatform()}},
	}
}

// writeBundle zips manifest.json and the binary and returns the SHA-256.
func writeBundle(t target, version, binDir, outDir string) (string, error) {
	exe, err := os.ReadFile(filepath.Join(binDir, t.goos+"_"+t.goarch, t.exe())) //nolint:gosec // build output path
	if err != nil {
		return "", fmt.Errorf("read %s/%s binary: %w", t.goos, t.goarch, err)
	}
	m, err := json.MarshalIndent(manifest(t, version), "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, mode os.FileMode, data []byte) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: bundleTime}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return fmt.Errorf("bundle entry %s: %w", name, err)
		}
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("bundle entry %s: %w", name, err)
		}
		return nil
	}
	if err := add("manifest.json", 0o644, append(m, '\n')); err != nil {
		return "", err
	}
	if err := add("server/"+t.exe(), 0o755, exe); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("close bundle: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, t.bundleName()), buf.Bytes(), 0o600); err != nil {
		return "", fmt.Errorf("write bundle: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// serverDocument is the registry server.json. One mcpb package per target:
// MCPB declares operating systems, not CPU architectures.
func serverDocument(version string, hashes map[target]string) ([]byte, error) {
	var pkgs []map[string]any
	for _, t := range targets {
		h, ok := hashes[t]
		if !ok {
			return nil, errors.New("missing hash for " + t.goos + "/" + t.goarch)
		}
		pkgs = append(pkgs, map[string]any{
			"registryType": "mcpb",
			"identifier":   fmt.Sprintf("%s/releases/download/v%s/%s", repository, version, t.bundleName()),
			"fileSha256":   h,
			"transport":    map[string]string{"type": "stdio"},
		})
	}
	doc := map[string]any{
		"$schema":     schemaURL,
		"name":        registryName,
		"title":       "Meiscope certificate inspector",
		"description": registryDescription,
		"version":     version,
		"websiteUrl":  "https://meiscope.com",
		"repository":  map[string]string{"url": repository, "source": "github"},
		"packages":    pkgs,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode server.json: %w", err)
	}
	return append(b, '\n'), nil
}
