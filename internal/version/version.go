// Package version carries build metadata set with -ldflags -X.
package version

// Set at build time; see Taskfile.yml.
var (
	Version = "0.0.0-dev"
	Commit  = "none"
)
