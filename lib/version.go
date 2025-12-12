package lib

// Version information - set via ldflags at build time.
// Example: go build -ldflags "-X github.com/modal-labs/vprox/lib.GitCommit=abc123 -X github.com/modal-labs/vprox/lib.GitTag=v1.0.0"
var (
	GitCommit = "unknown"
	GitTag    = "unknown"
)
