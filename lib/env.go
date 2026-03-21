package lib

import (
	"errors"
	"os"
	"strconv"
)

func GetVproxPassword() (string, error) {
	password := os.Getenv("VPROX_PASSWORD")
	if password == "" {
		return "", errors.New("VPROX_PASSWORD environment variable is not set")
	}
	return password, nil
}

// GetMaxPeers reads the maximum number of concurrent peers from the
// VPROX_MAX_PEERS environment variable. If unset or empty, it returns
// DefaultMaxPeers.
func GetMaxPeers() (int, error) {
	v := os.Getenv("VPROX_MAX_PEERS")
	if v == "" {
		return DefaultMaxPeers, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, errors.New("VPROX_MAX_PEERS must be a valid integer")
	}
	if n < 1 {
		return 0, errors.New("VPROX_MAX_PEERS must be >= 1")
	}
	return n, nil
}
