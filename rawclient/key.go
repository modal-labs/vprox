// Package rawclient is a variant of the vprox client (lib/client.go) that
// does not depend on wgctrl. It is written as free functions parametrized by
// the data they operate on, and talks to the kernel WireGuard module directly
// over generic netlink, implementing only the narrow slice of functionality
// that the vprox client actually uses.
//
// Linux-only.
package rawclient

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// KeyLen is the length in bytes of a WireGuard Curve25519 key.
const KeyLen = 32

// Key is a WireGuard private or public key (raw Curve25519 bytes).
type Key [KeyLen]byte

// GeneratePrivateKey returns a new clamped Curve25519 private key.
func GeneratePrivateKey() (Key, error) {
	var key Key
	if _, err := rand.Read(key[:]); err != nil {
		return Key{}, fmt.Errorf("failed to read random bytes: %v", err)
	}
	// Standard Curve25519 clamping, as done by wireguard-tools.
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}

// PublicKey computes the public key corresponding to private key priv.
func PublicKey(priv Key) Key {
	var pub Key
	p, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(pub[:], p)
	return pub
}

// KeyString returns the base64 encoding of key, as used on the wire and in
// key files.
func KeyString(key Key) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// ParseKey parses a base64-encoded key.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("failed to parse key: %v", err)
	}
	if len(b) != KeyLen {
		return Key{}, fmt.Errorf("incorrect key size: %d", len(b))
	}
	var key Key
	copy(key[:], b)
	return key, nil
}

// runDir is the path for runtime data that should be kept across restarts.
const runDir = "/run/vprox"

// LoadOrGenerateClientKey returns the persisted client private key for the
// given interface, generating and persisting a new one on first use.
// The key lives at /run/vprox/client-key-<ifname>.
func LoadOrGenerateClientKey(ifname string) (Key, error) {
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return Key{}, err
	}
	keyFile := path.Join(runDir, "client-key-"+ifname)
	contents, err := os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		key, err := GeneratePrivateKey()
		if err != nil {
			return Key{}, err
		}
		if err = os.WriteFile(keyFile, []byte(KeyString(key)), 0600); err != nil {
			return Key{}, err
		}
		return key, nil
	} else if err != nil {
		return Key{}, err
	}
	return ParseKey(strings.TrimSpace(string(contents)))
}
