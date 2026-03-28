package lib

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthMode determines how the server authenticates incoming requests.
type AuthMode string

const (
	AuthModePassword AuthMode = "password"
	AuthModeOIDC     AuthMode = "oidc"
)

// OIDCConfig holds configuration for OIDC-based authentication.
type OIDCConfig struct {
	// IssuerURL is the OIDC issuer URL (e.g. "https://oidc.modal.com").
	IssuerURL string

	// Audience is the expected "aud" claim in the token. If empty, audience is not checked.
	Audience string

	// AllowedWorkspaceIDs is a list of workspace IDs that are allowed to authenticate.
	// If empty, any workspace is allowed (only issuer/signature are checked).
	AllowedWorkspaceIDs []string

	// AllowedEnvironmentNames is a list of environment names that are allowed.
	// If empty, any environment is allowed.
	AllowedEnvironmentNames []string
}

// Authenticator provides request authentication for the vprox server.
type Authenticator struct {
	mode     AuthMode
	password string
	oidc     *OIDCConfig
	jwks     *JWKSCache
}

// NewPasswordAuthenticator creates an Authenticator that uses password-based auth.
func NewPasswordAuthenticator(password string) *Authenticator {
	return &Authenticator{
		mode:     AuthModePassword,
		password: password,
	}
}

// NewOIDCAuthenticator creates an Authenticator that validates Modal OIDC tokens.
func NewOIDCAuthenticator(config *OIDCConfig) (*Authenticator, error) {
	if config.IssuerURL == "" {
		return nil, errors.New("OIDC issuer URL is required")
	}
	// Strip trailing slash for consistency.
	config.IssuerURL = strings.TrimRight(config.IssuerURL, "/")

	jwksURL, err := discoverJWKSURL(config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover JWKS URL from issuer %s: %v", config.IssuerURL, err)
	}

	return &Authenticator{
		mode: AuthModeOIDC,
		oidc: config,
		jwks: NewJWKSCache(jwksURL),
	}, nil
}

// Authenticate checks the Authorization header of an HTTP request.
// Returns nil on success, or an error describing the failure.
func (a *Authenticator) Authenticate(r *http.Request) error {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return errors.New("missing or malformed Authorization header")
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	switch a.mode {
	case AuthModePassword:
		if token != a.password {
			return errors.New("invalid password")
		}
		return nil

	case AuthModeOIDC:
		return a.verifyOIDCToken(token)

	default:
		return fmt.Errorf("unknown auth mode: %s", a.mode)
	}
}

// Mode returns the authentication mode.
func (a *Authenticator) Mode() AuthMode {
	return a.mode
}

// verifyOIDCToken verifies a JWT token against the OIDC provider's JWKS.
func (a *Authenticator) verifyOIDCToken(tokenStr string) error {
	// Parse the JWT without verification first to get the header.
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT: expected 3 parts")
	}

	// Decode the header to get the key ID.
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return fmt.Errorf("invalid JWT header encoding: %v", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("invalid JWT header: %v", err)
	}

	if header.Alg != "RS256" {
		return fmt.Errorf("unsupported JWT algorithm: %s", header.Alg)
	}

	// Decode the payload.
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return fmt.Errorf("invalid JWT payload encoding: %v", err)
	}

	var claims ModalOIDCClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return fmt.Errorf("invalid JWT payload: %v", err)
	}

	// Verify the signature using the JWKS.
	sigBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("invalid JWT signature encoding: %v", err)
	}

	signedContent := parts[0] + "." + parts[1]
	if err := a.jwks.VerifyRS256(header.Kid, []byte(signedContent), sigBytes); err != nil {
		return fmt.Errorf("JWT signature verification failed: %v", err)
	}

	// Verify standard claims.
	now := time.Now().Unix()

	if claims.Exp != 0 && now > claims.Exp {
		return fmt.Errorf("token expired at %d, current time is %d", claims.Exp, now)
	}

	// Allow 60 seconds of clock skew for iat.
	if claims.Iat != 0 && now < claims.Iat-60 {
		return fmt.Errorf("token issued in the future: iat=%d, now=%d", claims.Iat, now)
	}

	if claims.Iss != a.oidc.IssuerURL {
		return fmt.Errorf("issuer mismatch: got %q, expected %q", claims.Iss, a.oidc.IssuerURL)
	}

	if a.oidc.Audience != "" && claims.Aud != a.oidc.Audience {
		return fmt.Errorf("audience mismatch: got %q, expected %q", claims.Aud, a.oidc.Audience)
	}

	// Verify Modal-specific claims.
	if len(a.oidc.AllowedWorkspaceIDs) > 0 {
		if !stringInSlice(claims.WorkspaceID, a.oidc.AllowedWorkspaceIDs) {
			return fmt.Errorf("workspace %q is not in the allowed list", claims.WorkspaceID)
		}
	}

	if len(a.oidc.AllowedEnvironmentNames) > 0 {
		if !stringInSlice(claims.EnvironmentName, a.oidc.AllowedEnvironmentNames) {
			return fmt.Errorf("environment %q is not in the allowed list", claims.EnvironmentName)
		}
	}

	return nil
}

// ModalOIDCClaims represents the claims in a Modal OIDC identity token.
type ModalOIDCClaims struct {
	// Standard OIDC claims
	Sub string `json:"sub\` // Subject: unique identifier for the user/entity
	Aud string `json:"aud\` // Audience: intended recipient of the token (e.g., client ID)
	Exp int64  `json:"exp"` // Expiration Time: Unix timestamp after which the token is invalid
	Iat int64  `json:"iat"` // Issued At: Unix timestamp when the token was issued
	Iss string `json:"iss"` // Issuer: URL of the identity provider that issued the token
	Jti string `json:"jti"` // JWT ID: unique identifier for the token (used to prevent replay attacks)

	// Modal-specific claims
	WorkspaceID     string `json:"workspace_id"`
	EnvironmentID   string `json:"environment_id"`
	EnvironmentName string `json:"environment_name"`
	AppID           string `json:"app_id"`
	AppName         string `json:"app_name"`
	FunctionID      string `json:"function_id"`
	FunctionName    string `json:"function_name"`
	ContainerID     string `json:"container_id"`
}

type jwtHeader struct {
	Alg string `json:"alg"` // Algorithm: the signing algorithm used (e.g. "RS256")
	Kid string `json:"kid"` // Key ID: identifier for the key used to sign the token
	Typ string `json:"typ"` // Type: the type of token (e.g., "JWT")
}

// --- JWKS Cache ---

// JWKSCache fetches and caches JWKS keys from a remote endpoint.
type JWKSCache struct {
	url        string
	mu         sync.RWMutex
	keys       map[string]*rsa.PublicKey
	lastFetch  time.Time
	httpClient *http.Client
}

const jwksCacheDuration = 5 * time.Minute

// NewJWKSCache creates a new JWKS cache for the given URL.
func NewJWKSCache(url string) *JWKSCache {
	return &JWKSCache{
		url:  url,
		keys: make(map[string]*rsa.PublicKey),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// VerifyRS256 verifies an RS256 signature using the cached JWKS keys.
func (c *JWKSCache) VerifyRS256(kid string, message, signature []byte) error {
	key, err := c.getKey(kid)
	if err != nil {
		return err
	}

	return verifyRS256Signature(key, message, signature)
}

// getKey returns the RSA public key for the given key ID, fetching from the
// JWKS endpoint if necessary.
func (c *JWKSCache) getKey(kid string) (*rsa.PublicKey, error) {
	// Try to find the key in the cache first.
	c.mu.RLock()
	key, ok := c.keys[kid]
	cacheValid := time.Since(c.lastFetch) < jwksCacheDuration
	c.mu.RUnlock()

	if ok && cacheValid {
		return key, nil
	}

	// If the key is not found or the cache is stale, refresh.
	if err := c.refresh(); err != nil {
		return nil, fmt.Errorf("failed to refresh JWKS: %v", err)
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}

	return key, nil
}

// refresh fetches the JWKS from the remote endpoint and updates the cache.
func (c *JWKSCache) refresh() error {
	resp, err := c.httpClient.Get(c.url)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS from %s: %v", c.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %v", err)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %v", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue
		}
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}

		pubKey, err := jwkToRSAPublicKey(jwk)
		if err != nil {
			continue // skip malformed keys
		}

		keys[jwk.Kid] = pubKey
	}

	c.mu.Lock()
	c.keys = keys
	c.lastFetch = time.Now()
	c.mu.Unlock()

	return nil
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// --- OIDC Discovery ---

type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discoverJWKSURL fetches the OIDC discovery document and returns the JWKS URL.
func discoverJWKSURL(issuerURL string) (string, error) {
	discoveryURL := issuerURL + "/.well-known/openid-configuration"

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC discovery from %s: %v", discoveryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OIDC discovery response: %v", err)
	}

	var discovery oidcDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return "", fmt.Errorf("failed to parse OIDC discovery document: %v", err)
	}

	if discovery.JWKSURI == "" {
		return "", errors.New("OIDC discovery document missing jwks_uri")
	}

	return discovery.JWKSURI, nil
}

// --- Crypto helpers ---

// jwkToRSAPublicKey converts a JWK to an RSA public key.
func jwkToRSAPublicKey(jwk jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK modulus: %v", err)
	}

	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK exponent: %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, errors.New("JWK exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// verifyRS256Signature verifies an RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signature.
func verifyRS256Signature(pubKey *rsa.PublicKey, message, signature []byte) error {
	// RS256 = RSASSA-PKCS1-v1_5 using SHA-256
	h := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h[:], signature)
}

// base64URLDecode decodes a base64url-encoded string (with or without padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// --- Utility ---

func stringInSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
