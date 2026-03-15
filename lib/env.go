package lib

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

func GetVproxPassword() (string, error) {
	password := os.Getenv("VPROX_PASSWORD")
	if password == "" {
		return "", errors.New("VPROX_PASSWORD environment variable is not set")
	}
	return password, nil
}

// GetAuthMode returns the configured auth mode from the VPROX_AUTH_MODE
// environment variable. Defaults to "password" if not set.
func GetAuthMode() AuthMode {
	mode := os.Getenv("VPROX_AUTH_MODE")
	switch strings.ToLower(mode) {
	case "oidc-modal":
		return AuthModeOIDCModal
	case "password", "":
		return AuthModePassword
	default:
		// Fall back to password mode for unknown values.
		return AuthModePassword
	}
}

// GetOIDCIssuerURL returns the OIDC issuer URL from the VPROX_OIDC_ISSUER
// environment variable. Defaults to "https://oidc.modal.com" if not set.
func GetOIDCIssuerURL() string {
	issuer := os.Getenv("VPROX_OIDC_ISSUER")
	if issuer == "" {
		return "https://oidc.modal.com"
	}
	return issuer
}

// GetOIDCAudience returns the expected OIDC audience from the
// VPROX_OIDC_AUDIENCE environment variable. If empty, audience is not checked.
func GetOIDCAudience() string {
	return os.Getenv("VPROX_OIDC_AUDIENCE")
}

// GetOIDCAllowedWorkspaceIDs returns the list of allowed Modal workspace IDs
// from the VPROX_OIDC_ALLOWED_WORKSPACE_IDS environment variable (comma-separated).
// If empty, any workspace is allowed. If set to "*", all workspaces are explicitly
// allowed (returns nil) with a warning logged at startup.
func GetOIDCAllowedWorkspaceIDs() []string {
	raw := os.Getenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS")
	if strings.TrimSpace(raw) == "*" {
		log.Println("WARNING: VPROX_OIDC_ALLOWED_WORKSPACE_IDS is set to '*', allowing ALL workspaces. This should only be used for testing!")
		return nil
	}
	return splitCSV(raw)
}

// GetOIDCAllowedEnvironmentNames returns the list of allowed Modal environment
// names from the VPROX_OIDC_ALLOWED_ENVIRONMENTS environment variable (comma-separated).
// If empty, any environment is allowed.
func GetOIDCAllowedEnvironmentNames() []string {
	return splitCSV(os.Getenv("VPROX_OIDC_ALLOWED_ENVIRONMENTS"))
}

// GetOIDCToken returns the OIDC identity token from the VPROX_OIDC_TOKEN
// environment variable.
func GetOIDCToken() (string, error) {
	token := os.Getenv("VPROX_OIDC_TOKEN")
	if token == "" {
		return "", errors.New("VPROX_OIDC_TOKEN environment variable is not set")
	}
	return token, nil
}

// GetAuthenticator creates the appropriate Authenticator based on environment
// configuration. This is used by the server.
func GetAuthenticator() (*Authenticator, error) {
	mode := GetAuthMode()

	switch mode {
	case AuthModeOIDCModal:
		config := &OIDCConfig{
			IssuerURL:               GetOIDCIssuerURL(),
			Audience:                GetOIDCAudience(),
			AllowedWorkspaceIDs:     GetOIDCAllowedWorkspaceIDs(),
			AllowedEnvironmentNames: GetOIDCAllowedEnvironmentNames(),
		}
		auth, err := NewOIDCModalAuthenticator(config)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC authenticator: %v", err)
		}
		return auth, nil

	case AuthModePassword:
		password, err := GetVproxPassword()
		if err != nil {
			return nil, err
		}
		return NewPasswordAuthenticator(password), nil

	default:
		return nil, fmt.Errorf("unknown auth mode: %s", mode)
	}
}

// GetClientToken returns the bearer token the client should send to the server,
// based on the current auth mode.
func GetClientToken() (string, error) {
	mode := GetAuthMode()

	switch mode {
	case AuthModeOIDCModal:
		return GetOIDCToken()
	case AuthModePassword:
		return GetVproxPassword()
	default:
		return "", fmt.Errorf("unknown auth mode: %s", mode)
	}
}

// splitCSV splits a comma-separated string into a slice, trimming whitespace
// and filtering out empty strings.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
