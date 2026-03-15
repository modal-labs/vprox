package lib

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetOIDCAllowedWorkspaceIDs_Wildcard(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "*")
	result := GetOIDCAllowedWorkspaceIDs()
	assert.Nil(t, result, "wildcard '*' should return nil (allow all)")
}

func TestGetOIDCAllowedWorkspaceIDs_WildcardWithWhitespace(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "  *  ")
	result := GetOIDCAllowedWorkspaceIDs()
	assert.Nil(t, result, "wildcard ' * ' with whitespace should return nil (allow all)")
}

func TestGetOIDCAllowedWorkspaceIDs_CommaSeparated(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "ws-abc,ws-def")
	result := GetOIDCAllowedWorkspaceIDs()
	assert.Equal(t, []string{"ws-abc", "ws-def"}, result)
}

func TestGetOIDCAllowedWorkspaceIDs_Empty(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "")
	result := GetOIDCAllowedWorkspaceIDs()
	assert.Nil(t, result, "empty string should return nil")
}

func TestGetOIDCAllowedWorkspaceIDs_Unset(t *testing.T) {
	os.Unsetenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS")
	result := GetOIDCAllowedWorkspaceIDs()
	assert.Nil(t, result, "unset env should return nil")
}

func TestGetOIDCAllowedWorkspaceIDs_WildcardIsNotSpecialInList(t *testing.T) {
	// A "*" mixed with other values is NOT treated as a wildcard;
	// it is treated as a literal workspace ID entry.
	t.Setenv("VPROX_OIDC_ALLOWED_WORKSPACE_IDS", "ws-abc,*,ws-def")
	result := GetOIDCAllowedWorkspaceIDs()
	assert.Equal(t, []string{"ws-abc", "*", "ws-def"}, result)
}

func TestGetAuthMode_Defaults(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "")
	assert.Equal(t, AuthModePassword, GetAuthMode())
}

func TestGetAuthMode_OIDCModal(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "oidc-modal")
	assert.Equal(t, AuthModeOIDCModal, GetAuthMode())
}

func TestGetAuthMode_OIDCModalCaseInsensitive(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "OIDC-MODAL")
	assert.Equal(t, AuthModeOIDCModal, GetAuthMode())
}

func TestGetAuthMode_UnknownFallsBackToPassword(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "bogus")
	assert.Equal(t, AuthModePassword, GetAuthMode())
}

func TestGetAuthMode_PlainOIDCFallsBackToPassword(t *testing.T) {
	// "oidc" alone is not a valid mode; must be "oidc-modal".
	t.Setenv("VPROX_AUTH_MODE", "oidc")
	assert.Equal(t, AuthModePassword, GetAuthMode())
}

func TestGetOIDCIssuerURL_Default(t *testing.T) {
	t.Setenv("VPROX_OIDC_ISSUER", "")
	assert.Equal(t, "https://oidc.modal.com", GetOIDCIssuerURL())
}

func TestGetOIDCIssuerURL_Custom(t *testing.T) {
	t.Setenv("VPROX_OIDC_ISSUER", "https://custom.issuer.example.com")
	assert.Equal(t, "https://custom.issuer.example.com", GetOIDCIssuerURL())
}

func TestGetOIDCAllowedEnvironmentNames_CommaSeparated(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_ENVIRONMENTS", "main, staging")
	result := GetOIDCAllowedEnvironmentNames()
	assert.Equal(t, []string{"main", "staging"}, result)
}

func TestGetOIDCAllowedEnvironmentNames_Empty(t *testing.T) {
	t.Setenv("VPROX_OIDC_ALLOWED_ENVIRONMENTS", "")
	result := GetOIDCAllowedEnvironmentNames()
	assert.Nil(t, result)
}

func TestGetOIDCToken_Set(t *testing.T) {
	t.Setenv("VPROX_OIDC_TOKEN", "eyJhbGciOiJSUzI1NiJ9.test.sig")
	token, err := GetOIDCToken()
	assert.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.test.sig", token)
}

func TestGetOIDCToken_Unset(t *testing.T) {
	os.Unsetenv("VPROX_OIDC_TOKEN")
	_, err := GetOIDCToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VPROX_OIDC_TOKEN")
}

func TestGetClientToken_Password(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "password")
	t.Setenv("VPROX_PASSWORD", "s3cret")
	token, err := GetClientToken()
	assert.NoError(t, err)
	assert.Equal(t, "s3cret", token)
}

func TestGetClientToken_OIDCModal(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "oidc-modal")
	t.Setenv("VPROX_OIDC_TOKEN", "eyJhbGciOiJSUzI1NiJ9.test.sig")
	token, err := GetClientToken()
	assert.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.test.sig", token)
}

func TestGetClientToken_OIDCModal_MissingToken(t *testing.T) {
	t.Setenv("VPROX_AUTH_MODE", "oidc-modal")
	os.Unsetenv("VPROX_OIDC_TOKEN")
	_, err := GetClientToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VPROX_OIDC_TOKEN")
}
