package cmd

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseServerConfigDefaultsBlockPerIpToWholeBlock(t *testing.T) {
	config, err := parseServerConfig([]string{"10.1.2.3"}, "10.0.0.0/24", "", "", false)
	require.NoError(t, err)

	assert.Equal(t, uint(24), config.wgBlockPerIp)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.1.2.3")}, config.bindAddrs)
}

func TestParseServerConfigMasksWgBlock(t *testing.T) {
	config, err := parseServerConfig([]string{"10.1.2.3"}, "10.0.0.77/24", "", "", false)
	require.NoError(t, err)

	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/24"), config.wgBlock)
}

func TestParseServerConfigRequiresIpWhenNoCloud(t *testing.T) {
	_, err := parseServerConfig(nil, "10.0.0.0/24", "", "", false)

	assert.ErrorContains(t, err, "--ip")
}

func TestParseServerConfigAllowsNoIpWithAwsCloud(t *testing.T) {
	config, err := parseServerConfig(nil, "10.0.0.0/16", "/20", "aws", false)
	require.NoError(t, err)

	assert.Equal(t, "aws", config.cloud)
	assert.Equal(t, uint(20), config.wgBlockPerIp)
}

func TestParseServerConfigRejectsUnknownCloud(t *testing.T) {
	_, err := parseServerConfig(nil, "10.0.0.0/16", "", "gcp", false)

	assert.ErrorContains(t, err, "--cloud")
}

func TestParseServerConfigRejectsBlockPerIpWithoutSlash(t *testing.T) {
	_, err := parseServerConfig([]string{"10.1.2.3"}, "10.0.0.0/16", "20", "", false)

	assert.ErrorContains(t, err, "must start with '/'")
}

func TestParseServerConfigRejectsBlockPerIpLargerThanBlock(t *testing.T) {
	_, err := parseServerConfig([]string{"10.1.2.3"}, "10.0.0.0/24", "/16", "", false)

	assert.ErrorContains(t, err, "--wg-block-per-ip")
}

func TestParseServerConfigRejectsMoreIpsThanBlocks(t *testing.T) {
	_, err := parseServerConfig([]string{"10.1.2.3", "10.1.2.4", "10.1.2.5"}, "10.0.0.0/23", "/24", "", false)

	assert.ErrorContains(t, err, "not enough IPs")
}

func TestParseServerConfigRejectsNonIpv4BindAddress(t *testing.T) {
	_, err := parseServerConfig([]string{"::1"}, "10.0.0.0/24", "", "", false)

	assert.ErrorContains(t, err, "invalid IPv4 address")
}
