package lib

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testServerManager(t *testing.T, wgBlock string, wgBlockPerIp uint) *ServerManager {
	t.Helper()
	return &ServerManager{
		wgBlock:      netip.MustParsePrefix(wgBlock).Masked(),
		wgBlockPerIp: wgBlockPerIp,
	}
}

func TestAllocateServerIndexHandsOutIndicesInOrder(t *testing.T) {
	manager := testServerManager(t, "10.0.0.0/22", 24)

	first, err := allocateServerIndex(manager)
	require.NoError(t, err)
	second, err := allocateServerIndex(manager)
	require.NoError(t, err)

	assert.Equal(t, uint16(0), first)
	assert.Equal(t, uint16(1), second)
}

func TestAllocateServerIndexReusesFreedIndexBeforeNewOnes(t *testing.T) {
	manager := testServerManager(t, "10.0.0.0/22", 24)
	first, err := allocateServerIndex(manager)
	require.NoError(t, err)
	_, err = allocateServerIndex(manager)
	require.NoError(t, err)

	freeServerIndex(manager, first)
	reused, err := allocateServerIndex(manager)
	require.NoError(t, err)

	assert.Equal(t, first, reused)
}

func TestAllocateServerIndexFailsWhenEveryBlockIsInUse(t *testing.T) {
	manager := testServerManager(t, "10.0.0.0/23", 24)
	_, err := allocateServerIndex(manager)
	require.NoError(t, err)
	_, err = allocateServerIndex(manager)
	require.NoError(t, err)

	_, err = allocateServerIndex(manager)

	assert.Error(t, err)
}

func TestServerWireguardCidrIsIndexthBlockWithServerAddressAfterNetworkAddress(t *testing.T) {
	manager := testServerManager(t, "10.0.0.0/22", 24)

	assert.Equal(t, netip.MustParsePrefix("10.0.0.1/24"), serverWireguardCidr(manager, 0))
	assert.Equal(t, netip.MustParsePrefix("10.0.2.1/24"), serverWireguardCidr(manager, 2))
}
