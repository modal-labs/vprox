package lib

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testPeerKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	assert.NoError(t, err)
	return key.PublicKey()
}

func TestPeerLastActivityTimeIsLastHandshakeWhenPeerHasHandshaked(t *testing.T) {
	peerKey := testPeerKey(t)
	handshakeTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	connectionTime := handshakeTime.Add(-time.Hour)
	peer := wgtypes.Peer{PublicKey: peerKey, LastHandshakeTime: handshakeTime}
	allPeers := map[wgtypes.Key]PeerInfo{peerKey: {ConnectionTime: connectionTime}}

	assert.Equal(t, handshakeTime, peerLastActivityTime(peer, allPeers))
}

func TestPeerLastActivityTimeIsConnectionTimeWhenPeerHasNotHandshaked(t *testing.T) {
	peerKey := testPeerKey(t)
	connectionTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	peer := wgtypes.Peer{PublicKey: peerKey}
	allPeers := map[wgtypes.Key]PeerInfo{peerKey: {ConnectionTime: connectionTime}}

	assert.Equal(t, connectionTime, peerLastActivityTime(peer, allPeers))
}

func TestPeerLastActivityTimeIsZeroWhenPeerIsUnknownAndHasNotHandshaked(t *testing.T) {
	peer := wgtypes.Peer{PublicKey: testPeerKey(t)}

	assert.True(t, peerLastActivityTime(peer, map[wgtypes.Key]PeerInfo{}).IsZero())
}

func TestIsPeerIdleWhenLastActivityIsOlderThanTimeout(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	assert.True(t, isPeerIdle(now.Add(-PeerIdleTimeout-time.Second), now))
}

func TestIsPeerNotIdleWhenLastActivityIsWithinTimeout(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	assert.False(t, isPeerIdle(now.Add(-PeerIdleTimeout+time.Second), now))
}

func TestIsPeerIdleWhenLastActivityIsUnknown(t *testing.T) {
	assert.True(t, isPeerIdle(time.Time{}, time.Now()))
}
