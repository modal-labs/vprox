package lib

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestConnectHandlerSerializesSamePeerAllocation(t *testing.T) {
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	configureEntered := make(chan struct{}, 2)
	releaseConfigure := make(chan struct{})
	var configuring atomic.Int32
	var maxConfiguring atomic.Int32
	configure := func(wgtypes.Config) error {
		current := configuring.Add(1)
		for old := maxConfiguring.Load(); current > old && !maxConfiguring.CompareAndSwap(old, current); old = maxConfiguring.Load() {
		}
		defer configuring.Add(-1)
		configureEntered <- struct{}{}
		<-releaseConfigure
		return nil
	}
	srv := &Server{
		configureWireGuard: configure,
		Auth:               NewPasswordAuthenticator("secret"),
		WgCidr:             netip.MustParsePrefix("10.0.0.0/29"),
		Key:                peerKey,
		allPeers:           make(map[wgtypes.Key]PeerInfo),
		ipAllocator:        NewIpAllocator(netip.MustParsePrefix("10.0.0.0/29")),
	}
	srv.ipAllocator.Allocate() // reserve the server address

	body, err := json.Marshal(connectRequest{PeerPublicKey: peerKey.PublicKey().String()})
	require.NoError(t, err)
	responses := make([]*httptest.ResponseRecorder, 2)
	var requests sync.WaitGroup
	for i := range responses {
		requests.Add(1)
		go func(i int) {
			defer requests.Done()
			req := httptest.NewRequest(http.MethodPost, "/connect", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer secret")
			responses[i] = httptest.NewRecorder()
			srv.connectHandler(responses[i], req)
		}(i)
	}

	select {
	case <-configureEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("connect handler did not reach WireGuard configuration")
	}
	// Give the second handler a chance to reach WireGuard; without serialization
	// both handlers configure concurrently after reserving different addresses.
	time.Sleep(100 * time.Millisecond)
	close(releaseConfigure)
	requests.Wait()

	for _, response := range responses {
		require.Equal(t, http.StatusOK, response.Code)
	}
	require.Equal(t, 2, srv.ipAllocator.AllocatedCount(), "one server address plus one peer address")
	require.Len(t, srv.allPeers, 1)
	require.EqualValues(t, 1, maxConfiguring.Load(), "same-peer WireGuard updates must not overlap")
	var first, second connectResponse
	require.NoError(t, json.Unmarshal(responses[0].Body.Bytes(), &first))
	require.NoError(t, json.Unmarshal(responses[1].Body.Bytes(), &second))
	require.Equal(t, first.AssignedAddr, second.AssignedAddr)
	assigned, err := netip.ParsePrefix(first.AssignedAddr)
	require.NoError(t, err)
	require.Equal(t, assigned.Addr(), srv.allPeers[peerKey.PublicKey()].PeerIp)
}

func TestConnectHandlerConfigureFailurePreservesExistingPeerOwnership(t *testing.T) {
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	var failNext atomic.Bool
	configure := func(wgtypes.Config) error {
		if failNext.Swap(false) {
			return errors.New("injected configure failure")
		}
		return nil
	}
	cidr := netip.MustParsePrefix("10.0.0.0/29")
	srv := &Server{
		configureWireGuard: configure,
		Auth:               NewPasswordAuthenticator("secret"),
		WgCidr:             cidr,
		Key:                peerKey,
		allPeers:           make(map[wgtypes.Key]PeerInfo),
		ipAllocator:        NewIpAllocator(cidr),
	}
	srv.ipAllocator.Allocate() // reserve the server address

	request := func() *httptest.ResponseRecorder {
		body, marshalErr := json.Marshal(connectRequest{PeerPublicKey: peerKey.PublicKey().String()})
		require.NoError(t, marshalErr)
		req := httptest.NewRequest(http.MethodPost, "/connect", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		srv.connectHandler(response, req)
		return response
	}

	first := request()
	require.Equal(t, http.StatusOK, first.Code)
	failNext.Store(true)
	failed := request()
	require.Equal(t, http.StatusInternalServerError, failed.Code)
	require.Len(t, srv.allPeers, 1)
	require.Equal(t, 2, srv.ipAllocator.AllocatedCount())
	var original connectResponse
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &original))
	recovered := request()
	require.Equal(t, http.StatusOK, recovered.Code)
	var next connectResponse
	require.NoError(t, json.Unmarshal(recovered.Body.Bytes(), &next))
	require.Equal(t, original.AssignedAddr, next.AssignedAddr)
}
