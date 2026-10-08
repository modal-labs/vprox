package lib

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// errNoAddressesAvailable is returned when every address in the server's
// WireGuard CIDR is already assigned to a peer.
var errNoAddressesAvailable = errors.New("no more IP addresses available")

// addPeer assigns a tunnel address to the peer with the given public key and
// configures it on the server's WireGuard interface. A peer that is already
// connected keeps its existing address. Returns the peer's tunnel address, or
// errNoAddressesAvailable if the WireGuard CIDR is exhausted.
func addPeer(server *Server, peerKey wgtypes.Key) (netip.Addr, error) {
	server.mu.Lock()
	peerInfo, exists := server.allPeers[peerKey]
	server.mu.Unlock()

	var peerIp netip.Addr
	if exists {
		peerIp = peerInfo.PeerIp
	} else {
		peerIp = server.ipAllocator.Allocate()
	}

	if peerIp.IsUnspecified() {
		return netip.Addr{}, errNoAddressesAvailable
	}

	server.mu.Lock()
	server.allPeers[peerKey] = PeerInfo{
		ConnectionTime: time.Now(),
		PeerIp:         peerIp,
	}
	server.mu.Unlock()

	configureStart := time.Now()
	err := server.WgClient.ConfigureDevice(wireguardIfname(server), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         peerKey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{prefixToIPNet(netip.PrefixFrom(peerIp, 32))},
			},
		},
	})
	recordWireguardConfigureLatency("add_peer", time.Since(configureStart))
	if err != nil {
		server.mu.Lock()
		delete(server.allPeers, peerKey)
		server.mu.Unlock()
		server.ipAllocator.Free(peerIp)
		return netip.Addr{}, fmt.Errorf("failed to configure WireGuard peer: %v", err)
	}

	return peerIp, nil
}

// removePeer removes the peer with the given public key from the server's
// WireGuard interface and frees its tunnel address. Removing a peer the server
// does not know about is a no-op.
func removePeer(server *Server, peerKey wgtypes.Key) error {
	server.mu.Lock()
	peerInfo, exists := server.allPeers[peerKey]
	delete(server.allPeers, peerKey)
	server.mu.Unlock()

	if !exists {
		log.Printf("[%v] peer unexpectedly not found in allPeers - did /disconnect race with the periodic peer-GC loop?: %v", server.BindAddr, peerKey)
		return nil
	}

	log.Printf("[%v] removing peer at %v: %v", server.BindAddr, peerInfo.PeerIp, peerKey)
	configureStart := time.Now()
	err := server.WgClient.ConfigureDevice(wireguardIfname(server), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: peerKey,
				Remove:    true,
			},
		},
	})
	recordWireguardConfigureLatency("remove_peer", time.Since(configureStart))
	if err != nil {
		return fmt.Errorf("failed to remove WireGuard peer: %v", err)
	}

	if !peerInfo.PeerIp.IsUnspecified() {
		server.ipAllocator.Free(peerInfo.PeerIp)
	}

	return nil
}

// removeIdlePeers removes every peer on the server's WireGuard interface whose
// last activity is older than PeerIdleTimeout and frees their tunnel addresses.
func removeIdlePeers(server *Server) error {
	device, err := server.WgClient.Device(wireguardIfname(server))
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device: %v", err)
	}

	server.mu.Lock()
	defer server.mu.Unlock()

	now := time.Now()
	var removePeerConfigs []wgtypes.PeerConfig
	var removeIps []netip.Addr
	for _, peer := range device.Peers {
		if !isPeerIdle(peerLastActivityTime(peer, server.allPeers), now) {
			continue
		}

		if peerIp, ok := peerTunnelAddress(peer); ok {
			log.Printf("[%v] removing idle peer at %v: %v", server.BindAddr, peerIp, peer.PublicKey)
			removeIps = append(removeIps, peerIp)
		}
		removePeerConfigs = append(removePeerConfigs, wgtypes.PeerConfig{
			PublicKey: peer.PublicKey,
			Remove:    true,
		})
		delete(server.allPeers, peer.PublicKey)
	}

	if len(removePeerConfigs) == 0 {
		return nil
	}

	configureStart := time.Now()
	err = server.WgClient.ConfigureDevice(wireguardIfname(server), wgtypes.Config{Peers: removePeerConfigs})
	recordWireguardConfigureLatency("remove_idle_peers", time.Since(configureStart))
	if err != nil {
		return err
	}
	for _, peerIp := range removeIps {
		server.ipAllocator.Free(peerIp)
	}

	return nil
}

// peerLastActivityTime returns the time of the peer's last WireGuard handshake,
// or the time it connected if it has never completed a handshake. Returns the
// zero time for a peer that has no record in allPeers and no handshake.
func peerLastActivityTime(peer wgtypes.Peer, allPeers map[wgtypes.Key]PeerInfo) time.Time {
	if !peer.LastHandshakeTime.IsZero() {
		return peer.LastHandshakeTime
	}
	peerInfo, exists := allPeers[peer.PublicKey]
	if !exists {
		return time.Time{}
	}
	return peerInfo.ConnectionTime
}

// isPeerIdle reports whether a peer whose last activity was at lastActivityTime
// has been idle for longer than PeerIdleTimeout as of now.
func isPeerIdle(lastActivityTime time.Time, now time.Time) bool {
	return now.Sub(lastActivityTime) > PeerIdleTimeout
}
