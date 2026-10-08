package lib

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FwmarkBase is the base value for firewall marks used by vprox.
const FwmarkBase = 0x54437D00

// WireguardListenPortBase is the base UDP listen port for WireGuard connections.
const WireguardListenPortBase = 50227

// PeerIdleTimeout is how long a peer may go without a handshake before it is
// removed from the server's WireGuard interface.
//
// This must be at least 2-3 minutes, since WireGuard sends handshakes
// interleaved with a data message only when 2-3 minutes have passed since the
// last successful handshake, regardless of the persistent-keepalive setting.
const PeerIdleTimeout = 5 * time.Minute

// bindAddrLifetime is how long the bind address stays valid on the host
// interface after each refresh.
const bindAddrLifetime = 60 * time.Second

// bindAddrRefreshInterval is how often the bind address is re-added to the
// host interface.
const bindAddrRefreshInterval = 45 * time.Second

// idlePeerRemovalInterval is how often idle peers are checked for and removed.
const idlePeerRemovalInterval = 5 * time.Second

// PeerInfo is the server's record of one connected WireGuard peer.
type PeerInfo struct {
	ConnectionTime time.Time
	PeerIp         netip.Addr
}

// Server is the state for one WireGuard network bound to one private IP.
type Server struct {
	// Key is the private key of the server.
	Key wgtypes.Key

	// BindAddr is the private IPv4 address that the server binds to.
	BindAddr netip.Addr

	// BindIface is the interface that the bind address lives on and the
	// outbound interface for VPN traffic after SNAT.
	BindIface netlink.Link

	// Auth is the authenticator used to verify incoming requests.
	Auth *Authenticator

	// Index is a unique server index, starting at 0, that selects the server's
	// interface name, listen port, and firewall mark.
	Index uint16

	// Ipt is the iptables client for managing firewall rules.
	Ipt *iptables.IPTables

	// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// WgCidr is the CIDR block of IPs that the server assigns to WireGuard peers.
	// Its first address belongs to the server itself.
	WgCidr netip.Prefix

	// Ctx is the shutdown context for the server.
	Ctx context.Context

	ipAllocator *IpAllocator

	// mu protects allPeers and relinquished.
	mu       sync.Mutex
	allPeers map[wgtypes.Key]PeerInfo

	// relinquished is whether the server should leave its WireGuard state in
	// place on exit for a replacement server instance to take over.
	relinquished bool
}

// newServer returns a Server bound to bindAddr on the host's default interface,
// with the first address of wgCidr reserved for the server itself.
func newServer(
	ctx context.Context,
	key wgtypes.Key,
	auth *Authenticator,
	ipt *iptables.IPTables,
	wgClient *wgctrl.Client,
	bindAddr netip.Addr,
	index uint16,
	wgCidr netip.Prefix,
) (*Server, error) {
	bindIface, err := getDefaultInterface()
	if err != nil {
		return nil, err
	}

	ipAllocator := NewIpAllocator(wgCidr)
	reservedIp := ipAllocator.Allocate()
	if reservedIp != wgCidr.Addr() {
		return nil, fmt.Errorf("reserved IP address mismatches CIDR: %v != %v", reservedIp, wgCidr.Addr())
	}

	return &Server{
		Key:         key,
		BindAddr:    bindAddr,
		BindIface:   bindIface,
		Auth:        auth,
		Index:       index,
		Ipt:         ipt,
		WgClient:    wgClient,
		WgCidr:      wgCidr,
		Ctx:         ctx,
		ipAllocator: ipAllocator,
		allPeers:    make(map[wgtypes.Key]PeerInfo),
	}, nil
}

// inheritPeersFromWireguardInterface records every peer on the server's
// existing WireGuard interface as connected now and marks its address as
// allocated.
func inheritPeersFromWireguardInterface(server *Server) error {
	device, err := server.WgClient.Device(wireguardIfname(server))
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device: %v", err)
	}

	server.mu.Lock()
	defer server.mu.Unlock()

	for _, peer := range device.Peers {
		peerIp, ok := peerTunnelAddress(peer)
		if !ok {
			continue
		}

		server.ipAllocator.MarkAllocated(peerIp)
		server.allPeers[peer.PublicKey] = PeerInfo{
			ConnectionTime: time.Now(),
			PeerIp:         peerIp,
		}
		log.Printf("[%v] takeover: inherited peer %v at %v", server.BindAddr, peer.PublicKey, peerIp)
	}

	log.Printf("[%v] takeover: inherited %d peers from WireGuard state", server.BindAddr, len(server.allPeers))
	return nil
}

// peerTunnelAddress returns the IPv4 tunnel address of a WireGuard peer, taken
// from its first allowed IP. Returns false if the peer has no IPv4 allowed IP.
func peerTunnelAddress(peer wgtypes.Peer) (netip.Addr, bool) {
	if len(peer.AllowedIPs) == 0 {
		return netip.Addr{}, false
	}
	ipv4 := peer.AllowedIPs[0].IP.To4()
	if ipv4 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(ipv4)), true
}

// runIdlePeerRemovalLoop removes idle peers and publishes peer gauges every
// idlePeerRemovalInterval until the server's context is done.
func runIdlePeerRemovalLoop(server *Server) {
	for {
		select {
		case <-server.Ctx.Done():
			return
		case <-time.After(idlePeerRemovalInterval):
		}

		server.mu.Lock()
		activePeerCount := len(server.allPeers)
		server.mu.Unlock()
		setActivePeersGauge(activePeerCount)
		setAllocatedIpsGauge(server.ipAllocator.AllocatedCount())

		if err := removeIdlePeers(server); err != nil {
			log.Printf("error removing idle peers: %v", err)
		}
	}
}

// runBindAddrRefreshLoop re-adds the bind address to the host interface every
// bindAddrRefreshInterval until the server's context is done.
func runBindAddrRefreshLoop(server *Server) {
	for {
		select {
		case <-server.Ctx.Done():
			return
		case <-time.After(bindAddrRefreshInterval):
		}
		_ = addBindAddr(server)
	}
}

// addBindAddr adds the bind address to the host interface as a /32 that expires
// after bindAddrLifetime unless refreshed.
func addBindAddr(server *Server) error {
	ipnet := prefixToIPNet(netip.PrefixFrom(server.BindAddr, 32))
	lifetimeSeconds := int(bindAddrLifetime.Seconds())
	return netlink.AddrReplace(server.BindIface, &netlink.Addr{
		IPNet:       &ipnet,
		ValidLft:    lifetimeSeconds,
		PreferedLft: lifetimeSeconds,
	})
}
