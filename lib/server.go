package lib

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FwmarkBase is the base value for firewall marks used by vprox.
const FwmarkBase = 0x54437D00

// UDP listen port base value for WireGuard connections.
const WireguardListenPortBase = 50227

// WireGuard interface MTU. WireGuard adds ~60 bytes overhead (40 for IPv4/UDP
// + 16 for WG header + padding). Setting MTU to 1420 prevents fragmentation
// on standard 1500 MTU networks.
const WireguardMTU = 1420

// WireGuard interface transmit queue length. Higher values reduce packet drops
// during traffic bursts.
const WireguardTxQLen = 1000

// GSO/GRO max size for improved throughput on Linux 5.19+. Allows the kernel
// to batch packets into large 64 KB super-packets before encryption/decryption.
const WireguardGSOMaxSize = 65536

// TCP MSS for traffic through the WireGuard tunnel, calculated as
// MTU (1420) - IP header (20) - TCP header (20) = 1380.
const WireguardMSS = 1380

// Number of TX/RX queues for parallel packet processing on multi-core systems.
const WireguardNumQueues = 4

// MaxTunnelsPerServer is the maximum number of parallel WireGuard tunnels
// allowed per server (per bind IP). Each tunnel uses a different UDP port
// so that the NIC hashes them to different hardware RX queues.
const MaxTunnelsPerServer = 16

// PortsPerIndex is the number of UDP ports reserved per server index.
// This must be >= MaxTunnelsPerServer. With this spacing, server index 0
// uses ports 50227..50242, index 1 uses 50243..50258, etc.
const PortsPerIndex = MaxTunnelsPerServer

// A new peer must connect with a handshake within this time.
const FirstHandshakeTimeout = 10 * time.Second

// If no handshakes are received in this time, the peer is considered idle and
// removed from the server's WireGuard interface list.
//
// Note that this must be at least 2-3 minutes, since WireGuard sends handshakes
// interleaved with a data message only when 2-3 minutes have passed since the
// last successful handshake. This is regardless of the persistent-keepalive
// setting.
const PeerIdleTimeout = 5 * time.Minute

type PeerInfo struct {
	ConnectionTime time.Time
	PeerIp         netip.Addr
}

// Server handles state for one WireGuard network.
//
// The `vprox server` command should create one Server instance for each
// private IP that the server should bind to.
type Server struct {
	// Key is the private key of the server.
	Key wgtypes.Key

	// BindAddr is the private IPv4 address that the server binds to.
	BindAddr netip.Addr

	// BindIface is the interface that the address is bound to, and it's also
	// the interface for outbound VPN traffic after masquerade.
	//
	// Currently only setting this to the default interface is supported.
	BindIface netlink.Link

	// Password is needed to authenticate connection requests.
	Password string

	// Index is a unique server index for firewall marks and other uses. It starts at 0.
	Index uint16

	// NumTunnels is the number of parallel WireGuard tunnels to create for
	// this server. Each tunnel listens on a different UDP port so that the NIC
	// hashes them to different hardware RX queues, increasing throughput beyond
	// the single-flow limit. Defaults to 1 for backwards compatibility.
	NumTunnels int

	// Ipt is the iptables client for managing firewall rules.
	Ipt *iptables.IPTables

	// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// WgCidr is the CIDR block of IPs that the server assigns to WireGuard peers.
	WgCidr netip.Prefix

	// Ctx is the shutdown context for the server.
	Ctx context.Context

	ipAllocator *IpAllocator

	mu       sync.Mutex // Protects the fields below.
	allPeers map[wgtypes.Key]PeerInfo

	// relinquished indicates this server should not clean up WireGuard state on exit.
	// Set via the /relinquish endpoint for non-disruptive upgrades.
	relinquished bool

	// takeover indicates this server should take over existing WireGuard state
	// instead of creating a fresh interface. Used for non-disruptive upgrades.
	takeover bool
}

// numTunnels returns the effective tunnel count, defaulting to 1.
func (srv *Server) numTunnels() int {
	if srv.NumTunnels <= 0 {
		return 1
	}
	if srv.NumTunnels > MaxTunnelsPerServer {
		return MaxTunnelsPerServer
	}
	return srv.NumTunnels
}

// InitState initializes the private server state.
func (srv *Server) InitState() error {
	if srv.BindIface == nil {
		iface, err := getDefaultInterface()
		if err != nil {
			return err
		}
		srv.BindIface = iface
	}

	srv.ipAllocator = NewIpAllocator(srv.WgCidr)
	// Reserve the first IP address for the server itself.
	reservedIp := srv.ipAllocator.Allocate()
	if reservedIp != srv.WgCidr.Addr() {
		return fmt.Errorf("reserved IP address mistamches CIDR: %v != %v", reservedIp, srv.WgCidr.Addr())
	}
	srv.allPeers = make(map[wgtypes.Key]PeerInfo)

	// In takeover mode, initialize state from existing WireGuard peers if device exists
	if srv.takeover {
		if _, err := srv.WgClient.Device(srv.Ifname()); err == nil {
			log.Printf("[%v] takeover: inheriting state from existing WireGuard device", srv.BindAddr)
			if err := srv.initStateFromWireguard(); err != nil {
				return fmt.Errorf("failed to initialize state from WireGuard: %v", err)
			}
		} else {
			log.Printf("[%v] takeover: WireGuard device not found, starting fresh", srv.BindAddr)
		}
	}

	return nil
}

// initStateFromWireguard populates allPeers and ipAllocator from existing WireGuard state.
// Used in takeover mode to inherit state from a previous server instance.
func (srv *Server) initStateFromWireguard() error {
	device, err := srv.WgClient.Device(srv.Ifname())
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	for _, peer := range device.Peers {
		if len(peer.AllowedIPs) == 0 {
			continue
		}

		// Extract the peer's IP from AllowedIPs
		ipv4 := peer.AllowedIPs[0].IP.To4()
		if ipv4 == nil {
			continue
		}
		peerIp := netip.AddrFrom4([4]byte(ipv4))

		// Mark the IP as allocated
		srv.ipAllocator.MarkAllocated(peerIp)

		// Add to allPeers with current time as connection time
		srv.allPeers[peer.PublicKey] = PeerInfo{
			ConnectionTime: time.Now(),
			PeerIp:         peerIp,
		}

		log.Printf("[%v] takeover: inherited peer %v at %v", srv.BindAddr, peer.PublicKey, peerIp)
	}

	log.Printf("[%v] takeover: inherited %d peers from WireGuard state", srv.BindAddr, len(srv.allPeers))
	return nil
}

func (srv *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fmt.Fprintf(w, "vprox ok. received %v -> %v:443\n", r.RemoteAddr, srv.BindAddr)
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type connectRequest struct {
	PeerPublicKey string
}

// TunnelInfo describes a single WireGuard tunnel endpoint within a multi-tunnel
// connection. Clients that support multi-tunnel will use these to set up
// parallel WireGuard interfaces.
type TunnelInfo struct {
	ListenPort int    `json:"ListenPort"`
	Ifname     string `json:"Ifname"`
}

type connectResponse struct {
	AssignedAddr     string
	ServerPublicKey  string
	ServerListenPort int

	// Tunnels lists all available tunnel endpoints for this server. Clients
	// that support multi-tunnel create one WireGuard interface per entry.
	// Clients that don't understand this field will fall back to the single
	// ServerListenPort above (backwards compatible).
	Tunnels []TunnelInfo `json:"Tunnels,omitempty"`
}

// Handle a new connection.
func (srv *Server) connectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+srv.Password {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	req := &connectRequest{}
	if err = json.Unmarshal(buf, req); err != nil {
		http.Error(w, "failed to parse request body", http.StatusBadRequest)
		return
	}

	peerKey, err := wgtypes.ParseKey(req.PeerPublicKey)
	if err != nil {
		http.Error(w, "invalid peer public key", http.StatusBadRequest)
		return
	}

	srv.mu.Lock()
	peerInfo, exists := srv.allPeers[peerKey]
	srv.mu.Unlock()

	// If the new connection already exists as a peer, just return that IP.
	var peerIp netip.Addr
	if exists {
		peerIp = peerInfo.PeerIp
	} else {
		// Add a WireGuard peer for the new connection.
		peerIp = srv.ipAllocator.Allocate()
	}

	if peerIp.IsUnspecified() {
		log.Printf("no more ip addresses available in %v", srv.WgCidr)
		http.Error(w, "no more IP addresses available", http.StatusServiceUnavailable)
		return
	}

	srv.mu.Lock()
	srv.allPeers[peerKey] = PeerInfo{
		ConnectionTime: time.Now(),
		PeerIp:         peerIp,
	}
	srv.mu.Unlock()

	clientIp := strings.Split(r.RemoteAddr, ":")[0] // for logging
	log.Printf("[%v] new peer %v at %v: %v", srv.BindAddr, clientIp, peerIp, peerKey)

	// Add the peer to ALL tunnel interfaces so that traffic arriving on any
	// tunnel is accepted, and the server can send traffic back on any tunnel.
	nt := srv.numTunnels()
	for t := 0; t < nt; t++ {
		ifname := srv.TunnelIfname(t)
		err = srv.WgClient.ConfigureDevice(ifname, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey:         peerKey,
					ReplaceAllowedIPs: true,
					AllowedIPs:        []net.IPNet{prefixToIPNet(netip.PrefixFrom(peerIp, 32))},
				},
			},
		})
		if err != nil {
			// Roll back: remove from any interfaces we already configured.
			for rb := 0; rb < t; rb++ {
				rbIfname := srv.TunnelIfname(rb)
				_ = srv.WgClient.ConfigureDevice(rbIfname, wgtypes.Config{
					Peers: []wgtypes.PeerConfig{{PublicKey: peerKey, Remove: true}},
				})
			}

			srv.mu.Lock()
			delete(srv.allPeers, peerKey)
			srv.mu.Unlock()
			srv.ipAllocator.Free(peerIp)

			log.Printf("failed to configure WireGuard peer on %s: %v", ifname, err)
			http.Error(w, "failed to configure WireGuard peer", http.StatusInternalServerError)
			return
		}
	}

	// Build the Tunnels list for multi-tunnel clients.
	tunnels := make([]TunnelInfo, nt)
	for t := 0; t < nt; t++ {
		tunnels[t] = TunnelInfo{
			ListenPort: srv.tunnelListenPort(t),
			Ifname:     srv.TunnelIfname(t),
		}
	}

	// Return the assigned IP address and the server's public key.
	resp := &connectResponse{
		AssignedAddr:     fmt.Sprintf("%v/%d", peerIp, srv.WgCidr.Bits()),
		ServerPublicKey:  srv.Key.PublicKey().String(),
		ServerListenPort: srv.tunnelListenPort(0), // primary tunnel for old clients
		Tunnels:          tunnels,
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)
}

type disconnectRequest struct {
	PeerPublicKey string
}

type disconnectResponse struct {
	Status string
}

// Handle a disconnect request from a client.
func (srv *Server) disconnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+srv.Password {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	req := &disconnectRequest{}
	if err = json.Unmarshal(buf, req); err != nil {
		http.Error(w, "failed to parse request body", http.StatusBadRequest)
		return
	}

	peerKey, err := wgtypes.ParseKey(req.PeerPublicKey)
	if err != nil {
		http.Error(w, "invalid peer public key", http.StatusBadRequest)
		return
	}

	// Clean up the peer (idempotent operation).
	clientIp := strings.Split(r.RemoteAddr, ":")[0] // for logging
	log.Printf("[%v] disconnect request from %v: %v", srv.BindAddr, clientIp, peerKey)

	err = srv.cleanupPeer(peerKey)
	if err != nil {
		log.Printf("failed to cleanup peer %v: %v", peerKey, err)
		http.Error(w, "failed to cleanup peer", http.StatusInternalServerError)
		return
	}

	// Return success response.
	resp := &disconnectResponse{
		Status: "success",
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)
}

type relinquishResponse struct {
	Status string
}

// Handle a relinquish request - marks the server to preserve WireGuard state on exit.
// Used for non-disruptive software upgrades. This is meant to be called by an "external"
// software update process, not by the vprox client.
func (srv *Server) relinquishHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+srv.Password {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	srv.mu.Lock()
	srv.relinquished = true
	srv.mu.Unlock()

	log.Printf("[%v] server relinquished - WireGuard state will be preserved on exit", srv.BindAddr)

	resp := &relinquishResponse{
		Status: "relinquished",
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)
}

type versionResponse struct {
	GitCommit string `json:"git_commit"`
	GitTag    string `json:"git_tag"`
}

// Handle a version request - returns the server version information.
func (srv *Server) versionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+srv.Password {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	resp := &versionResponse{
		GitCommit: GitCommit,
		GitTag:    GitTag,
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)
}

// Ifname returns the primary WireGuard interface name (tunnel 0). This is used
// for backwards-compatible code paths like takeover and idle peer removal.
func (srv *Server) Ifname() string {
	return srv.TunnelIfname(0)
}

// TunnelIfname returns the WireGuard interface name for the t-th tunnel.
// When NumTunnels == 1, this returns "vprox0" (same as before).
// When NumTunnels > 1, tunnel 0 is "vprox0", tunnel 1 is "vprox0t1", etc.
func (srv *Server) TunnelIfname(t int) string {
	base := fmt.Sprintf("vprox%d", srv.Index)
	if t == 0 {
		return base
	}
	return fmt.Sprintf("%st%d", base, t)
}

// tunnelListenPort returns the UDP listen port for the t-th tunnel.
func (srv *Server) tunnelListenPort(t int) int {
	return WireguardListenPortBase + int(srv.Index)*PortsPerIndex + t
}

// StartWireguard creates and configures all tunnel WireGuard interfaces.
func (srv *Server) StartWireguard() error {
	nt := srv.numTunnels()
	for t := 0; t < nt; t++ {
		if err := srv.startWireguardTunnel(t); err != nil {
			// Clean up any tunnels we already created.
			for rb := 0; rb < t; rb++ {
				srv.cleanupWireguardTunnel(rb)
			}
			return err
		}
	}
	if nt > 1 {
		log.Printf("[%v] started %d WireGuard tunnels (ports %d..%d)",
			srv.BindAddr, nt, srv.tunnelListenPort(0), srv.tunnelListenPort(nt-1))

		// Set up equal-cost routes across all tunnel interfaces so the kernel
		// distributes reply traffic across them (same approach as client side).
		if err := srv.setupMultipathRouting(nt); err != nil {
			log.Printf("[%v] warning: failed to set up multipath routing: %v", srv.BindAddr, err)
		} else {
			log.Printf("[%v] multipath routing configured across %d tunnels", srv.BindAddr, nt)
		}
	}
	return nil
}

// startWireguardTunnel creates and configures a single WireGuard tunnel interface.
func (srv *Server) startWireguardTunnel(t int) error {
	ifname := srv.TunnelIfname(t)
	link := &linkWireguard{LinkAttrs: netlink.LinkAttrs{
		Name:        ifname,
		MTU:         WireguardMTU,
		TxQLen:      WireguardTxQLen,
		NumTxQueues: WireguardNumQueues,
		NumRxQueues: WireguardNumQueues,
		GSOMaxSize:  WireguardGSOMaxSize,
		GROMaxSize:  WireguardGSOMaxSize,
	}}

	createdFreshInterface := false

	if srv.takeover {
		_, err := netlink.LinkByName(ifname)
		if err == nil {
			log.Printf("[%v] takeover mode: using existing WireGuard interface %s", srv.BindAddr, ifname)
		} else {
			log.Printf("[%v] takeover mode: interface %s not found, creating fresh", srv.BindAddr, ifname)
			if err := srv.createFreshInterface(link, t); err != nil {
				return err
			}
			createdFreshInterface = true
		}
	} else {
		_ = netlink.LinkDel(link) // remove if it already exists
		if err := srv.createFreshInterface(link, t); err != nil {
			return err
		}
		createdFreshInterface = true
	}

	listenPort := srv.tunnelListenPort(t)
	err := srv.WgClient.ConfigureDevice(ifname, wgtypes.Config{
		PrivateKey: &srv.Key,
		ListenPort: &listenPort,
	})
	if err != nil {
		if createdFreshInterface {
			netlink.LinkDel(link)
		}
		return err
	}

	return nil
}

// createFreshInterface creates and configures a new WireGuard interface.
// Every tunnel interface gets the same subnet IP so the kernel can route
// reply packets back through any of them.
func (srv *Server) createFreshInterface(link *linkWireguard, tunnelIndex int) error {
	err := netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("failed to create WireGuard device %s: %v", link.Name, err)
	}

	// Assign the subnet IP to every tunnel interface.
	ipnet := prefixToIPNet(srv.WgCidr)
	err = netlink.AddrReplace(link, &netlink.Addr{IPNet: &ipnet})
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("failed to add address to WireGuard device %s: %v", link.Name, err)
	}

	// Set MTU explicitly after link creation (some kernels ignore it in LinkAttrs)
	err = netlink.LinkSetMTU(link, WireguardMTU)
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("failed to set MTU on WireGuard device %s: %v", link.Name, err)
	}

	// Set TxQLen for improved burst handling
	err = netlink.LinkSetTxQLen(link, WireguardTxQLen)
	if err != nil {
		log.Printf("warning: failed to set TxQLen on WireGuard device %s: %v", link.Name, err)
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("failed to bring up WireGuard device %s: %v", link.Name, err)
	}

	return nil
}

// setupMultipathRouting adds equal-cost device-scoped routes for the WireGuard
// subnet across all tunnel interfaces so the kernel round-robins reply traffic.
func (srv *Server) setupMultipathRouting(nt int) error {
	subnetIPNet := prefixToIPNet(srv.WgCidr.Masked())

	// Remove any existing routes for this subnet so we start clean.
	existingRoutes, _ := netlink.RouteList(nil, netlink.FAMILY_V4)
	for i := range existingRoutes {
		r := &existingRoutes[i]
		if r.Dst != nil && r.Dst.String() == subnetIPNet.String() {
			_ = netlink.RouteDel(r)
		}
	}

	// Append one route per tunnel interface. Equal-cost routes to the same
	// destination cause the kernel to distribute flows across them.
	for t := 0; t < nt; t++ {
		ifname := srv.TunnelIfname(t)
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			return fmt.Errorf("failed to find interface %s: %v", ifname, err)
		}
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &subnetIPNet,
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteAppend(route); err != nil {
			return fmt.Errorf("failed to append route on %s: %v", ifname, err)
		}
	}
	return nil
}

// CleanupWireguard removes all tunnel WireGuard interfaces.
func (srv *Server) CleanupWireguard() {
	srv.mu.Lock()
	relinquished := srv.relinquished
	srv.mu.Unlock()

	if relinquished {
		log.Printf("[%v] skipping WireGuard cleanup (relinquished)", srv.BindAddr)
		return
	}

	log.Printf("[%v] cleaning up WireGuard state", srv.BindAddr)
	nt := srv.numTunnels()
	for t := 0; t < nt; t++ {
		srv.cleanupWireguardTunnel(t)
	}
}

// cleanupWireguardTunnel removes a single WireGuard tunnel interface.
func (srv *Server) cleanupWireguardTunnel(t int) {
	ifname := srv.TunnelIfname(t)
	_ = netlink.LinkDel(&linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}})
}

// iptablesInputFwmarkRule adds or removes the mangle PREROUTING rule for traffic
// from WireGuard. One rule per tunnel interface, all using the same fwmark.
func (srv *Server) iptablesInputFwmarkRule(enabled bool) error {
	firewallMark := FwmarkBase + int(srv.Index)
	nt := srv.numTunnels()
	for t := 0; t < nt; t++ {
		ifname := srv.TunnelIfname(t)
		rule := []string{
			"-i", ifname,
			"-j", "MARK", "--set-mark", strconv.Itoa(firewallMark),
			"-m", "comment", "--comment", fmt.Sprintf("vprox fwmark rule for %s", ifname),
		}
		if enabled {
			if err := srv.Ipt.AppendUnique("mangle", "PREROUTING", rule...); err != nil {
				return err
			}
		} else {
			srv.Ipt.Delete("mangle", "PREROUTING", rule...)
		}
	}
	return nil
}

// iptablesSnatRule adds or removes the nat POSTROUTING rule for outbound traffic.
// This is shared across all tunnels via fwmark (only one rule needed).
func (srv *Server) iptablesSnatRule(enabled bool) error {
	firewallMark := FwmarkBase + int(srv.Index)
	rule := []string{
		"-m", "mark", "--mark", strconv.Itoa(firewallMark),
		"-j", "SNAT", "--to-source", srv.BindAddr.String(),
		"-m", "comment", "--comment", fmt.Sprintf("vprox snat rule for index %d", srv.Index),
	}
	if enabled {
		return srv.Ipt.AppendUnique("nat", "POSTROUTING", rule...)
	} else {
		return srv.Ipt.Delete("nat", "POSTROUTING", rule...)
	}
}

// iptablesNotrackRule adds or removes NOTRACK rules in the raw table to bypass
// connection tracking for WireGuard UDP traffic on all tunnel ports.
func (srv *Server) iptablesNotrackRule(enabled bool) error {
	nt := srv.numTunnels()
	for t := 0; t < nt; t++ {
		listenPort := strconv.Itoa(srv.tunnelListenPort(t))
		ifname := srv.TunnelIfname(t)
		inRule := []string{
			"-p", "udp",
			"--dport", listenPort,
			"-j", "NOTRACK",
			"-m", "comment", "--comment", fmt.Sprintf("vprox notrack in for %s", ifname),
		}
		outRule := []string{
			"-p", "udp",
			"--sport", listenPort,
			"-j", "NOTRACK",
			"-m", "comment", "--comment", fmt.Sprintf("vprox notrack out for %s", ifname),
		}
		if enabled {
			if err := srv.Ipt.AppendUnique("raw", "PREROUTING", inRule...); err != nil {
				return fmt.Errorf("failed to add NOTRACK PREROUTING rule for %s: %v", ifname, err)
			}
			if err := srv.Ipt.AppendUnique("raw", "OUTPUT", outRule...); err != nil {
				srv.Ipt.Delete("raw", "PREROUTING", inRule...)
				return fmt.Errorf("failed to add NOTRACK OUTPUT rule for %s: %v", ifname, err)
			}
		} else {
			srv.Ipt.Delete("raw", "PREROUTING", inRule...)
			srv.Ipt.Delete("raw", "OUTPUT", outRule...)
		}
	}
	return nil
}

// iptablesMssRule adds or removes FORWARD chain rules for TCP MSS clamping in
// both directions on all tunnel interfaces.
func (srv *Server) iptablesMssRule(enabled bool) error {
	nt := srv.numTunnels()
	for t := 0; t < nt; t++ {
		ifname := srv.TunnelIfname(t)
		outRule := []string{
			"-o", ifname,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", strconv.Itoa(WireguardMSS),
			"-m", "comment", "--comment", fmt.Sprintf("vprox mss out rule for %s", ifname),
		}
		inRule := []string{
			"-i", ifname,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", strconv.Itoa(WireguardMSS),
			"-m", "comment", "--comment", fmt.Sprintf("vprox mss in rule for %s", ifname),
		}

		if enabled {
			if err := srv.Ipt.AppendUnique("mangle", "FORWARD", outRule...); err != nil {
				return err
			}
			if err := srv.Ipt.AppendUnique("mangle", "FORWARD", inRule...); err != nil {
				srv.Ipt.Delete("mangle", "FORWARD", outRule...)
				return err
			}
		} else {
			srv.Ipt.Delete("mangle", "FORWARD", outRule...)
			srv.Ipt.Delete("mangle", "FORWARD", inRule...)
		}
	}
	return nil
}

func (srv *Server) StartIptables() error {
	err := srv.iptablesInputFwmarkRule(true)
	if err != nil {
		return fmt.Errorf("failed to add fwmark rule: %v", err)
	}

	err = srv.iptablesSnatRule(true)
	if err != nil {
		srv.iptablesInputFwmarkRule(false)
		return fmt.Errorf("failed to add SNAT rule: %v", err)
	}

	err = srv.iptablesMssRule(true)
	if err != nil {
		srv.iptablesSnatRule(false)
		srv.iptablesInputFwmarkRule(false)
		return fmt.Errorf("failed to add MSS rule: %v", err)
	}

	// NOTRACK is best-effort — don't fail startup if the raw table isn't available.
	if err = srv.iptablesNotrackRule(true); err != nil {
		log.Printf("warning: failed to add NOTRACK rules (non-fatal): %v", err)
	}

	return nil
}

func (srv *Server) CleanupIptables() {
	if err := srv.iptablesInputFwmarkRule(false); err != nil {
		log.Printf("warning: error cleaning up iptables fwmark rule: %v\n", err)
	}
	if err := srv.iptablesSnatRule(false); err != nil {
		log.Printf("warning: error cleaning up iptables SNAT rule: %v\n", err)
	}
	if err := srv.iptablesMssRule(false); err != nil {
		log.Printf("warning: error cleaning up iptables MSS rule: %v\n", err)
	}
	srv.iptablesNotrackRule(false)
}

func (srv *Server) removeIdlePeersLoop() {
	for {
		// Wait for up to 5 seconds, or stop when the context is done.
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		if err := srv.removeIdlePeers(); err != nil {
			log.Printf("error removing idle peers: %v", err)
		}
	}
}

// cleanupPeer removes a peer from ALL WireGuard tunnel interfaces, reclaims its
// subnet IP, and removes it from the allPeers map.
func (srv *Server) cleanupPeer(publicKey wgtypes.Key) error {
	// Look up the peer in allPeers map to get its IP address.
	srv.mu.Lock()
	peerInfo, exists := srv.allPeers[publicKey]
	if !exists {
		srv.mu.Unlock()
		log.Printf("[%v] peer unexpectedly not found in allPeers - did /disconnect race with the periodic peer-GC loop?: %v", srv.BindAddr, publicKey)
		return nil
	}

	// Extract peer info and remove from allPeers.
	peerIp := peerInfo.PeerIp
	delete(srv.allPeers, publicKey)
	srv.mu.Unlock()

	// Remove the peer from ALL tunnel interfaces.
	nt := srv.numTunnels()
	log.Printf("[%v] removing peer at %v from %d tunnel(s): %v", srv.BindAddr, peerIp, nt, publicKey)
	var firstErr error
	for t := 0; t < nt; t++ {
		ifname := srv.TunnelIfname(t)
		err := srv.WgClient.ConfigureDevice(ifname, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: publicKey,
					Remove:    true,
				},
			},
		})
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to remove WireGuard peer from %s: %v", ifname, err)
		}
	}

	// Free the IP address.
	if !peerIp.IsUnspecified() {
		srv.ipAllocator.Free(peerIp)
	}

	return firstErr
}

func (srv *Server) removeIdlePeers() error {
	// Check idle status using the primary tunnel interface (tunnel 0).
	// All tunnels share the same peers, so we only need to inspect one.
	device, err := srv.WgClient.Device(srv.Ifname())
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device: %v", err)
	}

	// Hold the lock for access to allPeers.
	srv.mu.Lock()
	defer srv.mu.Unlock()

	var removePeerKeys []wgtypes.Key
	var removeIps []netip.Addr
	for _, peer := range device.Peers {
		var idle bool
		if peer.LastHandshakeTime.IsZero() {
			peerInfo, exists := srv.allPeers[peer.PublicKey]
			if exists {
				idle = time.Since(peerInfo.ConnectionTime) > PeerIdleTimeout
			} else {
				idle = true
			}
		} else {
			idle = time.Since(peer.LastHandshakeTime) > PeerIdleTimeout
		}

		if idle {
			if len(peer.AllowedIPs) > 0 {
				ipv4 := peer.AllowedIPs[0].IP.To4()
				if ipv4 != nil {
					log.Printf("[%v] removing idle peer at %v: %v",
						srv.BindAddr, ipv4, peer.PublicKey)
					removeIps = append(removeIps, netip.AddrFrom4([4]byte(ipv4)))
				}
			}
			removePeerKeys = append(removePeerKeys, peer.PublicKey)
			delete(srv.allPeers, peer.PublicKey)
		}
	}

	if len(removePeerKeys) > 0 {
		// Build the peer removal config.
		removePeers := make([]wgtypes.PeerConfig, len(removePeerKeys))
		for i, pk := range removePeerKeys {
			removePeers[i] = wgtypes.PeerConfig{PublicKey: pk, Remove: true}
		}

		// Remove from ALL tunnel interfaces.
		nt := srv.numTunnels()
		for t := 0; t < nt; t++ {
			ifname := srv.TunnelIfname(t)
			err := srv.WgClient.ConfigureDevice(ifname, wgtypes.Config{Peers: removePeers})
			if err != nil {
				log.Printf("warning: failed to remove idle peers from %s: %v", ifname, err)
			}
		}

		for _, ip := range removeIps {
			srv.ipAllocator.Free(ip)
		}
	}

	return nil
}

func (srv *Server) addBindAddrLoop() {
	for {
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(45 * time.Second):
		}
		_ = srv.addBindAddr()
	}
}

func (srv *Server) addBindAddr() error {
	// Add the bind address to the host's network interface.
	ipnet := prefixToIPNet(netip.PrefixFrom(srv.BindAddr, 32))
	return netlink.AddrReplace(srv.BindIface, &netlink.Addr{
		IPNet:       &ipnet,
		ValidLft:    60, // expiry time in seconds
		PreferedLft: 60, // expiry time in seconds
	})
}

func (srv *Server) ListenForHttps() error {
	if !srv.BindAddr.Is4() {
		return fmt.Errorf("invalid IPv4 bind address: %v", srv.BindAddr)
	}

	go srv.removeIdlePeersLoop()

	// Some bind addresses may not have been added to the network interface. If
	// that is the case, we need to add it (transiently).
	_ = srv.addBindAddr()
	go srv.addBindAddrLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.indexHandler)
	mux.HandleFunc("/connect", srv.connectHandler)
	mux.HandleFunc("/disconnect", srv.disconnectHandler)
	mux.HandleFunc("/relinquish", srv.relinquishHandler)
	mux.HandleFunc("/version", srv.versionHandler)

	cert, err := loadServerTls()
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%v:443", srv.BindAddr))
	if err != nil {
		return fmt.Errorf("failed to listen on :443: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("server listening on %v:443\n", srv.BindAddr)
		err = httpServer.ServeTLS(listener, "", "")
		if err != http.ErrServerClosed {
			errCh <- fmt.Errorf("https server failed to serve %v: %v", srv.BindAddr, err)
		} else {
			errCh <- nil
		}
	}()

	select {
	case <-srv.Ctx.Done():
		log.Printf("server no longer listening on %v:443\n", srv.BindAddr)
		return httpServer.Shutdown(srv.Ctx)
	case err = <-errCh:
		return err
	}
}

//go:embed certs/cert.pem certs/key.pem
var defaultCerts embed.FS

// loadServerTls loads the server's TLS certificate for control connections.
func loadServerTls() (tls.Certificate, error) {
	certData, _ := defaultCerts.ReadFile("certs/cert.pem")
	keyData, _ := defaultCerts.ReadFile("certs/key.pem")

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load server certificate: %v", err)
	}
	return cert, nil
}
