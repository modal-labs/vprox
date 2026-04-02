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

// EdgePeerInfo extends PeerInfo with route advertisements for edge connectors.
type EdgePeerInfo struct {
	PeerInfo
	AdvertisedRoutes []netip.Prefix
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

	// Auth is the authenticator used to verify incoming requests.
	Auth *Authenticator

	// Index is a unique server index for firewall marks and other uses. It starts at 0.
	Index uint16

	// Ipt is the iptables client for managing firewall rules.
	Ipt *iptables.IPTables

	// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// WgCidr is the CIDR block of IPs that the server assigns to WireGuard peers.
	WgCidr netip.Prefix

	// Ctx is the shutdown context for the server.
	Ctx context.Context

	ipAllocator *IpAllocator

	mu        sync.Mutex // Protects the fields below.
	allPeers  map[wgtypes.Key]PeerInfo
	edgePeers map[wgtypes.Key]EdgePeerInfo

	// relinquished indicates this server should not clean up WireGuard state on exit.
	// Set via the /relinquish endpoint for non-disruptive upgrades.
	relinquished bool

	// takeover indicates this server should take over existing WireGuard state
	// instead of creating a fresh interface. Used for non-disruptive upgrades.
	takeover bool
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
	srv.edgePeers = make(map[wgtypes.Key]EdgePeerInfo)

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
type connectResponse struct {
	AssignedAddr     string
	ServerPublicKey  string
	ServerListenPort int
}

// Handle a new connection.
func (srv *Server) connectHandler(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	MetricsIncr("connect.count")
	defer func() { MetricsTiming("connect.server_side_latency_ms", time.Since(t0)) }()

	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := srv.Auth.Authenticate(r); err != nil {
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
	tWg := time.Now()
	err = srv.WgClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         peerKey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{prefixToIPNet(netip.PrefixFrom(peerIp, 32))},
			},
		},
	})
	MetricsTiming("wg_configure.latency_ms", time.Since(tWg), "operation:add_peer")
	if err != nil {
		srv.mu.Lock()
		delete(srv.allPeers, peerKey)
		srv.mu.Unlock()

		srv.ipAllocator.Free(peerIp)
		log.Printf("failed to configure WireGuard peer: %v", err)
		http.Error(w, "failed to configure WireGuard peer", http.StatusInternalServerError)
		return
	}

	// Return the assigned IP address and the server's public key.
	resp := &connectResponse{
		AssignedAddr:     fmt.Sprintf("%v/%d", peerIp, srv.WgCidr.Bits()),
		ServerPublicKey:  srv.Key.PublicKey().String(),
		ServerListenPort: WireguardListenPortBase + int(srv.Index),
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
	t0 := time.Now()
	MetricsIncr("disconnect.count")
	defer func() { MetricsTiming("disconnect.server_side_latency_ms", time.Since(t0)) }()

	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := srv.Auth.Authenticate(r); err != nil {
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

// --- Edge connector handlers ---

type edgeConnectRequest struct {
	PeerPublicKey string   `json:"peer_public_key"`
	Routes        []string `json:"routes"`
}

type edgeConnectResponse struct {
	AssignedAddr     string `json:"assigned_addr"`
	ServerPublicKey  string `json:"server_public_key"`
	ServerListenPort int    `json:"server_listen_port"`
}

// hasRouteConflict checks if any of the given routes conflict with existing edge
// routes or the WireGuard CIDR. Must be called with srv.mu held.
func (srv *Server) hasRouteConflict(routes []netip.Prefix, excludeKey *wgtypes.Key) error {
	for _, route := range routes {
		if route.Overlaps(srv.WgCidr) {
			return fmt.Errorf("route %v overlaps with WireGuard CIDR %v", route, srv.WgCidr)
		}
		for key, edge := range srv.edgePeers {
			if excludeKey != nil && key == *excludeKey {
				continue
			}
			for _, existing := range edge.AdvertisedRoutes {
				if route.Overlaps(existing) {
					return fmt.Errorf("route %v overlaps with existing edge route %v", route, existing)
				}
			}
		}
	}
	return nil
}

// Handle a new edge connector peering request.
func (srv *Server) edgeConnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := srv.Auth.Authenticate(r); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	req := &edgeConnectRequest{}
	if err = json.Unmarshal(buf, req); err != nil {
		http.Error(w, "failed to parse request body", http.StatusBadRequest)
		return
	}

	peerKey, err := wgtypes.ParseKey(req.PeerPublicKey)
	if err != nil {
		http.Error(w, "invalid peer public key", http.StatusBadRequest)
		return
	}

	if len(req.Routes) == 0 {
		http.Error(w, "at least one route must be advertised", http.StatusBadRequest)
		return
	}

	// Parse and validate routes.
	var routes []netip.Prefix
	for _, routeStr := range req.Routes {
		prefix, err := netip.ParsePrefix(routeStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid route %q: %v", routeStr, err), http.StatusBadRequest)
			return
		}
		routes = append(routes, prefix.Masked())
	}

	srv.mu.Lock()
	// Check for route conflicts (allow re-registration by the same key).
	if err := srv.hasRouteConflict(routes, &peerKey); err != nil {
		srv.mu.Unlock()
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	peerInfo, exists := srv.allPeers[peerKey]
	srv.mu.Unlock()

	// If the edge already exists as a peer, reuse its IP.
	var peerIp netip.Addr
	if exists {
		peerIp = peerInfo.PeerIp
	} else {
		peerIp = srv.ipAllocator.Allocate()
	}

	if peerIp.IsUnspecified() {
		log.Printf("no more ip addresses available in %v", srv.WgCidr)
		http.Error(w, "no more IP addresses available", http.StatusServiceUnavailable)
		return
	}

	// Build AllowedIPs: the peer's own /32 plus all advertised routes.
	allowedIPs := []net.IPNet{prefixToIPNet(netip.PrefixFrom(peerIp, 32))}
	for _, route := range routes {
		allowedIPs = append(allowedIPs, prefixToIPNet(route))
	}

	srv.mu.Lock()
	srv.allPeers[peerKey] = PeerInfo{
		ConnectionTime: time.Now(),
		PeerIp:         peerIp,
	}
	srv.edgePeers[peerKey] = EdgePeerInfo{
		PeerInfo: PeerInfo{
			ConnectionTime: time.Now(),
			PeerIp:         peerIp,
		},
		AdvertisedRoutes: routes,
	}
	srv.mu.Unlock()

	clientIp := strings.Split(r.RemoteAddr, ":")[0]
	log.Printf("[%v] new edge peer %v at %v: %v (routes: %v)", srv.BindAddr, clientIp, peerIp, peerKey, routes)
	err = srv.WgClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         peerKey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        allowedIPs,
			},
		},
	})
	if err != nil {
		srv.mu.Lock()
		delete(srv.allPeers, peerKey)
		delete(srv.edgePeers, peerKey)
		srv.mu.Unlock()

		srv.ipAllocator.Free(peerIp)
		log.Printf("failed to configure WireGuard edge peer: %v", err)
		http.Error(w, "failed to configure WireGuard peer", http.StatusInternalServerError)
		return
	}

	resp := &edgeConnectResponse{
		AssignedAddr:     fmt.Sprintf("%v/%d", peerIp, srv.WgCidr.Bits()),
		ServerPublicKey:  srv.Key.PublicKey().String(),
		ServerListenPort: WireguardListenPortBase + int(srv.Index),
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)
}

// Handle an edge connector disconnect request.
func (srv *Server) edgeDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := srv.Auth.Authenticate(r); err != nil {
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

	clientIp := strings.Split(r.RemoteAddr, ":")[0]
	log.Printf("[%v] edge disconnect request from %v: %v", srv.BindAddr, clientIp, peerKey)

	err = srv.cleanupPeer(peerKey)
	if err != nil {
		log.Printf("failed to cleanup edge peer %v: %v", peerKey, err)
		http.Error(w, "failed to cleanup peer", http.StatusInternalServerError)
		return
	}

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

	if err := srv.Auth.Authenticate(r); err != nil {
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

	if err := srv.Auth.Authenticate(r); err != nil {
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

func (srv *Server) Ifname() string {
	return fmt.Sprintf("vprox%d", srv.Index)
}

func (srv *Server) StartWireguard() error {
	ifname := srv.Ifname()
	link := &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}}

	// Track whether we created a fresh interface (for cleanup on error)
	createdFreshInterface := false

	if srv.takeover {
		// In takeover mode, use existing interface if available, otherwise create fresh
		_, err := netlink.LinkByName(ifname)
		if err == nil {
			log.Printf("[%v] takeover mode: using existing WireGuard interface %s", srv.BindAddr, ifname)
		} else {
			// Interface doesn't exist, create fresh
			log.Printf("[%v] takeover mode: interface %s not found, creating fresh", srv.BindAddr, ifname)
			if err := srv.createFreshInterface(link); err != nil {
				return err
			}
			createdFreshInterface = true
		}
	} else {
		// Normal mode: delete and recreate the interface
		_ = netlink.LinkDel(link) // remove if it already exists
		if err := srv.createFreshInterface(link); err != nil {
			return err
		}
		createdFreshInterface = true
	}

	listenPort := WireguardListenPortBase + int(srv.Index)
	tWg := time.Now()
	err := srv.WgClient.ConfigureDevice(ifname, wgtypes.Config{
		PrivateKey: &srv.Key,
		ListenPort: &listenPort,
	})
	MetricsTiming("wg_configure.latency_ms", time.Since(tWg), "operation:init")
	if err != nil {
		if createdFreshInterface {
			netlink.LinkDel(link)
		}
		return err
	}

	return nil
}

// createFreshInterface creates and configures a new WireGuard interface.
func (srv *Server) createFreshInterface(link *linkWireguard) error {
	err := netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("failed to create WireGuard device: %v", err)
	}

	ipnet := prefixToIPNet(srv.WgCidr)
	err = netlink.AddrAdd(link, &netlink.Addr{IPNet: &ipnet})
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("failed to add address to WireGuard device: %v", err)
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("failed to bring up WireGuard device: %v", err)
	}

	return nil
}

func (srv *Server) CleanupWireguard() {
	srv.mu.Lock()
	relinquished := srv.relinquished
	srv.mu.Unlock()

	if relinquished {
		log.Printf("[%v] skipping WireGuard cleanup (relinquished)", srv.BindAddr)
	} else {
		log.Printf("[%v] cleaning up WireGuard state", srv.BindAddr)
		ifname := srv.Ifname()
		_ = netlink.LinkDel(&linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}})
	}
}

// iptablesInputFwmarkRule adds or removes the mangle PREROUTING rule for traffic from WireGuard.
func (srv *Server) iptablesInputFwmarkRule(enabled bool) error {
	firewallMark := FwmarkBase + int(srv.Index)
	rule := []string{
		"-i", srv.Ifname(),
		"-j", "MARK", "--set-mark", strconv.Itoa(firewallMark),
		"-m", "comment", "--comment", fmt.Sprintf("vprox fwmark rule for %s", srv.Ifname()),
	}
	if enabled {
		return srv.Ipt.AppendUnique("mangle", "PREROUTING", rule...)
	} else {
		return srv.Ipt.Delete("mangle", "PREROUTING", rule...)
	}
}

// iptablesSnatRule adds or removes the nat POSTROUTING rule for outbound traffic.
func (srv *Server) iptablesSnatRule(enabled bool) error {
	firewallMark := FwmarkBase + int(srv.Index)
	rule := []string{
		"-m", "mark", "--mark", strconv.Itoa(firewallMark),
		"-o", srv.BindIface.Attrs().Name,
		"-j", "SNAT", "--to-source", srv.BindAddr.String(),
		"-m", "comment", "--comment", fmt.Sprintf("vprox snat rule for %s", srv.Ifname()),
	}
	if enabled {
		return srv.Ipt.AppendUnique("nat", "POSTROUTING", rule...)
	} else {
		return srv.Ipt.Delete("nat", "POSTROUTING", rule...)
	}
}

// iptablesMssRule adds or removes the FORWARD chain rule for TCP MSS adjustment
func (srv *Server) iptablesMssRule(enabled bool) error {
	rule := []string{
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--set-mss", "1160",
		"-m", "comment", "--comment", fmt.Sprintf("vprox mss rule for %s", srv.Ifname()),
	}

	if enabled {
		return srv.Ipt.AppendUnique("filter", "FORWARD", rule...)
	} else {
		return srv.Ipt.Delete("filter", "FORWARD", rule...)
	}
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

	return nil
}

func (srv *Server) CleanupIptables() {
	if err := srv.iptablesInputFwmarkRule(false); err != nil {
		log.Printf("warning: error cleaning up IP tables: failed to add fwmark rule: %v\n", err)
	}
	if err := srv.iptablesSnatRule(false); err != nil {
		log.Printf("warning: error cleaning up IP tables: failed to add SNAT rule: %v\n", err)
	}
}

func (srv *Server) removeIdlePeersLoop() {
	for {
		// Wait for up to 5 seconds, or stop when the context is done.
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		// Emit gauge metrics.
		srv.mu.Lock()
		activePeers := len(srv.allPeers)
		srv.mu.Unlock()
		MetricsGauge("active_peers", float64(activePeers))
		MetricsGauge("allocated_ips", float64(srv.ipAllocator.AllocatedCount()))

		if err := srv.removeIdlePeers(); err != nil {
			log.Printf("error removing idle peers: %v", err)
		}
	}
}

// cleanupPeer removes a peer from the WireGuard interface, reclaims its subnet IP,
// and removes it from the allPeers map. This function is idempotent and safe to call
// even if the peer doesn't exist. It uses the allPeers map as the source of truth.
func (srv *Server) cleanupPeer(publicKey wgtypes.Key) error {
	// Look up the peer in allPeers map to get its IP address.
	srv.mu.Lock()
	peerInfo, exists := srv.allPeers[publicKey]
	if !exists {
		// Peer not in allPeers - it likely already got cleaned up.
		srv.mu.Unlock()
		log.Printf("[%v] peer unexpectedly not found in allPeers - did /disconnect race with the periodic peer-GC loop?: %v", srv.BindAddr, publicKey)
		return nil
	}

	// Extract peer info and remove from allPeers and edgePeers.
	peerIp := peerInfo.PeerIp
	delete(srv.allPeers, publicKey)
	delete(srv.edgePeers, publicKey)
	srv.mu.Unlock()

	// Remove the peer from WireGuard (no lock held during WireGuard operations).
	log.Printf("[%v] removing peer at %v: %v", srv.BindAddr, peerIp, publicKey)
	tWg := time.Now()
	err := srv.WgClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: publicKey,
				Remove:    true,
			},
		},
	})
	MetricsTiming("wg_configure.latency_ms", time.Since(tWg), "operation:remove_peer")
	if err != nil {
		return fmt.Errorf("failed to remove WireGuard peer: %v", err)
	}

	// Free the IP address.
	if !peerIp.IsUnspecified() {
		srv.ipAllocator.Free(peerIp)
	}

	return nil
}

func (srv *Server) removeIdlePeers() error {
	device, err := srv.WgClient.Device(srv.Ifname())
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device: %v", err)
	}

	// Hold the lock for access to allPeers.
	srv.mu.Lock()
	defer srv.mu.Unlock()

	var removePeers []wgtypes.PeerConfig
	var removeIps []netip.Addr
	for _, peer := range device.Peers {
		var idle bool
		if peer.LastHandshakeTime.IsZero() {
			peerInfo, exists := srv.allPeers[peer.PublicKey]
			if exists {
				idle = time.Since(peerInfo.ConnectionTime) > PeerIdleTimeout
			} else {
				// If we somehow have a WireGuard interface for a peer but no allPeers entry,
				// let's just assume it's idle and remove it.
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
			if edgeInfo, isEdge := srv.edgePeers[peer.PublicKey]; isEdge {
				log.Printf("[%v] removing idle edge peer with routes: %v",
					srv.BindAddr, edgeInfo.AdvertisedRoutes)
			}
			removePeers = append(removePeers, wgtypes.PeerConfig{
				PublicKey: peer.PublicKey,
				Remove:    true,
			})
			delete(srv.allPeers, peer.PublicKey)
			delete(srv.edgePeers, peer.PublicKey)
		}
	}

	if len(removePeers) > 0 {
		tWg := time.Now()
		err := srv.WgClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{Peers: removePeers})
		MetricsTiming("wg_configure.latency_ms", time.Since(tWg), "operation:remove_idle_peers")
		if err != nil {
			return err
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
	mux.HandleFunc("/edge-connect", srv.edgeConnectHandler)
	mux.HandleFunc("/edge-disconnect", srv.edgeDisconnectHandler)
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
