package lib

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"

	"sync"
	"sync/atomic"
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

// DefaultMaxPeers is the default maximum number of active peers a server will
// accept before returning 429 Too Many Requests.
const DefaultMaxPeers = 10000

// A new peer must connect with a handshake within this time. Under sustained
// load with 1000+ concurrent connections, handshakes can take 20+ seconds due
// to kernel-side WireGuard crypto serialisation, so this must be generous.
const FirstHandshakeTimeout = 15 * time.Second

// If no handshakes are received in this time, the peer is considered idle and
// removed from the server's WireGuard interface list.
//
// Note that this must be at least 2-3 minutes, since WireGuard sends handshakes
// interleaved with a data message only when 2-3 minutes have passed since the
// last successful handshake. This is regardless of the persistent-keepalive
// setting.
const PeerIdleTimeout = 5 * time.Minute

// NumShards is the number of parallel netlink sockets (wgctrl.Clients) each
// Server uses for WireGuard peer operations. All shards target the same
// single WireGuard interface, but each has its own netlink connection so
// ConfigureDevice calls can proceed in parallel. 16 shards keeps the flush
// pipeline saturated even when individual ConfigureDevice calls block for
// a few milliseconds under heavy peer churn.
const NumShards = 16

// peerState tracks per-peer metadata kept in memory so the connect handler can
// avoid expensive netlink round-trips for duplicate checks.
type peerState struct {
	IP             netip.Addr
	CreatedAt      time.Time
	HandshakeSeen  bool // set true once Device() confirms a WireGuard handshake
}

// pendingPeer wraps a WireGuard peer config with a done channel so the HTTP
// handler can wait for the flush loop to actually register the peer in
// WireGuard before returning the response to the client. This prevents a
// race where the client starts handshaking before the server has registered
// the peer.
type pendingPeer struct {
	config wgtypes.PeerConfig
	done   chan error // closed (with nil) on success, or receives an error
}

// wgShard owns its own netlink socket (wgctrl.Client) for parallel I/O to the
// single shared WireGuard interface. Multiple shards avoid the per-connection
// mutex in the netlink library that would otherwise serialise all operations.
type wgShard struct {
	wgClient     *wgctrl.Client
	pendingPeers chan pendingPeer
	flushDone    chan struct{}
}

// Server handles state for one WireGuard network.
//
// The `vprox server` command should create one Server instance for each
// private IP that the server should bind to.
type Server struct {
	// Key is the private key of the server.
	// MaxPeers is the maximum number of concurrent peers. When len(peers)
	// reaches this limit, new /connect requests receive 429. Zero means use
	// DefaultMaxPeers.
	MaxPeers int

	// PlainHTTP disables TLS on the control-plane listener. When true the
	// server accepts plain HTTP on port 443, eliminating TLS handshake
	// overhead entirely. Clients must use http:// instead of https://.
	PlainHTTP bool

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

	// Ipt is the iptables client for managing firewall rules.
	Ipt *iptables.IPTables

	// WgClient is used only for the initial ConfigureDevice in StartWireguard
	// (setting the private key / listen port). Per-shard clients handle
	// ongoing peer operations.
	WgClient *wgctrl.Client

	// WgCidr is the CIDR block of IPs that the server assigns to WireGuard peers.
	WgCidr netip.Prefix

	// Ctx is the shutdown context for the server.
	Ctx context.Context

	ipAllocator *IpAllocator

	mu    sync.Mutex // Protects the fields below.
	peers map[wgtypes.Key]peerState

	shards      []*wgShard    // NumShards netlink clients for parallel flush
	shardNext   atomic.Uint64 // round-robin counter for shard selection
	cleanupClient *wgctrl.Client // dedicated netlink client for removeIdlePeers
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
	srv.peers = make(map[wgtypes.Key]peerState)
	if srv.MaxPeers == 0 {
		maxPeers, err := GetMaxPeers()
		if err != nil {
			return fmt.Errorf("invalid max peers configuration: %v", err)
		}
		srv.MaxPeers = maxPeers
	}
	return nil
}

// pickShard returns the next shard via round-robin.
func (srv *Server) pickShard() *wgShard {
	idx := srv.shardNext.Add(1) - 1
	return srv.shards[idx%uint64(len(srv.shards))]
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

// Handle a new connection via HTTPS (or plain HTTP). The actual peer
// registration logic lives in registerPeer() which is shared with the
// UDP registration handler.
func (srv *Server) connectHandler(w http.ResponseWriter, r *http.Request) {
	// Drain the request body on every path so Go's HTTP server can reuse
	// the underlying TCP connection for keep-alive. Without this, early-
	// return error paths (auth failure, bad method) leave unread body bytes
	// that force the connection closed.
	defer func() {
		io.Copy(io.Discard, r.Body)
	}()

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

	// Delegate to shared registration logic (also used by UDP handler).
	reg, regErr := srv.registerPeer(peerKey, r.RemoteAddr)
	if regErr != nil {
		switch {
		case errors.Is(regErr, errPeerCapacity):
			log.Printf("[%v] at peer capacity, rejecting %v", srv.BindAddr, peerKey)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "resource_exhausted",
				"message": fmt.Sprintf("server at capacity (%d peers)", srv.MaxPeers),
			})
		case errors.Is(regErr, errNoAddresses):
			log.Printf("no more ip addresses available in %v", srv.WgCidr)
			http.Error(w, "no more IP addresses available", http.StatusServiceUnavailable)
		case errors.Is(regErr, errShardQueueFull):
			log.Printf("[%v] peer queue full, rejecting %v", srv.BindAddr, peerKey)
			http.Error(w, "server busy, try again", http.StatusServiceUnavailable)
		default:
			http.Error(w, "failed to configure WireGuard peer", http.StatusInternalServerError)
		}
		return
	}

	resp := reg.toConnectResponse()
	respBuf, err := json.Marshal(&resp)
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
	_ = netlink.LinkDel(link) // remove if it already exists
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

	listenPort := WireguardListenPortBase + int(srv.Index)
	err = srv.WgClient.ConfigureDevice(ifname, wgtypes.Config{
		PrivateKey: &srv.Key,
		ListenPort: &listenPort,
	})
	if err != nil {
		netlink.LinkDel(link)
		return err
	}

	// Create a dedicated netlink client for removeIdlePeers so that its
	// (potentially heavy) Device() and ConfigureDevice() calls never block
	// the flush shards.
	srv.cleanupClient, err = wgctrl.New()
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("failed to create cleanup wgctrl client: %v", err)
	}

	// Create NumShards netlink clients, each with its own socket, all
	// targeting the same WireGuard interface. This parallelises
	// ConfigureDevice calls that would otherwise serialise on a single
	// netlink connection mutex.
	srv.shards = make([]*wgShard, NumShards)
	for i := 0; i < NumShards; i++ {
		shardClient, err := wgctrl.New()
		if err != nil {
			srv.cleanupShards(i)
			srv.cleanupClient.Close()
			netlink.LinkDel(link)
			return fmt.Errorf("failed to create wgctrl client for shard %d: %v", i, err)
		}
		srv.shards[i] = &wgShard{
			wgClient:     shardClient,
			pendingPeers: make(chan pendingPeer, 4096),
			flushDone:    make(chan struct{}),
		}
	}

	log.Printf("[%v] created WireGuard interface %s with %d netlink shards + 1 cleanup client", srv.BindAddr, ifname, NumShards)
	return nil
}

// cleanupShards closes shard clients [0, upTo) during a partial setup failure.
func (srv *Server) cleanupShards(upTo int) {
	for j := 0; j < upTo; j++ {
		if srv.shards[j] != nil {
			close(srv.shards[j].pendingPeers)
			<-srv.shards[j].flushDone
			srv.shards[j].wgClient.Close()
		}
	}
}

func (srv *Server) CleanupWireguard() {
	// Shut down all shard flush loops and close their netlink clients.
	for _, shard := range srv.shards {
		if shard == nil {
			continue
		}
		close(shard.pendingPeers)
		<-shard.flushDone
		shard.wgClient.Close()
	}

	// Close the dedicated cleanup client.
	if srv.cleanupClient != nil {
		srv.cleanupClient.Close()
	}

	// Delete the single WireGuard interface.
	ifname := srv.Ifname()
	_ = netlink.LinkDel(&linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}})
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
		log.Printf("warning: error cleaning up IP tables: failed to remove fwmark rule: %v\n", err)
	}
	if err := srv.iptablesSnatRule(false); err != nil {
		log.Printf("warning: error cleaning up IP tables: failed to remove SNAT rule: %v\n", err)
	}
	if err := srv.iptablesMssRule(false); err != nil {
		log.Printf("warning: error cleaning up IP tables: failed to remove MSS rule: %v\n", err)
	}
}

func (srv *Server) removeIdlePeersLoop() {
	var iter int
	for {
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(1 * time.Second):
		}

		// Fast path every second: remove peers that never completed a
		// handshake using only the in-memory map — no Device() call.
		if err := srv.removeStaleNewPeers(); err != nil {
			log.Printf("error removing stale new peers: %v", err)
		}

		// Slow path every 15 iterations (~15s): full Device() netlink
		// scan to update HandshakeSeen flags and remove handshaked peers
		// that have gone idle or orphaned WireGuard entries.
		iter++
		if iter%15 == 0 {
			if err := srv.removeIdleHandshakedPeers(); err != nil {
				log.Printf("error removing idle peers: %v", err)
			}
		}
	}
}

// removeStaleNewPeers is the fast-path cleanup that runs every second.
// It examines only the in-memory peer map (no Device() netlink call) and
// removes peers that were registered more than FirstHandshakeTimeout ago
// but have never been confirmed as handshaked by a Device() scan.
// This is O(n) in the map size and avoids the expensive netlink round-trip
// that dominates under sustained load with 1000+ concurrent connections.
func (srv *Server) removeStaleNewPeers() error {
	srv.mu.Lock()

	var removePeers []wgtypes.PeerConfig
	var removeKeys []wgtypes.Key
	var removeIps []netip.Addr
	now := time.Now()

	for key, ps := range srv.peers {
		if !ps.HandshakeSeen && now.Sub(ps.CreatedAt) > FirstHandshakeTimeout {
			removePeers = append(removePeers, wgtypes.PeerConfig{
				PublicKey: key,
				Remove:    true,
			})
			removeKeys = append(removeKeys, key)
			removeIps = append(removeIps, ps.IP)
		}
	}

	srv.mu.Unlock()

	if len(removePeers) == 0 {
		return nil
	}

	if len(removePeers) >= 10 {
		log.Printf("[%v] fast-removing %d stale peer(s) (never handshaked)",
			srv.BindAddr, len(removePeers))
	}
	err := srv.cleanupClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{Peers: removePeers})
	if err != nil {
		return err
	}

	srv.mu.Lock()
	for _, key := range removeKeys {
		delete(srv.peers, key)
	}
	srv.mu.Unlock()

	for _, ip := range removeIps {
		srv.ipAllocator.Free(ip)
	}

	return nil
}

// removeIdleHandshakedPeers is the slow-path cleanup that runs every ~15s.
// It calls Device() to get the full peer list from WireGuard, updates the
// HandshakeSeen flag for peers that have completed a handshake, and removes
// peers that have been idle for PeerIdleTimeout or are orphaned (in WireGuard
// but not in the in-memory map).
func (srv *Server) removeIdleHandshakedPeers() error {
	device, err := srv.cleanupClient.Device(srv.Ifname())
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device: %v", err)
	}

	srv.mu.Lock()

	// Update HandshakeSeen for all peers that have completed a handshake.
	for _, peer := range device.Peers {
		if !peer.LastHandshakeTime.IsZero() {
			if ps, ok := srv.peers[peer.PublicKey]; ok && !ps.HandshakeSeen {
				ps.HandshakeSeen = true
				srv.peers[peer.PublicKey] = ps
			}
		}
	}

	// Clean up very old entries from the in-memory map.
	for key, ps := range srv.peers {
		if time.Since(ps.CreatedAt) > PeerIdleTimeout {
			delete(srv.peers, key)
		}
	}

	// Find peers to remove: handshaked-but-idle, or orphaned (not in map).
	var removePeers []wgtypes.PeerConfig
	var removeIps []netip.Addr
	for _, peer := range device.Peers {
		var shouldRemove bool

		if _, inMap := srv.peers[peer.PublicKey]; !inMap {
			// Orphaned: exists in WireGuard but not in our map.
			shouldRemove = true
		} else if !peer.LastHandshakeTime.IsZero() && time.Since(peer.LastHandshakeTime) > PeerIdleTimeout {
			// Handshaked but idle for too long.
			shouldRemove = true
		}

		if shouldRemove {
			if len(peer.AllowedIPs) > 0 {
				ipv4 := peer.AllowedIPs[0].IP.To4()
				if ipv4 != nil {
					removeIps = append(removeIps, netip.AddrFrom4([4]byte(ipv4)))
				}
			}
			removePeers = append(removePeers, wgtypes.PeerConfig{
				PublicKey: peer.PublicKey,
				Remove:    true,
			})
		}
	}

	srv.mu.Unlock()

	if len(removePeers) > 0 {
		if len(removePeers) >= 5 {
			log.Printf("[%v] slow-removing %d idle/orphaned peer(s)",
				srv.BindAddr, len(removePeers))
		}
		err := srv.cleanupClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{Peers: removePeers})
		if err != nil {
			return err
		}

		srv.mu.Lock()
		for _, p := range removePeers {
			delete(srv.peers, p.PublicKey)
		}
		srv.mu.Unlock()

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
	for i := range srv.shards {
		go srv.flushPeersLoop(srv.shards[i])
	}

	// Start the UDP registration listener alongside HTTPS.
	go func() {
		if err := srv.ListenForUDPRegister(); err != nil {
			log.Printf("[%v] UDP register listener failed: %v", srv.BindAddr, err)
		}
	}()

	// Some bind addresses may not have been added to the network interface. If
	// that is the case, we need to add it (transiently).
	_ = srv.addBindAddr()
	go srv.addBindAddrLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.indexHandler)
	mux.HandleFunc("/connect", srv.connectHandler)

	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KB
	}

	if !srv.PlainHTTP {
		cert, err := loadServerTls()
		if err != nil {
			return err
		}
		httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			// TLS 1.3 uses a 1-RTT handshake (vs 2-RTT for TLS 1.2),
			// halving connection setup latency under load.
			MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			// Session tickets allow TLS resumption, cutting even the
			// 1-RTT handshake down to a 0-RTT reconnect for repeat
			// clients within the ticket lifetime.
			SessionTicketsDisabled: false,
		}
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%v:443", srv.BindAddr))
	if err != nil {
		return fmt.Errorf("failed to listen on :443: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		var serveErr error
		if srv.PlainHTTP {
			log.Printf("server listening on %v:443 (plain HTTP, no TLS)\n", srv.BindAddr)
			serveErr = httpServer.Serve(listener)
		} else {
			log.Printf("server listening on %v:443 (HTTPS, TLS 1.3)\n", srv.BindAddr)
			serveErr = httpServer.ServeTLS(listener, "", "")
		}
		if serveErr != http.ErrServerClosed {
			errCh <- fmt.Errorf("server failed to serve %v: %v", srv.BindAddr, serveErr)
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

// maxFlushBatch caps the number of peers flushed in a single ConfigureDevice
// call. This bounds the size of the netlink message and keeps the socket
// available for removeIdlePeers.
const maxFlushBatch = 256

// flushPeersLoop drains shard.pendingPeers and batches peer configs into single
// ConfigureDevice netlink calls via the shard's own netlink socket. All shards
// target the same WireGuard interface but use separate sockets for parallelism.
//
// Batching strategy:
//   - Block on the channel until the first peer arrives (zero overhead at low load).
//   - Non-blocking drain: grab everything already queued without waiting.
//   - Flush once the channel is empty or the batch hits maxFlushBatch.
//
// Under high load the channel naturally accumulates multiple items between
// flushes, so no artificial delay is needed to achieve batching.
//
// After each flush, all waiting HTTP handlers are unblocked via their done
// channels, so the client only receives its response after the peer is
// registered in WireGuard.
func (srv *Server) flushPeersLoop(shard *wgShard) {
	defer close(shard.flushDone)

	for {
		// Block until the first peer arrives or the channel is closed.
		first, ok := <-shard.pendingPeers
		if !ok {
			return // channel closed, we're shutting down
		}

		batch := []pendingPeer{first}

		// Non-blocking drain: grab everything already in the channel.
		batch, closed := drainPending(shard.pendingPeers, batch, maxFlushBatch)
		if closed {
			srv.flushShardBatch(shard, batch)
			return
		}

		srv.flushShardBatch(shard, batch)
	}
}

// drainPending does a non-blocking drain of ch into batch, stopping when the
// channel is empty or the batch reaches maxSize. Returns the (possibly grown)
// batch and whether the channel was closed.
func drainPending(ch <-chan pendingPeer, batch []pendingPeer, maxSize int) ([]pendingPeer, bool) {
	for len(batch) < maxSize {
		select {
		case p, ok := <-ch:
			if !ok {
				return batch, true
			}
			batch = append(batch, p)
		default:
			return batch, false
		}
	}
	return batch, false
}

// flushShardBatch sends a batch of peer configs to WireGuard via the shard's
// own netlink socket, then signals all waiting HTTP handlers via their done
// channels. On failure, it rolls back the in-memory state.
func (srv *Server) flushShardBatch(shard *wgShard, batch []pendingPeer) {
	// Extract the wgtypes.PeerConfig slice for the netlink call.
	configs := make([]wgtypes.PeerConfig, len(batch))
	for i, pp := range batch {
		configs[i] = pp.config
	}

	err := shard.wgClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{
		Peers: configs,
	})
	if err != nil {
		log.Printf("failed to configure %d WireGuard peer(s): %v", len(batch), err)
		srv.mu.Lock()
		for _, pp := range batch {
			if ps, ok := srv.peers[pp.config.PublicKey]; ok {
				srv.ipAllocator.Free(ps.IP)
				delete(srv.peers, pp.config.PublicKey)
			}
		}
		srv.mu.Unlock()
	} else if len(batch) > 16 {
		log.Printf("[%v] flushed %d peers in one call", srv.BindAddr, len(batch))
	}

	// Signal all waiting handlers. On success err is nil; on failure each
	// handler gets the error.
	for _, pp := range batch {
		pp.done <- err
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
