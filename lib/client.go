package lib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PolicyRoutingTable is the custom routing table number used for multi-tunnel
// multipath routing. Traffic from the vprox IP is redirected here via an
// ip rule, and this table contains equal-cost routes across all tunnels.
const PolicyRoutingTable = 51820

// PolicyRoutingPriority is the ip rule priority for the vprox policy route.
const PolicyRoutingPriority = 100

// Used to determine if we can recover from an error during connection setup.
type ConnectionError struct {
	Message     string
	Recoverable bool
}

func (e *ConnectionError) Error() string {
	return e.Message
}

// IsRecoverableError returns false if the error is a ConnectionError that is not recoverable.
func IsRecoverableError(err error) bool {
	var connErr *ConnectionError
	if errors.As(err, &connErr) {
		return connErr.Recoverable
	}
	// By default assume recoverable.
	return true
}

// Client manages a peering connection with a local WireGuard interface, or a
// set of parallel WireGuard interfaces when multi-tunnel is enabled.
//
// Single-tunnel (NumTunnels <= 1):
//
//	Applications use "vprox0" which is a plain WireGuard interface.
//
// Multi-tunnel (NumTunnels > 1):
//
//	WireGuard tunnels: vprox0t0, vprox0t1, vprox0t2, ...
//	Dummy device:      vprox0  (holds the IP address, user-facing)
//
//	Applications bind to "vprox0" (the dummy interface). An ip rule redirects
//	traffic sourced from the vprox IP into a custom routing table that has
//	equal-cost multipath routes across the WireGuard tunnels. The kernel
//	distributes flows across them via L4 hashing. Each tunnel uses a different
//	UDP port so the NIC hashes the outer packets to different hardware RX queues.
type Client struct {
	// Key is the private key of the client.
	Key wgtypes.Key

	// Ifname is the name of the interface exposed to applications (e.g. "vprox0").
	// In multi-tunnel mode this is a dummy device; individual WireGuard tunnels
	// are named <Ifname>t0, <Ifname>t1, etc.
	Ifname string

	// ServerIp is the public IPv4 address of the server.
	ServerIp netip.Addr

	// Password authenticates the client connection.
	Password string

	// NumTunnels is the number of parallel WireGuard tunnels to create.
	// When <= 1, the client creates a single plain WireGuard interface.
	// When > 1, a dummy device + policy routing is created over N WireGuard tunnels.
	NumTunnels int

	// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// Http is used to make connect requests to the server.
	Http *http.Client

	// wgCidr is the current subnet assigned to the interface, if any.
	wgCidr netip.Prefix

	// activeTunnels tracks how many tunnel interfaces were actually created
	// during the last successful Connect().
	activeTunnels int
}

// ---------------------------------------------------------------------------
// Naming helpers
// ---------------------------------------------------------------------------

// numTunnels returns the effective tunnel count, defaulting to 1.
func (c *Client) numTunnels() int {
	if c.NumTunnels <= 1 {
		return 1
	}
	return c.NumTunnels
}

// isMultiTunnel returns true when we should create a bond device.
func (c *Client) isMultiTunnel() bool {
	return c.numTunnels() > 1
}

// tunnelIfname returns the WireGuard interface name for the t-th tunnel.
//   - Single-tunnel mode: returns Ifname directly (e.g. "vprox0").
//   - Multi-tunnel mode:  returns "<Ifname>t<t>" (e.g. "vprox0t0", "vprox0t1").
func (c *Client) tunnelIfname(t int) string {
	if !c.isMultiTunnel() {
		return c.Ifname
	}
	return fmt.Sprintf("%st%d", c.Ifname, t)
}

// tunnelLink builds a linkWireguard with tuned LinkAttrs for the t-th tunnel.
func (c *Client) tunnelLink(t int) *linkWireguard {
	return &linkWireguard{LinkAttrs: netlink.LinkAttrs{
		Name:        c.tunnelIfname(t),
		MTU:         WireguardMTU,
		TxQLen:      WireguardTxQLen,
		NumTxQueues: WireguardNumQueues,
		NumRxQueues: WireguardNumQueues,
		GSOMaxSize:  WireguardGSOMaxSize,
		GROMaxSize:  WireguardGSOMaxSize,
	}}
}

// ---------------------------------------------------------------------------
// Interface creation / deletion
// ---------------------------------------------------------------------------

// CreateInterface creates the network interface(s) that applications will use.
//   - Single-tunnel: one plain WireGuard interface named Ifname.
//   - Multi-tunnel:  N WireGuard interfaces + a dummy device named Ifname
//     with policy routing to distribute traffic across the tunnels.
//
// DeleteInterface() must be called to clean up.
func (c *Client) CreateInterface() error {
	nt := c.numTunnels()

	// Create the WireGuard tunnel interfaces.
	for t := 0; t < nt; t++ {
		if err := c.createTunnelInterface(t); err != nil {
			for rb := 0; rb < t; rb++ {
				c.deleteTunnelInterface(rb)
			}
			return err
		}
	}

	// In multi-tunnel mode, create a dummy device for the user-facing interface.
	if c.isMultiTunnel() {
		if err := c.createDummyInterface(); err != nil {
			for t := 0; t < nt; t++ {
				c.deleteTunnelInterface(t)
			}
			return err
		}
		log.Printf("created dummy %s with %d WireGuard tunnels (%s .. %s)",
			c.Ifname, nt, c.tunnelIfname(0), c.tunnelIfname(nt-1))
	}

	return nil
}

// createTunnelInterface creates a single WireGuard tunnel interface.
func (c *Client) createTunnelInterface(t int) error {
	link := c.tunnelLink(t)

	err := netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("error creating WireGuard interface %s: %v", link.Name, err)
	}

	// Set MTU explicitly (some kernels ignore LinkAttrs.MTU on creation).
	if err := netlink.LinkSetMTU(link, WireguardMTU); err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("error setting MTU on %s: %v", link.Name, err)
	}

	// Set TxQLen for improved burst handling (non-fatal).
	if err := netlink.LinkSetTxQLen(link, WireguardTxQLen); err != nil {
		log.Printf("warning: failed to set TxQLen on %s: %v", link.Name, err)
	}

	return nil
}

// createDummyInterface creates a dummy network interface named Ifname. This is
// the user-facing device that applications bind to. A policy routing rule will
// redirect its traffic into a custom table with multipath routes across the
// WireGuard tunnels.
func (c *Client) createDummyInterface() error {
	// Remove any stale interface with this name.
	if existing, _ := netlink.LinkByName(c.Ifname); existing != nil {
		_ = netlink.LinkDel(existing)
	}

	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:   c.Ifname,
			MTU:    WireguardMTU,
			TxQLen: WireguardTxQLen,
		},
	}

	if err := netlink.LinkAdd(dummy); err != nil {
		return fmt.Errorf("failed to create dummy interface %s: %v", c.Ifname, err)
	}

	return nil
}

// DeleteInterface removes all interfaces and policy routing rules.
func (c *Client) DeleteInterface() {
	if c.isMultiTunnel() {
		// Clean up policy routing.
		c.cleanupPolicyRouting()

		// Delete the dummy interface.
		log.Printf("About to delete dummy interface %v", c.Ifname)
		if dummy, err := netlink.LinkByName(c.Ifname); err == nil {
			if err := netlink.LinkDel(dummy); err != nil {
				log.Printf("error deleting dummy %v: %v", c.Ifname, err)
			} else {
				log.Printf("successfully deleted dummy %v", c.Ifname)
			}
		}
	}

	nt := c.numTunnels()
	for t := nt - 1; t >= 0; t-- {
		c.deleteTunnelInterface(t)
	}
}

// deleteTunnelInterface removes a single WireGuard tunnel interface.
func (c *Client) deleteTunnelInterface(t int) {
	ifname := c.tunnelIfname(t)
	log.Printf("About to delete vprox interface %v", ifname)
	link := &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}}
	if err := netlink.LinkDel(link); err != nil {
		log.Printf("error deleting vprox interface %v: %v", ifname, err)
	} else {
		log.Printf("successfully deleted vprox interface %v", ifname)
	}
}

// ---------------------------------------------------------------------------
// Connect / Disconnect
// ---------------------------------------------------------------------------

// Connect attempts to connect (or reconnect) to the server. All tunnel
// interfaces must already exist via CreateInterface().
func (c *Client) Connect() error {
	resp, err := c.sendConnectionRequest()
	if err != nil {
		return err
	}

	// Determine how many tunnels to actually use — minimum of what the client
	// wants and what the server offers.
	nt := c.numTunnels()
	serverTunnels := len(resp.Tunnels)
	if serverTunnels > 0 && serverTunnels < nt {
		nt = serverTunnels
	}
	if serverTunnels == 0 {
		nt = 1
	}
	c.activeTunnels = nt

	// Configure WireGuard on each tunnel interface.
	for t := 0; t < nt; t++ {
		ifname := c.tunnelIfname(t)

		link := c.tunnelLink(t)
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("error setting up %s: %v", ifname, err)
		}

		// Pick the listen port: tunnel 0 always uses ServerListenPort
		// (backwards compatible with old servers); tunnels 1+ use Tunnels[t].
		port := resp.ServerListenPort
		if t > 0 && t < len(resp.Tunnels) {
			port = resp.Tunnels[t].ListenPort
		}

		if err := c.configureWireguardTunnel(t, resp, port); err != nil {
			return fmt.Errorf("error configuring wireguard on %s: %v", ifname, err)
		}
	}

	// Bring up the user-facing interface and assign the address.
	if err := c.bringUpUserInterface(); err != nil {
		return err
	}

	if err := c.updateAddress(resp); err != nil {
		return err
	}

	// In multi-tunnel mode, assign addresses to each tunnel and set up
	// policy routing to distribute traffic across them.
	if c.isMultiTunnel() && nt > 1 {
		if err := c.setupPolicyRouting(nt); err != nil {
			return fmt.Errorf("error setting up policy routing: %v", err)
		}
		log.Printf("policy routing configured across %d tunnels", nt)
	}

	return nil
}

// bringUpUserInterface brings up the interface that applications will use.
// In single-tunnel mode this is the WireGuard interface itself; in multi-tunnel
// mode this is the bond device.
func (c *Client) bringUpUserInterface() error {
	link, err := netlink.LinkByName(c.Ifname)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %v", c.Ifname, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("error setting up %s: %v", c.Ifname, err)
	}
	return nil
}

// updateAddress assigns (or updates) the IP address on the user-facing
// interface (Ifname).
func (c *Client) updateAddress(resp connectResponse) error {
	cidr, err := netip.ParsePrefix(resp.AssignedAddr)
	if err != nil {
		return fmt.Errorf("failed to parse assigned address %v: %v", resp.AssignedAddr, err)
	}

	link, err := netlink.LinkByName(c.Ifname)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %v", c.Ifname, err)
	}

	if cidr != c.wgCidr {
		if c.wgCidr.IsValid() {
			oldIpnet := prefixToIPNet(c.wgCidr)
			if err := netlink.AddrDel(link, &netlink.Addr{IPNet: &oldIpnet}); err != nil {
				log.Printf("warning: failed to remove old address from %s: %v", c.Ifname, err)
			}
		}
		ipnet := prefixToIPNet(cidr)
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &ipnet}); err != nil {
			return fmt.Errorf("failed to add address to %s: %v", c.Ifname, err)
		}
		c.wgCidr = cidr
	}
	return nil
}

// ---------------------------------------------------------------------------
// Policy routing (multi-tunnel)
// ---------------------------------------------------------------------------

// setupPolicyRouting creates:
//  1. An ip rule that matches traffic from the vprox source IP and directs it
//     to a custom routing table.
//  2. Equal-cost multipath routes in that table across all WireGuard tunnels.
//
// This allows applications binding to the dummy vprox0 interface (or using the
// vprox IP as source) to have their traffic distributed across tunnels by the
// kernel's L4 flow hash.
func (c *Client) setupPolicyRouting(nt int) error {
	if !c.wgCidr.IsValid() {
		return fmt.Errorf("no valid CIDR assigned yet")
	}

	// Assign the same IP address to each WireGuard tunnel interface so that
	// the kernel can use any of them to reach the server WireGuard IP.
	for t := 0; t < nt; t++ {
		ifname := c.tunnelIfname(t)
		tunnelLink, err := netlink.LinkByName(ifname)
		if err != nil {
			return fmt.Errorf("failed to find tunnel %s: %v", ifname, err)
		}
		ipnet := prefixToIPNet(c.wgCidr)
		if err := netlink.AddrReplace(tunnelLink, &netlink.Addr{IPNet: &ipnet}); err != nil {
			return fmt.Errorf("failed to assign address to %s: %v", ifname, err)
		}
	}

	// Build multipath nexthops — one per tunnel interface.
	gwAddr := c.wgCidr.Masked().Addr().Next()
	gwIP := addrToIp(gwAddr)

	var nexthops []*netlink.NexthopInfo
	for t := 0; t < nt; t++ {
		ifname := c.tunnelIfname(t)
		tunnelLink, err := netlink.LinkByName(ifname)
		if err != nil {
			return fmt.Errorf("failed to find tunnel %s: %v", ifname, err)
		}
		nexthops = append(nexthops, &netlink.NexthopInfo{
			LinkIndex: tunnelLink.Attrs().Index,
			Gw:        gwIP,
			Hops:      0,
		})
	}

	// Add default multipath route in the custom table.
	_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
	mpRoute := &netlink.Route{
		Table:     PolicyRoutingTable,
		Dst:       defaultDst,
		MultiPath: nexthops,
	}
	if err := netlink.RouteReplace(mpRoute); err != nil {
		return fmt.Errorf("failed to add multipath route to table %d: %v", PolicyRoutingTable, err)
	}

	// Add an ip rule: from <vprox-ip> lookup table PolicyRoutingTable.
	srcIP := c.wgCidr.Addr()
	srcNet := &net.IPNet{
		IP:   addrToIp(srcIP),
		Mask: net.CIDRMask(32, 32),
	}
	rule := netlink.NewRule()
	rule.Src = srcNet
	rule.Table = PolicyRoutingTable
	rule.Priority = PolicyRoutingPriority

	// Remove any stale rule first (idempotent).
	_ = netlink.RuleDel(rule)

	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("failed to add ip rule for %v: %v", srcIP, err)
	}

	return nil
}

// cleanupPolicyRouting removes the ip rule and flushes the custom routing table.
func (c *Client) cleanupPolicyRouting() {
	if c.wgCidr.IsValid() {
		srcIP := c.wgCidr.Addr()
		srcNet := &net.IPNet{
			IP:   addrToIp(srcIP),
			Mask: net.CIDRMask(32, 32),
		}
		rule := netlink.NewRule()
		rule.Src = srcNet
		rule.Table = PolicyRoutingTable
		rule.Priority = PolicyRoutingPriority
		if err := netlink.RuleDel(rule); err != nil {
			log.Printf("warning: failed to delete ip rule: %v", err)
		}
	}

	// Flush routes in our custom table.
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Table: PolicyRoutingTable,
	}, netlink.RT_FILTER_TABLE)
	if err == nil {
		for i := range routes {
			_ = netlink.RouteDel(&routes[i])
		}
	}
}

// configureWireguardTunnel configures a single WireGuard tunnel interface with
// the server as a peer on the given port.
func (c *Client) configureWireguardTunnel(t int, resp connectResponse, serverPort int) error {
	serverPublicKey, err := wgtypes.ParseKey(resp.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse server public key: %v", err)
	}

	keepalive := 25 * time.Second
	ifname := c.tunnelIfname(t)
	return c.WgClient.ConfigureDevice(ifname, wgtypes.Config{
		PrivateKey:   &c.Key,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: serverPublicKey,
				Endpoint: &net.UDPAddr{
					IP:   addrToIp(c.ServerIp),
					Port: serverPort,
				},
				PersistentKeepaliveInterval: &keepalive,
				ReplaceAllowedIPs:           true,
				AllowedIPs: []net.IPNet{{
					IP:   net.IPv4(0, 0, 0, 0),
					Mask: net.CIDRMask(0, 32),
				}},
			},
		},
	})
}

// Disconnect notifies the server that this client is disconnecting, allowing the
// server to immediately reclaim resources (wireguard peer and subnet IP) instead of
// waiting for the idle timeout.
func (c *Client) Disconnect() error {
	disconnectUrl, err := url.Parse(fmt.Sprintf("https://%s/disconnect", c.ServerIp))
	if err != nil {
		return fmt.Errorf("failed to parse disconnect URL: %v", err)
	}

	reqJson := &disconnectRequest{
		PeerPublicKey: c.Key.PublicKey().String(),
	}
	buf, err := json.Marshal(reqJson)
	if err != nil {
		return fmt.Errorf("failed to marshal disconnect request: %v", err)
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    disconnectUrl,
		Header: http.Header{
			"Authorization": []string{"Bearer " + c.Password},
		},
		Body: io.NopCloser(bytes.NewBuffer(buf)),
	}

	resp, err := c.Http.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send disconnect request to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %v for disconnect request", resp.Status)
	}

	log.Printf("successfully disconnected from server %v", c.ServerIp)
	return nil
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

// CheckConnection checks the status of the connection with the wireguard peer,
// and returns true if it is healthy. This sends 3 pings in succession, and blocks
// until they receive a response or the timeout passes.
// In multi-tunnel mode, pings are sent through the first WireGuard tunnel
// interface (not the dummy device) so replies are received on the same interface.
func (c *Client) CheckConnection(timeout time.Duration, cancelCtx context.Context) bool {
	pinger, err := probing.NewPinger(c.wgCidr.Masked().Addr().Next().String())
	if err != nil {
		log.Printf("error creating pinger: %v", err)
		return false
	}

	// Use the first WireGuard tunnel for health checks. In single-tunnel mode
	// tunnelIfname(0) == Ifname; in multi-tunnel mode it's the actual WireGuard
	// device (e.g. "vprox0t0") rather than the dummy ("vprox0").
	pinger.InterfaceName = c.tunnelIfname(0)
	pinger.Timeout = timeout
	pinger.Count = 3
	pinger.Interval = 10 * time.Millisecond // Send approximately all at once
	err = pinger.RunWithContext(cancelCtx)   // Blocks until finished.
	if err != nil {
		log.Printf("error running pinger: %v", err)
		return false
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 && stats.PacketsRecv < stats.PacketsSent {
		log.Printf("warning: %v of %v packets in ping were dropped", stats.PacketsSent-stats.PacketsRecv, stats.PacketsSent)
	}
	return stats.PacketsRecv > 0
}

// ---------------------------------------------------------------------------
// HTTPS / control-plane
// ---------------------------------------------------------------------------

// sendConnectionRequest attempts to send a connection request to the peer.
func (c *Client) sendConnectionRequest() (connectResponse, error) {
	connectUrl, err := url.Parse(fmt.Sprintf("https://%s/connect", c.ServerIp))
	if err != nil {
		return connectResponse{}, fmt.Errorf("failed to parse connect URL: %v", err)
	}

	reqJson := &connectRequest{
		PeerPublicKey: c.Key.PublicKey().String(),
	}
	buf, err := json.Marshal(reqJson)
	if err != nil {
		return connectResponse{}, fmt.Errorf("failed to marshal connect request: %v", err)
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    connectUrl,
		Header: http.Header{
			"Authorization": []string{"Bearer " + c.Password},
		},
		Body: io.NopCloser(bytes.NewBuffer(buf)),
	}

	resp, err := c.Http.Do(req)
	if err != nil {
		return connectResponse{}, fmt.Errorf("failed to connect to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		recoverable := resp.StatusCode != http.StatusUnauthorized
		return connectResponse{}, &ConnectionError{
			Message:     fmt.Sprintf("server returned status %v", resp.Status),
			Recoverable: recoverable,
		}
	}

	buf, err = io.ReadAll(resp.Body)
	if err != nil {
		return connectResponse{}, fmt.Errorf("failed to read response body: %v", err)
	}

	var respJson connectResponse
	json.Unmarshal(buf, &respJson)
	return respJson, nil
}
