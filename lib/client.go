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

// Client manages a peering connection with a local WireGuard interface (or a
// set of parallel WireGuard interfaces when multi-tunnel is enabled).
type Client struct {
	// Key is the private key of the client.
	Key wgtypes.Key

	// Ifname is the base name of the client WireGuard interface (e.g. "vprox0").
	// With multi-tunnel this becomes the primary interface; additional tunnels
	// are named "vprox0t1", "vprox0t2", etc.
	Ifname string

	// ServerIp is the public IPv4 address of the server.
	ServerIp netip.Addr

	// Password authenticates the client connection.
	Password string

	// NumTunnels is the number of parallel WireGuard tunnels to create.
	// When <= 1, the client behaves exactly as before (single interface).
	NumTunnels int

	// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// Http is used to make connect requests to the server.
	Http *http.Client

	// wgCidr is the current subnet assigned to the WireGuard interface, if any.
	wgCidr netip.Prefix

	// activeTunnels tracks how many tunnel interfaces were actually created
	// during the last successful Connect(). This may be less than NumTunnels
	// if the server returned fewer Tunnels entries (e.g. old server).
	activeTunnels int
}

// numTunnels returns the effective tunnel count, defaulting to 1.
func (c *Client) numTunnels() int {
	if c.NumTunnels <= 1 {
		return 1
	}
	return c.NumTunnels
}

// tunnelIfname returns the interface name for the t-th tunnel.
// Tunnel 0 uses Ifname directly (e.g. "vprox0").
// Tunnel 1+ appends "t1", "t2", etc. (e.g. "vprox0t1", "vprox0t2").
func (c *Client) tunnelIfname(t int) string {
	if t == 0 {
		return c.Ifname
	}
	return fmt.Sprintf("%st%d", c.Ifname, t)
}

// tunnelLink builds a linkWireguard for the t-th tunnel with tuned LinkAttrs.
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

// link returns a linkWireguard for the primary (tunnel 0) interface.
func (c *Client) link() *linkWireguard {
	return c.tunnelLink(0)
}

// CreateInterface creates the WireGuard interface(s). For single-tunnel mode
// this creates one interface; for multi-tunnel mode it creates N interfaces.
// DeleteInterface() must be called to clean up.
func (c *Client) CreateInterface() error {
	nt := c.numTunnels()
	for t := 0; t < nt; t++ {
		if err := c.createTunnelInterface(t); err != nil {
			// Clean up any interfaces we already created.
			for rb := 0; rb < t; rb++ {
				c.deleteTunnelInterface(rb)
			}
			return err
		}
	}
	if nt > 1 {
		log.Printf("created %d tunnel interfaces (%s .. %s)", nt, c.tunnelIfname(0), c.tunnelIfname(nt-1))
	}
	return nil
}

// createTunnelInterface creates a single WireGuard tunnel interface.
func (c *Client) createTunnelInterface(t int) error {
	link := c.tunnelLink(t)

	err := netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("error creating vprox interface %s: %v", link.Name, err)
	}

	// Set MTU explicitly (some kernels ignore LinkAttrs.MTU on creation)
	err = netlink.LinkSetMTU(link, WireguardMTU)
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("error setting MTU on vprox interface %s: %v", link.Name, err)
	}

	// Set TxQLen for improved burst handling
	err = netlink.LinkSetTxQLen(link, WireguardTxQLen)
	if err != nil {
		// Non-fatal: log warning but continue
		log.Printf("warning: failed to set TxQLen on vprox interface %s: %v", link.Name, err)
	}

	return nil
}

// Connect attempts to connect (or reconnect) to the server. All tunnel
// interfaces must already exist via CreateInterface().
func (c *Client) Connect() error {
	resp, err := c.sendConnectionRequest()
	if err != nil {
		return err
	}

	// Determine how many tunnels to actually use. Use the minimum of what
	// the client wants and what the server offers.
	nt := c.numTunnels()
	serverTunnels := len(resp.Tunnels)
	if serverTunnels > 0 && serverTunnels < nt {
		nt = serverTunnels
	}
	// If the server returned no Tunnels list (old server), use 1 tunnel.
	if serverTunnels == 0 {
		nt = 1
	}
	c.activeTunnels = nt

	// Bring up, assign address, and configure WireGuard on ALL tunnel interfaces.
	// Each interface gets the same IP address so the kernel knows how to reach
	// the gateway (server WireGuard IP) through any of them.
	for t := 0; t < nt; t++ {
		link := c.tunnelLink(t)
		err = netlink.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("error setting up vprox interface %s: %v", link.Name, err)
		}

		// Assign the same address to every tunnel interface. The first call
		// also updates c.wgCidr; subsequent calls for the same CIDR are
		// handled by updateTunnelInterface which skips if already set.
		if err := c.updateTunnelInterface(t, resp); err != nil {
			return fmt.Errorf("error updating interface %s: %v", link.Name, err)
		}

		// Pick the listen port: tunnel 0 always uses ServerListenPort
		// (backwards compatible with old servers); tunnels 1+ use Tunnels[t].
		var port int
		if t == 0 {
			port = resp.ServerListenPort
		} else {
			port = resp.Tunnels[t].ListenPort
		}
		err = c.configureWireguardTunnel(t, resp, port)
		if err != nil {
			return fmt.Errorf("error configuring wireguard on %s: %v", c.tunnelIfname(t), err)
		}
	}

	// Set up multipath routing if we have multiple active tunnels.
	if nt > 1 {
		if err := c.setupMultipathRouting(nt); err != nil {
			log.Printf("warning: failed to set up multipath routing: %v", err)
			// Fall back: traffic will just use the primary interface's route.
		} else {
			log.Printf("multipath routing configured across %d tunnels", nt)
		}
	}

	return nil
}

// updateTunnelInterface assigns the WireGuard address to tunnel interface t.
// Every tunnel interface gets the same IP/CIDR so that the server gateway is
// reachable through each of them (required for multipath routing).
func (c *Client) updateTunnelInterface(t int, resp connectResponse) error {
	cidr, err := netip.ParsePrefix(resp.AssignedAddr)
	if err != nil {
		return fmt.Errorf("failed to parse assigned address %v: %v", resp.AssignedAddr, err)
	}

	link := c.tunnelLink(t)

	if t == 0 && c.wgCidr.IsValid() && cidr != c.wgCidr {
		// On reconnect the primary tunnel may need the old address removed.
		oldIpnet := prefixToIPNet(c.wgCidr)
		if err := netlink.AddrDel(link, &netlink.Addr{IPNet: &oldIpnet}); err != nil {
			log.Printf("warning: failed to remove old address from %s when reconnecting: %v", c.tunnelIfname(t), err)
		}
	}

	ipnet := prefixToIPNet(cidr)
	err = netlink.AddrReplace(link, &netlink.Addr{IPNet: &ipnet})
	if err != nil {
		return fmt.Errorf("failed to add address to %s: %v", c.tunnelIfname(t), err)
	}

	// Track the CIDR on the first tunnel.
	if t == 0 {
		c.wgCidr = cidr
	}
	return nil
}

// setupMultipathRouting creates equal-cost multipath routes across all active
// tunnel interfaces so that the kernel distributes flows across them.
//
// WireGuard interfaces are POINTOPOINT and don't automatically get subnet
// routes, so we first add a per-device route for each tunnel, then replace
// them with a single multipath route.
func (c *Client) setupMultipathRouting(nt int) error {
	if !c.wgCidr.IsValid() {
		return fmt.Errorf("no valid CIDR assigned yet")
	}

	subnetIPNet := prefixToIPNet(c.wgCidr.Masked())

	// Step 1: Remove any existing routes for this subnet so we start clean.
	existingRoutes, _ := netlink.RouteList(nil, netlink.FAMILY_V4)
	for i := range existingRoutes {
		r := &existingRoutes[i]
		if r.Dst != nil && r.Dst.String() == subnetIPNet.String() {
			_ = netlink.RouteDel(r)
		}
	}

	// Step 2: Ensure each tunnel interface has a device-scoped route for the
	// subnet. This makes the gateway reachable through every interface.
	for t := 0; t < nt; t++ {
		ifname := c.tunnelIfname(t)
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			return fmt.Errorf("failed to find interface %s: %v", ifname, err)
		}
		devRoute := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &subnetIPNet,
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteReplace(devRoute); err != nil {
			return fmt.Errorf("failed to add device route on %s: %v", ifname, err)
		}
	}

	// Step 3: Build multipath nexthops — one per tunnel interface, using the
	// server's WireGuard IP (first address in subnet) as the gateway. Now
	// that each interface has a device-scoped route, the gateway is reachable
	// through all of them.
	gwAddr := c.wgCidr.Masked().Addr().Next()
	gwIP := addrToIp(gwAddr)

	var nexthops []*netlink.NexthopInfo
	for t := 0; t < nt; t++ {
		ifname := c.tunnelIfname(t)
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			return fmt.Errorf("failed to find interface %s: %v", ifname, err)
		}
		nexthops = append(nexthops, &netlink.NexthopInfo{
			LinkIndex: link.Attrs().Index,
			Gw:        gwIP,
			Hops:      0, // equal weight
		})
	}

	// Step 4: Remove the per-device routes and replace with a single
	// multipath route.
	for t := 0; t < nt; t++ {
		ifname := c.tunnelIfname(t)
		link, _ := netlink.LinkByName(ifname)
		if link != nil {
			_ = netlink.RouteDel(&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       &subnetIPNet,
				Scope:     netlink.SCOPE_LINK,
			})
		}
	}

	mpRoute := &netlink.Route{
		Dst:       &subnetIPNet,
		MultiPath: nexthops,
	}
	if err := netlink.RouteReplace(mpRoute); err != nil {
		return fmt.Errorf("failed to add multipath route: %v", err)
	}

	return nil
}

// sendConnectionRequest attempts to send a connection request to the peer
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

// configureWireguard configures WireGuard on the primary tunnel (backwards compat).
func (c *Client) configureWireguard(connectionResponse connectResponse) error {
	return c.configureWireguardTunnel(0, connectionResponse, connectionResponse.ServerListenPort)
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

// DeleteInterface removes all WireGuard tunnel interfaces.
func (c *Client) DeleteInterface() {
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
	err := netlink.LinkDel(link)
	if err != nil {
		log.Printf("error deleting vprox interface %v: %v", ifname, err)
	} else {
		log.Printf("successfully deleted vprox interface %v", ifname)
	}
}

// CheckConnection checks the status of the connection with the wireguard peer,
// and returns true if it is healthy. This sends 3 pings in succession, and blocks
// until they receive a response or the timeout passes.
// Pings are sent through the primary tunnel interface (tunnel 0).
func (c *Client) CheckConnection(timeout time.Duration, cancelCtx context.Context) bool {
	pinger, err := probing.NewPinger(c.wgCidr.Masked().Addr().Next().String())
	if err != nil {
		log.Printf("error creating pinger: %v", err)
		return false
	}

	pinger.InterfaceName = c.Ifname
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
