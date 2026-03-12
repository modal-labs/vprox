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
	"os"
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

// Client manages a peering connection with a local WireGuard interface, or a
// set of parallel WireGuard interfaces bonded together when multi-tunnel is
// enabled.
//
// Single-tunnel (NumTunnels <= 1):
//
//	Applications use "vprox0" which is a plain WireGuard interface.
//
// Multi-tunnel (NumTunnels > 1):
//
//	WireGuard slaves: vprox0t0, vprox0t1, vprox0t2, ...
//	Bond master:      vprox0  (balance-rr, presents a single interface)
//
//	Applications bind to "vprox0" and the bonding driver distributes packets
//	round-robin across the WireGuard slaves. Each slave uses a different UDP
//	port to the server, so the NIC hashes them to different hardware RX queues.
type Client struct {
	// Key is the private key of the client.
	Key wgtypes.Key

	// Ifname is the name of the interface exposed to applications (e.g. "vprox0").
	// In multi-tunnel mode this is the bond device; individual WireGuard tunnels
	// are named <Ifname>t0, <Ifname>t1, etc.
	Ifname string

	// ServerIp is the public IPv4 address of the server.
	ServerIp netip.Addr

	// Password authenticates the client connection.
	Password string

	// NumTunnels is the number of parallel WireGuard tunnels to create.
	// When <= 1, the client creates a single plain WireGuard interface.
	// When > 1, a bonding device is created over N WireGuard slaves.
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
//   - Multi-tunnel:  N WireGuard interfaces + a bond master named Ifname.
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

	// In multi-tunnel mode, create a bond over the WireGuard slaves.
	if c.isMultiTunnel() {
		if err := c.createBond(nt); err != nil {
			for t := 0; t < nt; t++ {
				c.deleteTunnelInterface(t)
			}
			return err
		}
		log.Printf("created bond %s over %d tunnel slaves (%s .. %s)",
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

	// In multi-tunnel mode the slaves are brought up later when enslaved
	// to the bond. In single-tunnel mode we don't bring it up yet either
	// — Connect() will do it.

	return nil
}

// createBond creates a balance-rr bond device named Ifname and enslaves all
// WireGuard tunnel interfaces to it.
func (c *Client) createBond(nt int) error {
	// Ensure the bonding kernel module is loaded.
	_ = writeSysFile("/sys/module/bonding/initstate", "")

	bond := netlink.NewLinkBond(netlink.LinkAttrs{
		Name:   c.Ifname,
		MTU:    WireguardMTU,
		TxQLen: WireguardTxQLen,
	})
	bond.Mode = netlink.BOND_MODE_BALANCE_RR
	// MIIMon: link monitoring interval in ms. We set a low value so that if
	// a slave goes down, the bond reacts quickly.
	bond.Miimon = 100

	// Remove any stale bond with this name.
	if existing, _ := netlink.LinkByName(c.Ifname); existing != nil {
		_ = netlink.LinkDel(existing)
	}

	if err := netlink.LinkAdd(bond); err != nil {
		return fmt.Errorf("failed to create bond %s: %v", c.Ifname, err)
	}

	// Enslave each WireGuard tunnel interface to the bond.
	bondLink, err := netlink.LinkByName(c.Ifname)
	if err != nil {
		netlink.LinkDel(bond)
		return fmt.Errorf("failed to find bond %s after creation: %v", c.Ifname, err)
	}

	for t := 0; t < nt; t++ {
		slave, err := netlink.LinkByName(c.tunnelIfname(t))
		if err != nil {
			netlink.LinkDel(bond)
			return fmt.Errorf("failed to find slave %s: %v", c.tunnelIfname(t), err)
		}
		// The slave must be down before enslaving.
		_ = netlink.LinkSetDown(slave)
		if err := netlink.LinkSetMaster(slave, bondLink); err != nil {
			netlink.LinkDel(bond)
			return fmt.Errorf("failed to enslave %s to %s: %v", c.tunnelIfname(t), c.Ifname, err)
		}
	}

	return nil
}

// DeleteInterface removes all interfaces (bond + WireGuard tunnels).
func (c *Client) DeleteInterface() {
	if c.isMultiTunnel() {
		// Deleting the bond master also releases the slaves.
		log.Printf("About to delete bond interface %v", c.Ifname)
		if bond, err := netlink.LinkByName(c.Ifname); err == nil {
			if err := netlink.LinkDel(bond); err != nil {
				log.Printf("error deleting bond %v: %v", c.Ifname, err)
			} else {
				log.Printf("successfully deleted bond %v", c.Ifname)
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

		// Bring the slave up (bond requires slaves to be up for traffic).
		slave := c.tunnelLink(t)
		if err := netlink.LinkSetUp(slave); err != nil {
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
// Pings are sent through the user-facing interface (Ifname — either the plain
// WireGuard device in single-tunnel mode, or the bond in multi-tunnel mode).
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

// ---------------------------------------------------------------------------
// Sysfs helper
// ---------------------------------------------------------------------------

// writeSysFile is a best-effort helper to write a value to a sysfs file.
// Used to poke kernel module parameters. Errors are silently ignored.
func writeSysFile(path, value string) error {
	return os.WriteFile(path, []byte(value), 0644)
}
