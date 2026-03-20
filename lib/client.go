package lib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	verifyPollInterval = 100 * time.Millisecond
	verifyStepTimeout  = 10 * time.Second
)

// Client manages a peering connection with with a local WireGuard interface.
type Client struct {
	// Key is the private key of the client.
	Key wgtypes.Key

	// Ifname is the name of the client WireGuard interface.
	Ifname string

	// ServerIp is the public IPv4 address of the server.
	ServerIp netip.Addr

	// Password authenticates the client connection.
	Password string

	// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// Http is used to make connect requests to the server.
	Http *http.Client

	// wgCidr is the current subnet assigned to the WireGuard interface, if any.
	wgCidr netip.Prefix
}

// CreateInterface creates a new interface for wireguard. DeleteInterface() needs
// to be called to clean this up.
func (c *Client) CreateInterface() error {
	link := c.link()

	err := netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("error creating vprox interface: %v", err)
	}

	return nil
}

// Connect attempts to reconnect to the peer. A network interface needs to
// have already been created with CreateInterface() before calling Connect()
func (c *Client) Connect() error {
	resp, err := c.sendConnectionRequest()
	if err != nil {
		return err
	}

	link := c.link()
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("error setting up vprox interface: %v", err)
	}

	err = c.updateInterface(resp)
	if err != nil {
		return err
	}

	err = c.configureWireguard(resp)
	if err != nil {
		return fmt.Errorf("error configuring wireguard interface: %v", err)
	}

	return nil
}

// updateInterface updates the wireguard interface based on the provided connectionResponse
func (c *Client) updateInterface(resp connectResponse) error {
	cidr, err := netip.ParsePrefix(resp.AssignedAddr)
	if err != nil {
		return fmt.Errorf("failed to parse assigned address %v: %v", resp.AssignedAddr, err)
	}

	if cidr != c.wgCidr {
		link := c.link()

		if c.wgCidr.IsValid() {
			oldIpnet := prefixToIPNet(c.wgCidr)
			err = netlink.AddrDel(link, &netlink.Addr{IPNet: &oldIpnet})

			if err != nil {
				log.Printf("warning: failed to remove old address from vprox interface when reconnecting: %v", err)
			}
		}

		ipnet := prefixToIPNet(cidr)
		err = netlink.AddrAdd(link, &netlink.Addr{IPNet: &ipnet})
		if err != nil {
			return fmt.Errorf("failed to add new address to vprox interface: %v", err)
		}
		c.wgCidr = cidr
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
		return connectResponse{}, fmt.Errorf("server returned status %v", resp.Status)
	}

	buf, err = io.ReadAll(resp.Body)
	if err != nil {
		return connectResponse{}, fmt.Errorf("failed to read response body: %v", err)
	}

	var respJson connectResponse
	json.Unmarshal(buf, &respJson)
	return respJson, nil
}

// configureWireguard configures the WireGuard peer.
func (c *Client) configureWireguard(connectionResponse connectResponse) error {
	serverPublicKey, err := wgtypes.ParseKey(connectionResponse.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse server public key: %v", err)
	}

	keepalive := 25 * time.Second
	return c.WgClient.ConfigureDevice(c.Ifname, wgtypes.Config{
		PrivateKey:   &c.Key,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: serverPublicKey,
				Endpoint: &net.UDPAddr{
					IP:   addrToIp(c.ServerIp),
					Port: connectionResponse.ServerListenPort,
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

func (c *Client) DeleteInterface() {
	// Delete the WireGuard interface.
	netlink.LinkDel(c.link())
}

func (c *Client) link() *linkWireguard {
	return &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: c.Ifname}}
}

// CheckConnection checks the status of the connection with the wireguard peer,
// and returns true if it is healthy. This sends 3 pings in succession, and blocks
// until they receive a response or the timeout passes.
func (c *Client) CheckConnection(timeout time.Duration, cancelCtx context.Context) bool {
	pinger, err := probing.NewPinger(c.wgCidr.Masked().Addr().Next().String())
	if err != nil {
		log.Printf("error creating pinger: %v", err)
		return false
	}

	pinger.Timeout = timeout
	pinger.Count = 3
	pinger.Interval = 10 * time.Millisecond // Send approximately all at once
	err = pinger.RunWithContext(cancelCtx)  // Blocks until finished.
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

// VerifyInterface mirrors the Rust verify_interface() check: it polls for the
// interface to be UP with an IPv4 address, then waits for a WireGuard
// handshake, then pings the server's tunnel address. Each step retries for up
// to verifyStepTimeout (10 s) with verifyPollInterval (100 ms) between attempts.
func (c *Client) VerifyInterface(ctx context.Context) error {
	// Step 1: interface UP with an IPv4 address
	if err := waitFor(ctx, verifyStepTimeout, verifyPollInterval, func() error {
		return c.verifyInterfaceUp()
	}); err != nil {
		return fmt.Errorf("wireguard interface %s failed to come up: %w", c.Ifname, err)
	}

	// Step 2: WireGuard handshake completed
	if err := waitFor(ctx, verifyStepTimeout, verifyPollInterval, func() error {
		return c.verifyHandshake()
	}); err != nil {
		return fmt.Errorf("wireguard interface %s failed to handshake: %w", c.Ifname, err)
	}

	// Step 3: ping the server's tunnel address (first usable IP in the subnet)
	peerAddr := c.wgCidr.Masked().Addr().Next()
	if err := waitFor(ctx, verifyStepTimeout, verifyPollInterval, func() error {
		return c.verifyPing(peerAddr)
	}); err != nil {
		return fmt.Errorf("wireguard interface %s failed connectivity ping to %v: %w",
			c.Ifname, peerAddr, err)
	}

	return nil
}

// verifyInterfaceUp checks that the WireGuard interface is in the UP state and
// has an IPv4 address assigned.
func (c *Client) verifyInterfaceUp() error {
	link, err := netlink.LinkByName(c.Ifname)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}
	if link.Attrs().OperState != netlink.OperUp && (link.Attrs().Flags&net.FlagUp) == 0 {
		return fmt.Errorf("interface %s is not UP (state=%v)", c.Ifname, link.Attrs().OperState)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list addresses: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no IPv4 address on interface %s", c.Ifname)
	}
	return nil
}

// verifyHandshake checks that the WireGuard device has completed a handshake
// with at least one peer (i.e. LastHandshakeTime is non-zero).
func (c *Client) verifyHandshake() error {
	dev, err := c.WgClient.Device(c.Ifname)
	if err != nil {
		return fmt.Errorf("failed to get wireguard device: %w", err)
	}
	for _, peer := range dev.Peers {
		if !peer.LastHandshakeTime.IsZero() {
			return nil
		}
	}
	return fmt.Errorf("no completed handshake on interface %s", c.Ifname)
}

// verifyPing sends 3 ICMP pings to the given address through the WireGuard
// interface and returns an error if none are received.
// verifyPing shells out to `ping -I <interface>` to verify connectivity,
// matching the Rust verify_ping implementation. Using -I binds the socket to
// the correct WireGuard interface, which is necessary when multiple interfaces
// all have AllowedIPs 0.0.0.0/0 and would otherwise fight over the routing
// table.
func (c *Client) verifyPing(addr netip.Addr) error {
	cmd := exec.Command("ping",
		"-c", "3",
		"-W", "5",
		"-i", "0.1",
		"-q",
		"-I", c.Ifname,
		addr.String(),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ping to %v via %s failed: %s", addr, c.Ifname, strings.TrimSpace(string(output)))
	}
	return nil
}

// waitFor retries check until it succeeds, the timeout expires, or ctx is
// cancelled. It mirrors the Rust wait_for helper.
func waitFor(ctx context.Context, timeout, interval time.Duration, check func() error) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		lastErr = check()
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
	return fmt.Errorf("timed out after %v: %w", timeout, lastErr)
}
