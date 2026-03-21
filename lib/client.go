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
	"strings"
	"syscall"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)


const (
	verifyPollInitial = 20 * time.Millisecond
	verifyPollMax     = 200 * time.Millisecond
	verifyUpTimeout   = 5 * time.Second
	verifyPingTimeout = 10 * time.Second
)

// ErrResourceExhausted is returned when the server has reached its maximum
// number of active peers and cannot accept new connections.
var ErrResourceExhausted = errors.New("server at capacity: too many active peers")

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

	// PlainHTTP disables TLS for the control-plane connection. When true,
	// the client uses http:// instead of https:// to reach the server.
	PlainHTTP bool

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
	scheme := "https"
	if c.PlainHTTP {
		scheme = "http"
	}
	connectUrl, err := url.Parse(fmt.Sprintf("%s://%s:443/connect", scheme, c.ServerIp))
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

	if resp.StatusCode == http.StatusTooManyRequests {
		return connectResponse{}, ErrResourceExhausted
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return connectResponse{}, fmt.Errorf("server returned status %v: %s", resp.Status, strings.TrimSpace(string(body)))
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

// VerifyInterface checks the WireGuard interface is functional: UP with an
// IPv4 address and able to ping the server's tunnel endpoint. A successful
// ping implies the handshake completed, so we skip the separate handshake
// polling step (which required expensive Device() netlink calls that
// serialise under contention with 1000+ workers). Retries use exponential
// backoff to reduce contention on kernel resources.
func (c *Client) VerifyInterface(ctx context.Context) error {
	// Step 1: interface UP with an IPv4 address (fast, local check)
	if err := waitForBackoff(ctx, verifyUpTimeout, verifyPollInitial, verifyPollMax, func() error {
		return c.verifyInterfaceUp()
	}); err != nil {
		return fmt.Errorf("wireguard interface %s failed to come up: %w", c.Ifname, err)
	}

	// Step 2: ping the server's tunnel address. A successful ping proves
	// the handshake completed AND the tunnel is functional, so we don't
	// need a separate verifyHandshake step.
	peerAddr := c.wgCidr.Masked().Addr().Next()
	if err := waitForBackoff(ctx, verifyPingTimeout, verifyPollInitial, verifyPollMax, func() error {
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
	var link netlink.Link
	var err error
	for retries := 0; retries < 3; retries++ {
		link, err = netlink.LinkByName(c.Ifname)
		if err == nil || !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}
	if link.Attrs().OperState != netlink.OperUp && (link.Attrs().Flags&net.FlagUp) == 0 {
		return fmt.Errorf("interface %s is not UP (state=%v)", c.Ifname, link.Attrs().OperState)
	}

	var addrs []netlink.Addr
	for retries := 0; retries < 3; retries++ {
		addrs, err = netlink.AddrList(link, netlink.FAMILY_V4)
		if err == nil || !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("failed to list addresses: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no IPv4 address on interface %s", c.Ifname)
	}
	return nil
}

// verifyPing sends a single ICMP echo request to the given address using a
// raw socket bound to the WireGuard interface via SO_BINDTODEVICE. This is
// essential when multiple WireGuard interfaces all have AllowedIPs 0.0.0.0/0.
//
// Uses direct syscalls instead of the probing library to avoid the overhead
// of creating and tearing down pinger objects (DNS resolution, goroutines,
// internal timers) on every attempt — critical when 1000+ workers are
// polling concurrently. Each call opens a socket, sends one packet, waits
// up to 300ms for a reply, and closes the socket.
func (c *Client) verifyPing(addr netip.Addr) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("ping %v via %s: socket: %w", addr, c.Ifname, err)
	}
	defer syscall.Close(fd)

	// Bind to the WireGuard interface so the kernel routes the packet
	// through the correct tunnel.
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.Ifname); err != nil {
		return fmt.Errorf("ping %v via %s: bind: %w", addr, c.Ifname, err)
	}

	// Short receive timeout — we're already inside a retry loop with backoff.
	tv := syscall.Timeval{Sec: 0, Usec: 300000} // 300ms
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Build ICMP echo request using x/net/icmp for correct marshalling.
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("vprox"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("ping %v: marshal: %w", addr, err)
	}

	// Send echo request.
	dst := syscall.SockaddrInet4{}
	dst.Addr = addr.As4()
	if err := syscall.Sendto(fd, wb, 0, &dst); err != nil {
		return fmt.Errorf("ping %v via %s: send: %w", addr, c.Ifname, err)
	}

	// Read reply. Raw ICMP sockets include the IP header in received data.
	rb := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(fd, rb, 0)
	if err != nil {
		return fmt.Errorf("ping %v via %s: no reply: %w", addr, c.Ifname, err)
	}

	// Skip IP header (IHL field × 4 bytes) to get at the ICMP payload.
	if n < 20 {
		return fmt.Errorf("ping %v via %s: response too short (%d bytes)", addr, c.Ifname, n)
	}
	ihl := int(rb[0]&0x0f) * 4
	if n < ihl+8 {
		return fmt.Errorf("ping %v via %s: response too short for ICMP", addr, c.Ifname)
	}

	// Protocol number 1 = ICMPv4.
	rm, err := icmp.ParseMessage(1, rb[ihl:n])
	if err != nil {
		return fmt.Errorf("ping %v via %s: parse: %w", addr, c.Ifname, err)
	}
	if rm.Type != ipv4.ICMPTypeEchoReply {
		return fmt.Errorf("ping %v via %s: got %v, want echo reply", addr, c.Ifname, rm.Type)
	}

	return nil
}

// waitForBackoff retries check with exponential backoff (from initInterval up
// to maxInterval) until it succeeds, the timeout expires, or ctx is cancelled.
// Exponential backoff drastically reduces contention on kernel resources
// (netlink sockets, WireGuard handshake processing) when many workers poll
// concurrently.
func waitForBackoff(ctx context.Context, timeout, initInterval, maxInterval time.Duration, check func() error) error {
	deadline := time.Now().Add(timeout)
	interval := initInterval
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
		// Exponential backoff: double the interval up to the max.
		interval = interval * 2
		if interval > maxInterval {
			interval = maxInterval
		}
	}
	return fmt.Errorf("timed out after %v: %w", timeout, lastErr)
}
