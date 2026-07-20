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

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
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

// Client manages a peering connection with with a local WireGuard interface.
type Client struct {
	// Key is the private key of the client.
	Key wgtypes.Key

	// Ifname is the name of the client WireGuard interface.
	Ifname string

	// ServerIp is the public IPv4 address of the server.
	ServerIp netip.Addr

	// Token is the bearer token used to authenticate with the server.
	// In password mode, this is the VPROX_PASSWORD value.
	// In oidc-modal mode, this is the VPROX_OIDC_TOKEN value.
	Token string

	// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// Http is used to make connect requests to the server.
	Http *http.Client

	// wgCidr is the current subnet assigned to the WireGuard interface, if any.
	wgCidr netip.Prefix

	// serverKey is the public key of the server peer, used to locate it among
	// the interface's peers when reading connection health from the kernel.
	serverKey wgtypes.Key

	// tunnelSelf and tunnelPeer are our address and the server's address
	// inside the tunnel.
	tunnelSelf netip.Addr
	tunnelPeer netip.Addr

	// Liveness state, reset whenever the peer is reconfigured.
	lastRxBytes int64
	probeSeq    int
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

	// The vprox server always sits at the first usable address in the subnet.
	c.tunnelSelf = cidr.Addr()
	c.tunnelPeer = cidr.Masked().Addr().Next()

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
			"Authorization": []string{"Bearer " + c.Token},
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

// configureWireguard configures the WireGuard peer.
func (c *Client) configureWireguard(connectionResponse connectResponse) error {
	serverPublicKey, err := wgtypes.ParseKey(connectionResponse.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse server public key: %v", err)
	}

	c.serverKey = serverPublicKey

	// Replacing the peer resets its counters and handshake state, so the
	// liveness tracking has to start over with it.
	c.lastRxBytes = 0

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
			"Authorization": []string{"Bearer " + c.Token},
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

func (c *Client) DeleteInterface() {
	// Delete the WireGuard interface.
	log.Printf("About to delete vprox interface %v", c.Ifname)
	err := netlink.LinkDel(c.link())
	if err != nil {
		log.Printf("error deleting vprox interface %v: %v", c.Ifname, err)
	} else {
		log.Printf("successfully deleted vprox interface %v", c.Ifname)
	}
}

func (c *Client) link() *linkWireguard {
	return &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: c.Ifname}}
}

// SessionExpiry bounds how stale the last handshake may be before the
// connection is considered dead.
//
// WireGuard refuses to use a session older than REJECT_AFTER_TIME (180s), and
// a peer with traffic to send rekeys once the session passes REKEY_AFTER_TIME
// (120s). Because we configure a persistent keepalive there is always traffic
// to send, so a healthy peer's last handshake never ages much beyond 120s.
const SessionExpiry = 180 * time.Second

// handshakePollInterval is how often the kernel is polled while waiting for the
// first handshake to land.
const handshakePollInterval = 100 * time.Millisecond

// LivenessProbeTimeout is how long to wait for a probe reply before probing
// again. Replies on an established tunnel arrive in about 100ms, so this leaves
// several times the headroom needed for a cross-region path.
const LivenessProbeTimeout = 500 * time.Millisecond

// LivenessFailureThreshold is how many probes in a row must go unanswered
// before the tunnel is declared dead. Several are required because isolated
// packet loss must not tear down a working session: reconnecting replaces the
// peer and discards a perfectly good handshake.
const LivenessFailureThreshold = 4

// serverPeer returns the kernel's view of the server peer on our interface.
func (c *Client) serverPeer() (wgtypes.Peer, error) {
	device, err := c.WgClient.Device(c.Ifname)
	if err != nil {
		return wgtypes.Peer{}, fmt.Errorf("failed to read wireguard device %v: %v", c.Ifname, err)
	}
	for _, peer := range device.Peers {
		if peer.PublicKey == c.serverKey {
			return peer, nil
		}
	}
	return wgtypes.Peer{}, fmt.Errorf("server peer is not configured on %v", c.Ifname)
}

// CheckConnection reports whether the tunnel is currently carrying traffic.
//
// Health comes from the counters the WireGuard kernel module exposes. The
// server never sends anything unsolicited, though, so a healthy idle tunnel and
// a tunnel whose peer the server has forgotten look identical until the session
// ages out around 125s. Rather than wait that out, a tunnel that has gone quiet
// is probed: each probe is an echo request whose reply is observed as growth in
// the peer's receive counter, never read from a socket.
//
// Any traffic at all satisfies the check, so a busy tunnel is never probed.
func (c *Client) CheckConnection(cancelCtx context.Context) bool {
	peer, err := c.serverPeer()
	if err != nil {
		log.Printf("healthcheck: %v", err)
		return false
	}
	if peer.LastHandshakeTime.IsZero() {
		return false
	}
	// WireGuard refuses to use a session this old, so no probe could succeed.
	if time.Since(peer.LastHandshakeTime) > SessionExpiry {
		return false
	}
	if peer.ReceiveBytes > c.lastRxBytes {
		c.lastRxBytes = peer.ReceiveBytes
		return true
	}

	// The tunnel has been quiet since the last check. Establish whether the far
	// side is still answering before declaring it dead.
	for i := 0; i < LivenessFailureThreshold; i++ {
		if err := c.sendLivenessProbe(); err != nil {
			log.Printf("healthcheck: failed to send liveness probe: %v", err)
		}

		select {
		case <-cancelCtx.Done():
			return false
		case <-time.After(LivenessProbeTimeout):
		}

		peer, err := c.serverPeer()
		if err != nil {
			log.Printf("healthcheck: %v", err)
			return false
		}
		if peer.ReceiveBytes > c.lastRxBytes {
			c.lastRxBytes = peer.ReceiveBytes
			return true
		}
	}
	return false
}

// sendLivenessProbe emits a single echo request to the server's tunnel address.
// The reply is never read: it is observed as growth in the peer's receive
// counter on the next health check, which keeps this non-blocking.
func (c *Client) sendLivenessProbe() error {
	if !c.tunnelPeer.IsValid() || !c.tunnelSelf.IsValid() {
		return fmt.Errorf("tunnel addresses are not configured")
	}

	conn, err := icmp.ListenPacket("ip4:icmp", c.tunnelSelf.String())
	if err != nil {
		return err
	}
	defer conn.Close()

	c.probeSeq++
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  c.probeSeq & 0xffff,
			Data: []byte("vprox"),
		},
	}
	buf, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(buf, &net.IPAddr{IP: net.IP(c.tunnelPeer.AsSlice())})
	return err
}

// WaitForHandshake blocks until the tunnel completes its first handshake, the
// timeout expires, or the context is cancelled.
//
// A handshake initiation that is lost in transit is not retried by WireGuard
// until REKEY_TIMEOUT (5s), so the timeout must span several of those retries
// for a single dropped packet not to fail the connection.
func (c *Client) WaitForHandshake(timeout time.Duration, cancelCtx context.Context) bool {
	deadline := time.Now().Add(timeout)
	for {
		peer, err := c.serverPeer()
		if err != nil {
			log.Printf("waiting for handshake: %v", err)
		} else if !peer.LastHandshakeTime.IsZero() {
			return true
		}

		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-cancelCtx.Done():
			return false
		case <-time.After(handshakePollInterval):
		}
	}
}
