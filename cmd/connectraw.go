// Command connect-raw is a wgctrl-free variant of the vprox client
// (cmd/connect.go + lib/client.go), flattened into a single file. It is
// written as free functions parametrized by the data they operate on, and
// talks to the kernel WireGuard module directly over generic netlink,
// implementing only the narrow slice of functionality that the vprox client
// actually uses.
//
// Linux-only.
package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
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
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/mdlayher/genetlink"
	mnetlink "github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	probing "github.com/prometheus-community/pro-bing"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"

	"github.com/modal-labs/vprox/lib"
)

// ConnectRawCmd is a wgctrl-free variant of ConnectCmd, built on the
// rawclient package's free functions. It exists to map out exactly what a
// minimal client implementation needs.
var ConnectRawCmd = &cobra.Command{
	Use:        "connect-raw [flags] <ip>",
	Short:      "Peer a client connection to a VPN server (wgctrl-free variant)",
	Args:       cobra.ExactArgs(1),
	ArgAliases: []string{"ip"},
	RunE:       runConnectRaw,
}

var connectRawCmdArgs struct {
	ifname string
}

func init() {
	ConnectRawCmd.Flags().StringVar(&connectRawCmdArgs.ifname, "interface",
		"vprox0", "Interface name to proxy traffic through the VPN")
}

// waitForHealthyConnectionRaw sends pings to the vprox server over the
// wireguard tunnel until one succeeds or the deadline is exceeded.
func waitForHealthyConnectionRaw(ctx context.Context, ifname string, wgCidr netip.Prefix) bool {
	// Retry failed healthchecks for up to 20s before declaring the connection unhealthy.
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for {
		if SendPingsThroughTunnel(ifname, wgCidr, healthCheckTimeout, ctx) {
			return true
		}
		log.Printf("health check failed, retrying...")
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func runConnectRaw(cmd *cobra.Command, args []string) error {
	serverIp, err := netip.ParseAddr(args[0])
	if err != nil || !serverIp.Is4() {
		return fmt.Errorf("invalid IP address %s", args[0])
	}

	ifname := connectRawCmdArgs.ifname

	key, err := LoadOrGenerateClientKey(ifname)
	if err != nil {
		return fmt.Errorf("failed to load client key: %v", err)
	}

	token, err := lib.GetClientToken()
	if err != nil {
		return err
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     dialWithRetry,
		},
	}

	// Protect resource-cleanup work (executed in defer statements below) by
	// registering a signal handler. We make sure that cleanup work is done when
	// we receive a SIGINT/SIGKILL.
	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	if err = CreateInterface(ifname); err != nil {
		return err
	}
	defer DeleteInterface(ifname)

	resp, wgCidr, err := RequestPeerIpFromServer(httpClient, serverIp, token, key)
	if err != nil {
		return err
	}
	// Notify the server when we disconnect so it can reclaim resources immediately.
	defer func() {
		log.Println("About send /disconnect request to server.")
		if err := sendDisconnectRequest(httpClient, serverIp, token, key); err != nil {
			log.Printf("warning: failed to disconnect from server: %v", err)
		}
	}()
	if err = netlink.LinkSetUp(link(ifname)); err != nil {
		return fmt.Errorf("error setting up vprox interface: %v", err)
	}
	if err = AddAddressToInterface(ifname, wgCidr); err != nil {
		return err
	}
	serverPublicKey, err := ParseKey(resp.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse server public key: %v", err)
	}
	err = ConfigureWireguardDevice(ifname, key, serverPublicKey,
		serverIp.AsSlice(), resp.ServerListenPort, KeepaliveInterval)
	if err != nil {
		return fmt.Errorf("error configuring wireguard interface: %v", err)
	}

	log.Println("Connected...")
	if !waitForHealthyConnectionRaw(ctx, ifname, wgCidr) {
		return fmt.Errorf("connection failed initial healthcheck")
	}

	for {
		// currently in a healthy state
		select {
		case <-ctx.Done():
			log.Println("Context is Done. Returning from runConnectRaw.")
			return nil
		case <-time.After(healthCheckInterval):
		}

		atLeastOnePingSucceeded := SendPingsThroughTunnel(ifname, wgCidr, healthCheckTimeout, ctx)

		if !atLeastOnePingSucceeded {
			log.Println("No longer connected. Attempting to reconnect...")
		unhealthy_loop:
			for {
				// currently in an unhealthy state
				var (
					resp    ConnectResponse
					newCidr netip.Prefix
				)
				resp, newCidr, err = RequestPeerIpFromServer(httpClient, serverIp, token, key)
				if err != nil {
					if !IsRecoverableError(err) {
						return fmt.Errorf("unrecoverable connection error: %w", err)
					}
					goto retry
				}
				if err = netlink.LinkSetUp(link(ifname)); err != nil {
					err = fmt.Errorf("error setting up vprox interface: %v", err)
					goto retry
				}
				if newCidr != wgCidr {
					RemoveAddressFromInterface(ifname, wgCidr)
					if err = AddAddressToInterface(ifname, newCidr); err != nil {
						goto retry
					}
					wgCidr = newCidr
				}
				serverPublicKey, err = ParseKey(resp.ServerPublicKey)
				if err != nil {
					err = fmt.Errorf("failed to parse server public key: %v", err)
					goto retry
				}
				err = ConfigureWireguardDevice(ifname, key, serverPublicKey,
					serverIp.AsSlice(), resp.ServerListenPort, KeepaliveInterval)
				if err != nil {
					err = fmt.Errorf("error configuring wireguard interface: %v", err)
					goto retry
				}
				log.Println("Reconnected...")
				break unhealthy_loop

			retry:
				log.Printf("Failed to reconnect: %v", err)
				select {
				case <-ctx.Done():
					log.Println("Context is Done; received SIGINT or SIGTERM. Breaking out of unhealthy_loop.")
					break unhealthy_loop
				case <-time.After(reconnectInterval):
				}
			}
		}
	}
}

// KeyLen is the length in bytes of a WireGuard Curve25519 key.
const KeyLen = 32

// Key is a WireGuard private or public key (raw Curve25519 bytes).
type Key [KeyLen]byte

// GeneratePrivateKey returns a new clamped Curve25519 private key.
func GeneratePrivateKey() (Key, error) {
	var key Key
	if _, err := rand.Read(key[:]); err != nil {
		return Key{}, fmt.Errorf("failed to read random bytes: %v", err)
	}
	// Standard Curve25519 clamping, as done by wireguard-tools.
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}

// PublicKey computes the public key corresponding to private key priv.
func PublicKey(priv Key) Key {
	var pub Key
	p, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(pub[:], p)
	return pub
}

// KeyString returns the base64 encoding of key, as used on the wire and in
// key files.
func KeyString(key Key) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// ParseKey parses a base64-encoded key.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("failed to parse key: %v", err)
	}
	if len(b) != KeyLen {
		return Key{}, fmt.Errorf("incorrect key size: %d", len(b))
	}
	var key Key
	copy(key[:], b)
	return key, nil
}

// runDir is the path for runtime data that should be kept across restarts.
const runDir = "/run/vprox"

// LoadOrGenerateClientKey returns the persisted client private key for the
// given interface, generating and persisting a new one on first use.
// The key lives at /run/vprox/client-key-<ifname>.
func LoadOrGenerateClientKey(ifname string) (Key, error) {
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return Key{}, err
	}
	keyFile := path.Join(runDir, "client-key-"+ifname)
	contents, err := os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		key, err := GeneratePrivateKey()
		if err != nil {
			return Key{}, err
		}
		if err = os.WriteFile(keyFile, []byte(KeyString(key)), 0600); err != nil {
			return Key{}, err
		}
		return key, nil
	} else if err != nil {
		return Key{}, err
	}
	return ParseKey(strings.TrimSpace(string(contents)))
}

// ConfigureWireguardDevice configures the WireGuard device named ifname the
// specific way the vprox client uses it, via a single WG_CMD_SET_DEVICE
// generic netlink request:
//
//   - set the device private key
//   - replace all peers with a single server peer, identified by
//     serverPublicKey, reachable at endpoint (IPv4 UDP), with a persistent
//     keepalive and allowed IPs replaced by 0.0.0.0/0 (route everything).
//
// This is the wgctrl-free equivalent of
// wgctrl.Client.ConfigureDevice(ifname, wgtypes.Config{...}) as called from
// lib/client.go configureWireguard.
func ConfigureWireguardDevice(
	ifname string,
	privateKey Key,
	serverPublicKey Key,
	endpointIp net.IP,
	endpointPort int,
	keepalive time.Duration,
) error {
	attrs, err := encodeSetDeviceRequest(ifname, privateKey, serverPublicKey, endpointIp, endpointPort, keepalive)
	if err != nil {
		return err
	}

	// Dial a generic netlink socket and resolve the "wireguard" family, whose
	// numeric ID addresses the kernel WireGuard module.
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("failed to dial generic netlink: %v", err)
	}
	defer conn.Close()

	family, err := conn.GetFamily(unix.WG_GENL_NAME)
	if err != nil {
		return fmt.Errorf("wireguard generic netlink family unavailable (is the wireguard module loaded?): %v", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: unix.WG_CMD_SET_DEVICE,
			Version: unix.WG_GENL_VERSION,
		},
		Data: attrs,
	}
	if _, err := conn.Execute(msg, family.ID, mnetlink.Request|mnetlink.Acknowledge); err != nil {
		return fmt.Errorf("WG_CMD_SET_DEVICE failed: %w", err)
	}
	return nil
}

// encodeSetDeviceRequest encodes the netlink attribute payload for the
// WG_CMD_SET_DEVICE request described in ConfigureWireguardDevice.
func encodeSetDeviceRequest(
	ifname string,
	privateKey Key,
	serverPublicKey Key,
	endpointIp net.IP,
	endpointPort int,
	keepalive time.Duration,
) ([]byte, error) {
	ip4 := endpointIp.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("endpoint IP %v is not IPv4", endpointIp)
	}

	ae := mnetlink.NewAttributeEncoder()
	ae.String(unix.WGDEVICE_A_IFNAME, ifname)
	ae.Bytes(unix.WGDEVICE_A_PRIVATE_KEY, privateKey[:])
	// Wipe any existing peers; the client only ever has the one server peer.
	ae.Uint32(unix.WGDEVICE_A_FLAGS, unix.WGDEVICE_F_REPLACE_PEERS)

	ae.Nested(unix.WGDEVICE_A_PEERS, func(nae *mnetlink.AttributeEncoder) error {
		// Netlink arrays use the attribute type as an array index.
		nae.Nested(0, func(pae *mnetlink.AttributeEncoder) error {
			pae.Bytes(unix.WGPEER_A_PUBLIC_KEY, serverPublicKey[:])
			pae.Uint32(unix.WGPEER_A_FLAGS, unix.WGPEER_F_REPLACE_ALLOWEDIPS)
			pae.Do(unix.WGPEER_A_ENDPOINT, func() ([]byte, error) {
				var addr [4]byte
				copy(addr[:], ip4)
				sa := unix.RawSockaddrInet4{
					Family: unix.AF_INET,
					Port:   sockaddrPort(endpointPort),
					Addr:   addr,
				}
				return (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:], nil
			})
			pae.Uint16(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, uint16(keepalive.Seconds()))
			pae.Nested(unix.WGPEER_A_ALLOWEDIPS, func(aae *mnetlink.AttributeEncoder) error {
				// Single allowed IP: 0.0.0.0/0 (all IPv4 traffic).
				aae.Nested(0, func(ipae *mnetlink.AttributeEncoder) error {
					ipae.Uint16(unix.WGALLOWEDIP_A_FAMILY, unix.AF_INET)
					ipae.Bytes(unix.WGALLOWEDIP_A_IPADDR, net.IPv4zero.To4())
					ipae.Uint8(unix.WGALLOWEDIP_A_CIDR_MASK, 0)
					return nil
				})
				return nil
			})
			return nil
		})
		return nil
	})

	return ae.Encode()
}

// sockaddrPort interprets port as a big endian uint16 for use in sockaddr
// structures passed to the kernel.
func sockaddrPort(port int) uint16 {
	return binary.BigEndian.Uint16(nlenc.Uint16Bytes(uint16(port)))
}

// This file is the wgctrl-free counterpart of lib/client.go, written as free
// functions parametrized by the data they act on instead of methods on a
// Client object. The only piece of mutable state is the currently assigned
// tunnel CIDR, which callers thread through Connect explicitly.

// KeepaliveInterval is the WireGuard persistent keepalive used for the server peer.
const KeepaliveInterval = 25 * time.Second

// ConnectError reports whether a connection failure is recoverable.
type ConnectError struct {
	Message     string
	Recoverable bool
}

func (e *ConnectError) Error() string {
	return e.Message
}

// IsRecoverableError returns false if the error is a ConnectError that is
// not recoverable.
func IsRecoverableError(err error) bool {
	var connErr *ConnectError
	if errors.As(err, &connErr) {
		return connErr.Recoverable
	}
	return true
}

type connectRequest struct {
	PeerPublicKey string
}

type ConnectResponse struct {
	AssignedAddr     string
	ServerPublicKey  string
	ServerListenPort int
}

type disconnectRequest struct {
	PeerPublicKey string
}

// wgLink is the netlink link object for a WireGuard interface named ifname.
// Creating a link of Type() "wireguard" makes the kernel WireGuard module
// back the device.
type wgLink struct {
	netlink.LinkAttrs
}

func (l *wgLink) Attrs() *netlink.LinkAttrs { return &l.LinkAttrs }
func (l *wgLink) Type() string              { return "wireguard" }

func link(ifname string) *wgLink {
	return &wgLink{LinkAttrs: netlink.LinkAttrs{Name: ifname}}
}

// CreateInterface creates the WireGuard network interface named ifname.
// DeleteInterface must be called to clean it up.
func CreateInterface(ifname string) error {
	if err := netlink.LinkAdd(link(ifname)); err != nil {
		return fmt.Errorf("error creating vprox interface: %v", err)
	}
	return nil
}

// DeleteInterface deletes the WireGuard interface named ifname.
func DeleteInterface(ifname string) {
	log.Printf("About to delete vprox interface %v", ifname)
	if err := netlink.LinkDel(link(ifname)); err != nil {
		log.Printf("error deleting vprox interface %v: %v", ifname, err)
	} else {
		log.Printf("successfully deleted vprox interface %v", ifname)
	}
}

// RequestPeerIpFromServer registers this client as a peer with the server via
// POST /connect and parses the assigned CIDR from the response. The returned
// response also carries the server's public key and WireGuard listen port,
// needed to configure the device via ConfigureWireguardDevice.
func RequestPeerIpFromServer(
	httpClient *http.Client,
	serverIp netip.Addr,
	token string,
	privateKey Key,
) (ConnectResponse, netip.Prefix, error) {
	resp, err := sendConnectRequest(httpClient, serverIp, token, privateKey)
	if err != nil {
		return ConnectResponse{}, netip.Prefix{}, err
	}
	cidr, err := netip.ParsePrefix(resp.AssignedAddr)
	if err != nil {
		return ConnectResponse{}, netip.Prefix{}, fmt.Errorf("failed to parse assigned address %v: %v", resp.AssignedAddr, err)
	}
	return resp, cidr, nil
}

// AddAddressToInterface adds cidr as an address of interface ifname.
func AddAddressToInterface(ifname string, cidr netip.Prefix) error {
	ipnet := prefixToIPNet(cidr)
	if err := netlink.AddrAdd(link(ifname), &netlink.Addr{IPNet: &ipnet}); err != nil {
		return fmt.Errorf("failed to add new address to vprox interface: %v", err)
	}
	return nil
}

// RemoveAddressFromInterface removes cidr as an address of interface ifname,
// logging a warning on failure.
func RemoveAddressFromInterface(ifname string, cidr netip.Prefix) {
	ipnet := prefixToIPNet(cidr)
	if err := netlink.AddrDel(link(ifname), &netlink.Addr{IPNet: &ipnet}); err != nil {
		log.Printf("warning: failed to remove old address from vprox interface when reconnecting: %v", err)
	}
}

// sendConnectRequest POSTs /connect to the server, authenticating with
// token and identifying this peer by the public key of privateKey.
func sendConnectRequest(
	httpClient *http.Client,
	serverIp netip.Addr,
	token string,
	privateKey Key,
) (ConnectResponse, error) {
	connectUrl, err := url.Parse(fmt.Sprintf("https://%s/connect", serverIp))
	if err != nil {
		return ConnectResponse{}, fmt.Errorf("failed to parse connect URL: %v", err)
	}

	buf, err := json.Marshal(&connectRequest{
		PeerPublicKey: KeyString(PublicKey(privateKey)),
	})
	if err != nil {
		return ConnectResponse{}, fmt.Errorf("failed to marshal connect request: %v", err)
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    connectUrl,
		Header: http.Header{
			"Authorization": []string{"Bearer " + token},
		},
		Body: io.NopCloser(bytes.NewBuffer(buf)),
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return ConnectResponse{}, fmt.Errorf("failed to connect to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		recoverable := resp.StatusCode != http.StatusUnauthorized
		return ConnectResponse{}, &ConnectError{
			Message:     fmt.Sprintf("server returned status %v", resp.Status),
			Recoverable: recoverable,
		}
	}

	buf, err = io.ReadAll(resp.Body)
	if err != nil {
		return ConnectResponse{}, fmt.Errorf("failed to read response body: %v", err)
	}

	var respJson ConnectResponse
	json.Unmarshal(buf, &respJson)
	return respJson, nil
}

// sendDisconnectRequest notifies the server that this client is disconnecting, allowing
// the server to immediately reclaim resources (wireguard peer and subnet IP)
// instead of waiting for the idle timeout.
func sendDisconnectRequest(httpClient *http.Client, serverIp netip.Addr, token string, privateKey Key) error {
	disconnectUrl, err := url.Parse(fmt.Sprintf("https://%s/disconnect", serverIp))
	if err != nil {
		return fmt.Errorf("failed to parse disconnect URL: %v", err)
	}

	buf, err := json.Marshal(&disconnectRequest{
		PeerPublicKey: KeyString(PublicKey(privateKey)),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal disconnect request: %v", err)
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    disconnectUrl,
		Header: http.Header{
			"Authorization": []string{"Bearer " + token},
		},
		Body: io.NopCloser(bytes.NewBuffer(buf)),
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send disconnect request to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %v for disconnect request", resp.Status)
	}

	log.Printf("successfully disconnected from server %v", serverIp)
	return nil
}

// SendPingsThroughTunnel checks the health of the tunnel by pinging the server's
// tunnel-internal address (the first host of the assigned subnet wgCidr)
// through interface ifname. It sends 3 pings in quick succession and blocks
// until they receive a response or the timeout passes; healthy means at
// least one response arrived.
func SendPingsThroughTunnel(ifname string, wgCidr netip.Prefix, timeout time.Duration, cancelCtx context.Context) bool {
	pinger, err := probing.NewPinger(wgCidr.Masked().Addr().Next().String())
	if err != nil {
		log.Printf("error creating pinger: %v", err)
		return false
	}

	pinger.InterfaceName = ifname
	pinger.Timeout = timeout
	pinger.Count = 3
	pinger.Interval = 10 * time.Millisecond // Send approximately all at once
	if err := pinger.RunWithContext(cancelCtx); err != nil {
		log.Printf("error running pinger: %v", err)
		return false
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 && stats.PacketsRecv < stats.PacketsSent {
		log.Printf("warning: %v of %v packets in ping were dropped", stats.PacketsSent-stats.PacketsRecv, stats.PacketsSent)
	}
	return stats.PacketsRecv > 0
}

// prefixToIPNet converts a netip.Prefix to a net.IPNet.
func prefixToIPNet(p netip.Prefix) net.IPNet {
	return net.IPNet{
		IP:   p.Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}
