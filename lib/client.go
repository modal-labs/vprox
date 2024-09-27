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
	"syscall"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
		return fmt.Errorf("error reconfiguring vprox interface: %v", err)
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

		if c.wgCidr != (netip.Prefix{}) {
			oldIpnet := prefixToIPNet(c.wgCidr)
			err = netlink.AddrDel(link, &netlink.Addr{IPNet: &oldIpnet})
			if err != nil && !errors.Is(err, syscall.EEXIST) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
				return fmt.Errorf("failed to remove old address from vprox interface: %v", err)
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
	var err error
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
// and returns true if it is healthy. This sends 3 pings, one second apart each, so
// this will block for at least 2 seconds.
func (c *Client) CheckConnection(timeout time.Duration, cancelCtx context.Context) bool {
	pinger, err := probing.NewPinger(c.wgCidr.Masked().Addr().Next().String())
	if err != nil {
		log.Printf("error creating pinger: %v", err)
		return false
	}

	pinger.Timeout = timeout
	pinger.Count = 3
	pinger.Interval = 100 * time.Millisecond
	err = pinger.RunWithContext(cancelCtx) // Blocks until finished.
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
