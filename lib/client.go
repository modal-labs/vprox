package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

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

	// Password is authenticates the client connection.
	Password string

	// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// Http is used to make connect requests to the server.
	Http *http.Client
}

func (c *Client) CreateInterface() error {
	connectUrl, err := url.Parse(fmt.Sprintf("https://%s/connect", c.ServerIp))
	if err != nil {
		return fmt.Errorf("failed to parse connect URL: %v", err)
	}

	reqJson := &connectRequest{
		PeerPublicKey: c.Key.PublicKey().String(),
	}
	buf, err := json.Marshal(reqJson)
	if err != nil {
		return fmt.Errorf("failed to marshal connect request: %v", err)
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
		return fmt.Errorf("failed to connect to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %v", resp.Status)
	}

	buf, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	var respJson connectResponse
	json.Unmarshal(buf, &respJson)

	cidr, err := netip.ParsePrefix(respJson.AssignedAddr)
	if err != nil {
		return fmt.Errorf("failed to parse assigned address %v: %v", respJson.AssignedAddr, err)
	}

	serverPublicKey, err := wgtypes.ParseKey(respJson.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse server public key: %v", err)
	}

	// Create a new WireGuard interface.
	link := c.link()
	err = netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("error creating vprox interface: %v", err)
	}

	// Configure the WireGuard interface.
	ipnet := prefixToIPNet(cidr)
	err = netlink.AddrAdd(link, &netlink.Addr{IPNet: &ipnet})
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("error adding IP to vprox interface: %v", err)
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("error setting up vprox interface: %v", err)
	}

	// Configure the WireGuard peer.
	keepalive := 25 * time.Second
	err = c.WgClient.ConfigureDevice(c.Ifname, wgtypes.Config{
		PrivateKey:   &c.Key,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: serverPublicKey,
				Endpoint: &net.UDPAddr{
					IP:   addrToIp(c.ServerIp),
					Port: respJson.ServerListenPort,
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
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("error configuring vprox interface: %v", err)
	}

	return nil
}

func (c *Client) DeleteInterface() {
	// Delete the WireGuard interface.
	netlink.LinkDel(c.link())
}

func (c *Client) link() *linkWireguard {
	return &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: c.Ifname}}
}
