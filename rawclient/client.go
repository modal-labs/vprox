package rawclient

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
)

// This file is the wgctrl-free counterpart of lib/client.go, written as free
// functions parametrized by the data they act on instead of methods on a
// Client object. The only piece of mutable state is the currently assigned
// tunnel CIDR, which callers thread through Connect explicitly.

// KeepaliveInterval is the WireGuard persistent keepalive used for the server peer.
const KeepaliveInterval = 25 * time.Second

// ConnectionError reports whether a connection failure is recoverable.
type ConnectionError struct {
	Message     string
	Recoverable bool
}

func (e *ConnectionError) Error() string {
	return e.Message
}

// IsRecoverableError returns false if the error is a ConnectionError that is
// not recoverable.
func IsRecoverableError(err error) bool {
	var connErr *ConnectionError
	if errors.As(err, &connErr) {
		return connErr.Recoverable
	}
	return true
}

type connectRequest struct {
	PeerPublicKey string
}

type connectResponse struct {
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

// Connect performs one (re)connection attempt: it asks the server for a peer
// slot, brings the interface up, updates the interface address if the
// assignment changed, and configures the kernel WireGuard device.
//
// oldCidr is the CIDR currently assigned to the interface (zero value if
// none); the returned prefix is the now-current CIDR and must be passed to
// the next Connect and to CheckConnection.
func Connect(
	httpClient *http.Client,
	serverIp netip.Addr,
	token string,
	privateKey Key,
	ifname string,
	oldCidr netip.Prefix,
) (netip.Prefix, error) {
	resp, err := sendConnectionRequest(httpClient, serverIp, token, privateKey)
	if err != nil {
		return oldCidr, err
	}

	if err := netlink.LinkSetUp(link(ifname)); err != nil {
		return oldCidr, fmt.Errorf("error setting up vprox interface: %v", err)
	}

	newCidr, err := updateInterfaceAddr(ifname, oldCidr, resp.AssignedAddr)
	if err != nil {
		return oldCidr, err
	}

	serverPublicKey, err := ParseKey(resp.ServerPublicKey)
	if err != nil {
		return newCidr, fmt.Errorf("failed to parse server public key: %v", err)
	}
	err = ConfigureWireguardDevice(
		ifname,
		privateKey,
		serverPublicKey,
		serverIp.AsSlice(),
		resp.ServerListenPort,
		KeepaliveInterval,
	)
	if err != nil {
		return newCidr, fmt.Errorf("error configuring wireguard interface: %v", err)
	}

	return newCidr, nil
}

// updateInterfaceAddr ensures the interface carries the newly assigned
// address. If the assignment differs from oldCidr, the old address (if any)
// is removed and the new one added. Returns the now-current CIDR.
func updateInterfaceAddr(ifname string, oldCidr netip.Prefix, assignedAddr string) (netip.Prefix, error) {
	cidr, err := netip.ParsePrefix(assignedAddr)
	if err != nil {
		return oldCidr, fmt.Errorf("failed to parse assigned address %v: %v", assignedAddr, err)
	}

	if cidr == oldCidr {
		return oldCidr, nil
	}

	l := link(ifname)
	if oldCidr.IsValid() {
		oldIpnet := prefixToIPNet(oldCidr)
		if err := netlink.AddrDel(l, &netlink.Addr{IPNet: &oldIpnet}); err != nil {
			log.Printf("warning: failed to remove old address from vprox interface when reconnecting: %v", err)
		}
	}

	ipnet := prefixToIPNet(cidr)
	if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: &ipnet}); err != nil {
		return oldCidr, fmt.Errorf("failed to add new address to vprox interface: %v", err)
	}
	return cidr, nil
}

// sendConnectionRequest POSTs /connect to the server, authenticating with
// token and identifying this peer by the public key of privateKey.
func sendConnectionRequest(
	httpClient *http.Client,
	serverIp netip.Addr,
	token string,
	privateKey Key,
) (connectResponse, error) {
	connectUrl, err := url.Parse(fmt.Sprintf("https://%s/connect", serverIp))
	if err != nil {
		return connectResponse{}, fmt.Errorf("failed to parse connect URL: %v", err)
	}

	buf, err := json.Marshal(&connectRequest{
		PeerPublicKey: KeyString(PublicKey(privateKey)),
	})
	if err != nil {
		return connectResponse{}, fmt.Errorf("failed to marshal connect request: %v", err)
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

// Disconnect notifies the server that this client is disconnecting, allowing
// the server to immediately reclaim resources (wireguard peer and subnet IP)
// instead of waiting for the idle timeout.
func Disconnect(httpClient *http.Client, serverIp netip.Addr, token string, privateKey Key) error {
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

// CheckConnection checks the health of the tunnel by pinging the server's
// tunnel-internal address (the first host of the assigned subnet wgCidr)
// through interface ifname. It sends 3 pings in quick succession and blocks
// until they receive a response or the timeout passes; healthy means at
// least one response arrived.
func CheckConnection(ifname string, wgCidr netip.Prefix, timeout time.Duration, cancelCtx context.Context) bool {
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
