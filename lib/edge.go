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
	"os"
	"time"

	"github.com/coreos/go-iptables/iptables"
	probing "github.com/prometheus-community/pro-bing"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EdgeClient manages an edge connector that peers with a vprox server and
// acts as an exit node into the local network, forwarding traffic for the
// advertised routes.
type EdgeClient struct {
	// Key is the WireGuard private key of the edge connector.
	Key wgtypes.Key

	// Ifname is the name of the WireGuard interface created on this host.
	Ifname string

	// ServerIp is the public IPv4 address of the vprox server.
	ServerIp netip.Addr

	// Token is the bearer token for authenticating with the server.
	Token string

	// Routes is the list of CIDR prefixes this edge can reach and advertises
	// to the server so that connect-peers can access them.
	Routes []netip.Prefix

	// WgClient is used to interact with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// Http is the HTTP client for control-plane requests.
	Http *http.Client

	// wgCidr is the WireGuard address assigned by the server.
	wgCidr netip.Prefix

	// defaultIface is the host's default network interface, used as the
	// outbound interface for masqueraded traffic.
	defaultIface netlink.Link

	// ipt is the iptables handle for managing forwarding / NAT rules.
	ipt *iptables.IPTables

	// iptRulesInstalled tracks whether we have installed iptables rules
	// so that cleanup is idempotent.
	iptRulesInstalled bool
}

// --- control-plane request / response types --------------------------------
// edgeConnectRequest and edgeConnectResponse are defined in server.go.

type edgeDisconnectRequest struct {
	PeerPublicKey string `json:"peer_public_key"`
}

// --- interface lifecycle ---------------------------------------------------

// CreateInterface creates the WireGuard network interface.
// Call DeleteInterface to clean it up.
func (e *EdgeClient) CreateInterface() error {
	link := e.link()
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("edge: error creating interface %s: %v", e.Ifname, err)
	}
	return nil
}

// DeleteInterface removes the WireGuard network interface.
func (e *EdgeClient) DeleteInterface() {
	log.Printf("edge: deleting interface %s", e.Ifname)
	if err := netlink.LinkDel(e.link()); err != nil {
		log.Printf("edge: error deleting interface %s: %v", e.Ifname, err)
	} else {
		log.Printf("edge: deleted interface %s", e.Ifname)
	}
}

func (e *EdgeClient) link() *linkWireguard {
	return &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: e.Ifname}}
}

// --- connect / disconnect --------------------------------------------------

// Connect sends an edge-connect request to the server and configures the
// local WireGuard interface + networking stack.
func (e *EdgeClient) Connect() error {
	resp, err := e.sendEdgeConnectRequest()
	if err != nil {
		return err
	}

	link := e.link()
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("edge: error bringing up interface: %v", err)
	}

	if err := e.updateInterface(resp); err != nil {
		return err
	}

	if err := e.configureWireguard(resp); err != nil {
		return fmt.Errorf("edge: error configuring WireGuard: %v", err)
	}

	return nil
}

// Disconnect notifies the server that this edge connector is going away.
func (e *EdgeClient) Disconnect() error {
	disconnectURL, err := url.Parse(fmt.Sprintf("https://%s/edge-disconnect", e.ServerIp))
	if err != nil {
		return fmt.Errorf("edge: failed to parse disconnect URL: %v", err)
	}

	reqJSON := &edgeDisconnectRequest{
		PeerPublicKey: e.Key.PublicKey().String(),
	}
	buf, err := json.Marshal(reqJSON)
	if err != nil {
		return fmt.Errorf("edge: failed to marshal disconnect request: %v", err)
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    disconnectURL,
		Header: http.Header{
			"Authorization": []string{"Bearer " + e.Token},
		},
		Body: io.NopCloser(bytes.NewBuffer(buf)),
	}

	resp, err := e.Http.Do(req)
	if err != nil {
		return fmt.Errorf("edge: failed to send disconnect request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("edge: server returned status %v for disconnect", resp.Status)
	}

	log.Printf("edge: successfully disconnected from server %v", e.ServerIp)
	return nil
}

// --- internal networking ---------------------------------------------------

func (e *EdgeClient) sendEdgeConnectRequest() (edgeConnectResponse, error) {
	connectURL, err := url.Parse(fmt.Sprintf("https://%s/edge-connect", e.ServerIp))
	if err != nil {
		return edgeConnectResponse{}, fmt.Errorf("edge: failed to parse connect URL: %v", err)
	}

	routeStrs := make([]string, len(e.Routes))
	for i, r := range e.Routes {
		routeStrs[i] = r.String()
	}

	reqJSON := &edgeConnectRequest{
		PeerPublicKey: e.Key.PublicKey().String(),
		Routes:        routeStrs,
	}
	buf, err := json.Marshal(reqJSON)
	if err != nil {
		return edgeConnectResponse{}, fmt.Errorf("edge: failed to marshal connect request: %v", err)
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    connectURL,
		Header: http.Header{
			"Authorization": []string{"Bearer " + e.Token},
		},
		Body: io.NopCloser(bytes.NewBuffer(buf)),
	}

	resp, err := e.Http.Do(req)
	if err != nil {
		return edgeConnectResponse{}, fmt.Errorf("edge: failed to connect to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		recoverable := resp.StatusCode != http.StatusUnauthorized
		return edgeConnectResponse{}, &ConnectionError{
			Message:     fmt.Sprintf("edge: server returned status %v", resp.Status),
			Recoverable: recoverable,
		}
	}

	buf, err = io.ReadAll(resp.Body)
	if err != nil {
		return edgeConnectResponse{}, fmt.Errorf("edge: failed to read response body: %v", err)
	}

	var respJSON edgeConnectResponse
	if err := json.Unmarshal(buf, &respJSON); err != nil {
		return edgeConnectResponse{}, fmt.Errorf("edge: failed to parse response: %v", err)
	}
	return respJSON, nil
}

func (e *EdgeClient) updateInterface(resp edgeConnectResponse) error {
	cidr, err := netip.ParsePrefix(resp.AssignedAddr)
	if err != nil {
		return fmt.Errorf("edge: failed to parse assigned address %v: %v", resp.AssignedAddr, err)
	}

	if cidr != e.wgCidr {
		link := e.link()

		if e.wgCidr.IsValid() {
			oldIPNet := prefixToIPNet(e.wgCidr)
			if err := netlink.AddrDel(link, &netlink.Addr{IPNet: &oldIPNet}); err != nil {
				log.Printf("edge: warning: failed to remove old address: %v", err)
			}
		}

		ipnet := prefixToIPNet(cidr)
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &ipnet}); err != nil {
			return fmt.Errorf("edge: failed to add address to interface: %v", err)
		}
		e.wgCidr = cidr
	}
	return nil
}

func (e *EdgeClient) configureWireguard(resp edgeConnectResponse) error {
	serverPubKey, err := wgtypes.ParseKey(resp.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("edge: failed to parse server public key: %v", err)
	}

	// AllowedIPs: the server's WG CIDR so we accept tunnel traffic from any
	// connect-peer, plus 0.0.0.0/0 would be too broad. We use the masked WG
	// network so that we can reach any peer on the WireGuard subnet (for
	// health-check pings, etc.) and also receive routed traffic from the server.
	// Using 0.0.0.0/0 here is acceptable because the edge is dedicated to this
	// tunnel; all traffic on this interface is server-originated.
	keepalive := 25 * time.Second
	return e.WgClient.ConfigureDevice(e.Ifname, wgtypes.Config{
		PrivateKey:   &e.Key,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: serverPubKey,
				Endpoint: &net.UDPAddr{
					IP:   addrToIp(e.ServerIp),
					Port: resp.ServerListenPort,
				},
				PersistentKeepaliveInterval: &keepalive,
				ReplaceAllowedIPs:           true,
				AllowedIPs: []net.IPNet{
					{
						IP:   net.IPv4(0, 0, 0, 0),
						Mask: net.CIDRMask(0, 32),
					},
				},
			},
		},
	})
}

// setupForwarding enables IP forwarding and installs iptables rules so that
// traffic arriving from the WireGuard tunnel destined for local networks is
// masqueraded through the default interface.
func (e *EdgeClient) SetupForwarding() error {
	// Ensure IP forwarding is enabled.
	if err := enableIPForwarding(); err != nil {
		return err
	}

	// Discover default interface if we haven't already.
	if e.defaultIface == nil {
		iface, err := getDefaultInterface()
		if err != nil {
			return fmt.Errorf("edge: failed to get default interface: %v", err)
		}
		e.defaultIface = iface
	}

	// Create iptables handle if needed.
	if e.ipt == nil {
		ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(5))
		if err != nil {
			return fmt.Errorf("edge: failed to initialize iptables: %v", err)
		}
		e.ipt = ipt
	}

	outIface := e.defaultIface.Attrs().Name

	// NAT: masquerade traffic from the WG subnet leaving via the default interface.
	masqRule := e.masqueradeRule(outIface)
	if err := e.ipt.AppendUnique("nat", "POSTROUTING", masqRule...); err != nil {
		return fmt.Errorf("edge: failed to add masquerade rule: %v", err)
	}

	// FORWARD: allow traffic from WG interface to default interface.
	fwdOutRule := e.forwardOutRule(outIface)
	if err := e.ipt.AppendUnique("filter", "FORWARD", fwdOutRule...); err != nil {
		return fmt.Errorf("edge: failed to add forward-out rule: %v", err)
	}

	// FORWARD: allow established/related return traffic.
	fwdInRule := e.forwardInRule(outIface)
	if err := e.ipt.AppendUnique("filter", "FORWARD", fwdInRule...); err != nil {
		return fmt.Errorf("edge: failed to add forward-in rule: %v", err)
	}

	// MSS clamp for TCP SYN packets traversing the tunnel to avoid MTU issues.
	mssRule := e.mssClampRule()
	if err := e.ipt.AppendUnique("filter", "FORWARD", mssRule...); err != nil {
		return fmt.Errorf("edge: failed to add MSS clamp rule: %v", err)
	}

	e.iptRulesInstalled = true
	log.Printf("edge: forwarding rules installed (wg=%s, out=%s)", e.Ifname, outIface)
	return nil
}

// CleanupForwarding removes the iptables rules installed by SetupForwarding.
func (e *EdgeClient) CleanupForwarding() error {
	if !e.iptRulesInstalled || e.ipt == nil || e.defaultIface == nil {
		return nil
	}

	outIface := e.defaultIface.Attrs().Name
	var firstErr error

	if err := e.ipt.Delete("nat", "POSTROUTING", e.masqueradeRule(outIface)...); err != nil {
		log.Printf("edge: warning: failed to remove masquerade rule: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	if err := e.ipt.Delete("filter", "FORWARD", e.forwardOutRule(outIface)...); err != nil {
		log.Printf("edge: warning: failed to remove forward-out rule: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	if err := e.ipt.Delete("filter", "FORWARD", e.forwardInRule(outIface)...); err != nil {
		log.Printf("edge: warning: failed to remove forward-in rule: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	if err := e.ipt.Delete("filter", "FORWARD", e.mssClampRule()...); err != nil {
		log.Printf("edge: warning: failed to remove MSS clamp rule: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}

	e.iptRulesInstalled = false
	log.Printf("edge: forwarding rules removed")
	return firstErr
}

// --- iptables rule helpers -------------------------------------------------

func (e *EdgeClient) masqueradeRule(outIface string) []string {
	return []string{
		"-s", e.wgCidr.Masked().String(),
		"-o", outIface,
		"-j", "MASQUERADE",
		"-m", "comment", "--comment", fmt.Sprintf("vprox edge masquerade for %s", e.Ifname),
	}
}

func (e *EdgeClient) forwardOutRule(outIface string) []string {
	return []string{
		"-i", e.Ifname,
		"-o", outIface,
		"-j", "ACCEPT",
		"-m", "comment", "--comment", fmt.Sprintf("vprox edge forward-out for %s", e.Ifname),
	}
}

func (e *EdgeClient) forwardInRule(outIface string) []string {
	return []string{
		"-i", outIface,
		"-o", e.Ifname,
		"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
		"-j", "ACCEPT",
		"-m", "comment", "--comment", fmt.Sprintf("vprox edge forward-in for %s", e.Ifname),
	}
}

func (e *EdgeClient) mssClampRule() []string {
	return []string{
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--set-mss", "1160",
		"-m", "comment", "--comment", fmt.Sprintf("vprox edge mss clamp for %s", e.Ifname),
	}
}

// --- health check ----------------------------------------------------------

// CheckConnection pings the server's WireGuard IP through the tunnel to verify
// connectivity. Returns true if at least one reply is received.
func (e *EdgeClient) CheckConnection(timeout time.Duration, ctx context.Context) bool {
	// The server's WG IP is the first address in the masked CIDR.
	serverWgIp := e.wgCidr.Masked().Addr().Next()

	pinger, err := probing.NewPinger(serverWgIp.String())
	if err != nil {
		log.Printf("edge: error creating pinger: %v", err)
		return false
	}

	pinger.InterfaceName = e.Ifname
	pinger.Timeout = timeout
	pinger.Count = 3
	pinger.Interval = 10 * time.Millisecond
	if err := pinger.RunWithContext(ctx); err != nil {
		log.Printf("edge: error running pinger: %v", err)
		return false
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 && stats.PacketsRecv < stats.PacketsSent {
		log.Printf("edge: warning: %d of %d ping packets dropped",
			stats.PacketsSent-stats.PacketsRecv, stats.PacketsSent)
	}
	return stats.PacketsRecv > 0
}

// --- helpers ---------------------------------------------------------------

// enableIPForwarding writes to /proc to ensure the kernel forwards IPv4 packets.
func enableIPForwarding() error {
	const procPath = "/proc/sys/net/ipv4/ip_forward"
	current, err := os.ReadFile(procPath)
	if err != nil {
		return fmt.Errorf("edge: failed to read %s: %v", procPath, err)
	}
	if len(current) > 0 && current[0] == '1' {
		return nil // already enabled
	}
	log.Printf("edge: enabling IPv4 forwarding")
	if err := os.WriteFile(procPath, []byte("1"), 0644); err != nil {
		return fmt.Errorf("edge: failed to enable IP forwarding: %v", err)
	}
	return nil
}
