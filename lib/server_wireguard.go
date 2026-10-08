package lib

import (
	"fmt"
	"log"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func wireguardIfname(server *Server) string {
	return fmt.Sprintf("vprox%d", server.Index)
}

func wireguardListenPort(server *Server) int {
	return WireguardListenPortBase + int(server.Index)
}

func wireguardLink(server *Server) *linkWireguard {
	return &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: wireguardIfname(server)}}
}

// wireguardInterfaceExists reports whether a network interface with the
// server's WireGuard interface name is present on the host.
func wireguardInterfaceExists(server *Server) bool {
	_, err := netlink.LinkByName(wireguardIfname(server))
	return err == nil
}

// createFreshWireguardInterface replaces any existing interface with the
// server's name by a new WireGuard interface that is addressed, up, and
// configured with the server's private key and listen port. The interface is
// deleted again if any step fails.
func createFreshWireguardInterface(server *Server) error {
	link := wireguardLink(server)
	_ = netlink.LinkDel(link)

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("failed to create WireGuard device: %v", err)
	}

	ipnet := prefixToIPNet(server.WgCidr)
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &ipnet}); err != nil {
		_ = netlink.LinkDel(link)
		return fmt.Errorf("failed to add address to WireGuard device: %v", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		_ = netlink.LinkDel(link)
		return fmt.Errorf("failed to bring up WireGuard device: %v", err)
	}

	if err := configureWireguardKeyAndPort(server); err != nil {
		_ = netlink.LinkDel(link)
		return err
	}

	return nil
}

// reuseExistingWireguardInterface configures the server's private key and
// listen port on the WireGuard interface left behind by a previous server
// instance, keeping that interface's peers intact.
func reuseExistingWireguardInterface(server *Server) error {
	log.Printf("[%v] takeover mode: using existing WireGuard interface %s", server.BindAddr, wireguardIfname(server))
	return configureWireguardKeyAndPort(server)
}

func configureWireguardKeyAndPort(server *Server) error {
	listenPort := wireguardListenPort(server)
	configureStart := time.Now()
	err := server.WgClient.ConfigureDevice(wireguardIfname(server), wgtypes.Config{
		PrivateKey: &server.Key,
		ListenPort: &listenPort,
	})
	recordWireguardConfigureLatency("init", time.Since(configureStart))
	return err
}

// deleteWireguardInterfaceUnlessRelinquished removes the server's WireGuard
// interface, or leaves it in place for the next server instance if the server
// has been relinquished.
func deleteWireguardInterfaceUnlessRelinquished(server *Server) {
	server.mu.Lock()
	relinquished := server.relinquished
	server.mu.Unlock()

	if relinquished {
		log.Printf("[%v] skipping WireGuard cleanup (relinquished)", server.BindAddr)
		return
	}

	log.Printf("[%v] cleaning up WireGuard state", server.BindAddr)
	_ = netlink.LinkDel(wireguardLink(server))
}
