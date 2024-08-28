// Implementation of Netlink device for WireGuard.

package lib

import "github.com/vishvananda/netlink"

type LinkWireguard struct {
	netlink.LinkAttrs
}

func (wg *LinkWireguard) Attrs() *netlink.LinkAttrs {
	return &wg.LinkAttrs
}

func (wg *LinkWireguard) Type() string {
	return "wireguard"
}
