// Implementation of Netlink device for WireGuard.

package lib

import "github.com/vishvananda/netlink"

type linkWireguard struct {
	netlink.LinkAttrs
}

func (wg *linkWireguard) Attrs() *netlink.LinkAttrs {
	return &wg.LinkAttrs
}

func (wg *linkWireguard) Type() string {
	return "wireguard"
}
