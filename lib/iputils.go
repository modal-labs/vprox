package lib

import (
	"net"
	"net/netip"
)

// prefixToIPNet converts a netip.Prefix to a net.IPNet.
func prefixToIPNet(prefix netip.Prefix) net.IPNet {
	ip := net.IP(prefix.Addr().AsSlice())
	ones := prefix.Bits()
	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(ones, len(ip)*8),
	}
}

// addrToIp converts a netip.Addr to a net.IP.
func addrToIp(addr netip.Addr) net.IP {
	return net.IP(addr.AsSlice())
}
