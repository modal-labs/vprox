package lib

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/vishvananda/netlink"
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

// getDefaultInterface returns the default network interface.
func getDefaultInterface() (netlink.Link, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %v", err)
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero) {
			// Get the link (network interface) associated with the route
			return netlink.LinkByIndex(route.LinkIndex)
		}
	}

	return nil, fmt.Errorf("failed to find default route")
}

// IpAllocator is a simple IP address allocator that produces IP addresses
// within a prefix, in increasing order of available IPs.
//
// All operations on an IpAllocator are thread-safe.
type IpAllocator struct {
	mu        sync.Mutex // Protects the fields below
	prefix    netip.Prefix
	allocated map[netip.Addr]struct{}
}

// NewIpAllocator creates a new IpAllocator for the given prefix.
//
// The prefix is masked out to normalize its address at the beginning of the IP
// range. It must be valid.
func NewIpAllocator(prefix netip.Prefix) *IpAllocator {
	ipa := new(IpAllocator)
	ipa.prefix = prefix.Masked()
	ipa.allocated = make(map[netip.Addr]struct{})
	return ipa
}

// Allocate returns the next available IP address in the prefix.
//
// This never uses the initial address (the "zero address") of the prefix. For
// example, for the prefix `192.168.0.0/24`, the first IP address allocated
// will be `192.168.0.1`.
//
// If there are no more available IP addresses, this returns the zero address.
func (ipa *IpAllocator) Allocate() netip.Addr {
	ipa.mu.Lock()
	defer ipa.mu.Unlock()

	addr := ipa.prefix.Addr().Next()
	for ipa.prefix.Contains(addr) && !addr.IsUnspecified() {
		if _, ok := ipa.allocated[addr]; !ok {
			ipa.allocated[addr] = struct{}{}
			return addr
		}
		addr = addr.Next()
	}

	// Otherwise, return the zero address.
	if ipa.prefix.Addr().Is4() {
		return netip.AddrFrom4([4]byte{})
	} else {
		return netip.AddrFrom16([16]byte{})
	}
}

// Free marks the given IP address as available for allocation.
func (ipa *IpAllocator) Free(addr netip.Addr) bool {
	ipa.mu.Lock()
	defer ipa.mu.Unlock()

	if _, ok := ipa.allocated[addr]; ok {
		delete(ipa.allocated, addr)
		return true
	}
	return false
}

// AfterCountIpBlock returns the result of incrementing an IP address by N CIDR
// counts.
func AfterCountIpBlock(ip netip.Addr, size uint, count uint) netip.Addr {
	// Copy the IP address to avoid modifying the original.
	ipBytes := ip.As4()

	bits := 8 * uint(len(ipBytes))
	if size > bits {
		log.Panicf("block size of %v is larger than ip bits %v", size, bits)
	}

	// CIDR block size rounded up to the nearest multiple of 8
	// 32->32, 31->32, 30->32, ..., 25->32, 24->24
	tSize := 8 * ((size + 7) / 8)
	tCount := count << (tSize - size)
	for ; tSize > 0; tSize -= 8 {
		c := tCount & 0xff // how much to add to the current byte
		tCount = tCount >> 8
		// 1.2.3.4/32 (byteIndex = 3) -> 1.2.3.5/32
		// 1.2.3.4/24 (byteIndex = 2) -> 1.2.4.4/24
		byteIndex := tSize/8 - 1
		addWithCarry := uint(ipBytes[byteIndex]) + c
		ipBytes[byteIndex] = byte(addWithCarry)
		tCount += addWithCarry >> 8
	}

	return netip.AddrFrom4(ipBytes)
}
