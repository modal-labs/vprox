package lib

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/vishvananda/netlink"
)

// prefixToIPNet converts a netip.Prefix to a net.IPNet.
func prefixToIPNet(prefix netip.Prefix) net.IPNet {
	ip := net.IP(prefix.Addr().AsSlice())
	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(prefix.Bits(), len(ip)*8),
	}
}

// addrToIp converts a netip.Addr to a net.IP.
func addrToIp(addr netip.Addr) net.IP {
	return net.IP(addr.AsSlice())
}

// getDefaultInterface returns the network interface that the default route
// points at.
func getDefaultInterface() (netlink.Link, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %v", err)
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero) {
			return netlink.LinkByIndex(route.LinkIndex)
		}
	}

	return nil, fmt.Errorf("failed to find default route")
}

// IpAllocator is the set of addresses handed out from one prefix. It hands out
// the lowest free address first. All operations are safe for concurrent use.
type IpAllocator struct {
	// mu protects prefix and allocated.
	mu        sync.Mutex
	prefix    netip.Prefix
	allocated map[netip.Addr]struct{}

	// allocatedCount mirrors len(allocated) so that it can be read without the lock.
	allocatedCount atomic.Int64
}

// NewIpAllocator returns an empty IpAllocator for the masked form of prefix.
func NewIpAllocator(prefix netip.Prefix) *IpAllocator {
	return &IpAllocator{
		prefix:    prefix.Masked(),
		allocated: make(map[netip.Addr]struct{}),
	}
}

// Allocate marks the lowest free address in the prefix as allocated and
// returns it. The prefix's network address is never handed out, so the first
// address allocated from 192.168.0.0/24 is 192.168.0.1. Returns the
// unspecified address if the prefix is exhausted.
func (allocator *IpAllocator) Allocate() netip.Addr {
	allocator.mu.Lock()
	defer allocator.mu.Unlock()

	addr := allocator.prefix.Addr().Next()
	for allocator.prefix.Contains(addr) && !addr.IsUnspecified() {
		if _, ok := allocator.allocated[addr]; !ok {
			allocator.allocated[addr] = struct{}{}
			allocator.allocatedCount.Add(1)
			return addr
		}
		addr = addr.Next()
	}

	if allocator.prefix.Addr().Is4() {
		return netip.AddrFrom4([4]byte{})
	}
	return netip.AddrFrom16([16]byte{})
}

// Free marks addr as available again and reports whether it was allocated.
func (allocator *IpAllocator) Free(addr netip.Addr) bool {
	allocator.mu.Lock()
	defer allocator.mu.Unlock()

	if _, ok := allocator.allocated[addr]; ok {
		delete(allocator.allocated, addr)
		allocator.allocatedCount.Add(-1)
		return true
	}
	return false
}

// AllocatedCount returns the number of currently allocated addresses.
func (allocator *IpAllocator) AllocatedCount() int {
	return int(allocator.allocatedCount.Load())
}

// MarkAllocated marks addr as allocated if it is inside the prefix and not
// already allocated.
func (allocator *IpAllocator) MarkAllocated(addr netip.Addr) {
	allocator.mu.Lock()
	defer allocator.mu.Unlock()

	if !allocator.prefix.Contains(addr) {
		return
	}
	if _, ok := allocator.allocated[addr]; ok {
		return
	}
	allocator.allocated[addr] = struct{}{}
	allocator.allocatedCount.Add(1)
}

// AfterCountIpBlock returns ip advanced by count blocks of prefix length size.
// For example, 10.0.0.0 advanced by 2 blocks of size 24 is 10.0.2.0.
func AfterCountIpBlock(ip netip.Addr, size uint, count uint) netip.Addr {
	ipBytes := ip.As4()

	bits := 8 * uint(len(ipBytes))
	if size > bits {
		log.Panicf("block size of %v is larger than ip bits %v", size, bits)
	}

	// Round the block size up to a whole number of bytes and scale the count to match so that
	// the addition can proceed one byte at a time from the least significant byte.
	roundedSize := 8 * ((size + 7) / 8)
	remainingCount := count << (roundedSize - size)
	for ; roundedSize > 0; roundedSize -= 8 {
		byteIncrement := remainingCount & 0xff
		remainingCount = remainingCount >> 8
		byteIndex := roundedSize/8 - 1
		sumWithCarry := uint(ipBytes[byteIndex]) + byteIncrement
		ipBytes[byteIndex] = byte(sumWithCarry)
		remainingCount += sumWithCarry >> 8
	}

	return netip.AddrFrom4(ipBytes)
}
