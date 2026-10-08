package lib

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAfterCountIpBlockAdvancesOneBlockOfVariousSizes(t *testing.T) {
	start := netip.MustParseAddr("192.168.1.0")

	assert.Equal(t, netip.MustParseAddr("192.168.2.0"), AfterCountIpBlock(start, 24, 1))
	assert.Equal(t, netip.MustParseAddr("192.168.1.16"), AfterCountIpBlock(start, 28, 1))
	assert.Equal(t, netip.MustParseAddr("193.168.1.0"), AfterCountIpBlock(start, 8, 1))
}

func TestAfterCountIpBlockAdvancesMultipleBlocks(t *testing.T) {
	start := netip.MustParseAddr("192.168.1.0")

	assert.Equal(t, netip.MustParseAddr("192.168.6.0"), AfterCountIpBlock(start, 24, 5))
	assert.Equal(t, netip.MustParseAddr("192.168.1.64"), AfterCountIpBlock(start, 28, 4))
	assert.Equal(t, netip.MustParseAddr("192.168.2.128"), AfterCountIpBlock(start, 25, 3))
}

func TestAllocateSkipsNetworkAddress(t *testing.T) {
	allocator := NewIpAllocator(netip.MustParsePrefix("10.0.0.0/30"))

	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), allocator.Allocate())
}

func TestAllocateReturnsUnspecifiedWhenPrefixIsExhausted(t *testing.T) {
	allocator := NewIpAllocator(netip.MustParsePrefix("10.0.0.0/30"))
	allocator.Allocate()
	allocator.Allocate()
	allocator.Allocate()

	assert.True(t, allocator.Allocate().IsUnspecified())
}

func TestFreeMakesAddressAvailableAgain(t *testing.T) {
	allocator := NewIpAllocator(netip.MustParsePrefix("10.0.0.0/30"))
	first := allocator.Allocate()
	allocator.Allocate()

	assert.True(t, allocator.Free(first))
	assert.Equal(t, first, allocator.Allocate())
}

func TestFreeReportsFalseForUnallocatedAddress(t *testing.T) {
	allocator := NewIpAllocator(netip.MustParsePrefix("10.0.0.0/30"))

	assert.False(t, allocator.Free(netip.MustParseAddr("10.0.0.1")))
}

func TestMarkAllocatedReservesAddressInsidePrefix(t *testing.T) {
	allocator := NewIpAllocator(netip.MustParsePrefix("10.0.0.0/30"))

	allocator.MarkAllocated(netip.MustParseAddr("10.0.0.1"))

	assert.Equal(t, 1, allocator.AllocatedCount())
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), allocator.Allocate())
}

func TestMarkAllocatedIgnoresAddressOutsidePrefix(t *testing.T) {
	allocator := NewIpAllocator(netip.MustParsePrefix("10.0.0.0/30"))

	allocator.MarkAllocated(netip.MustParseAddr("10.0.1.1"))

	assert.Equal(t, 0, allocator.AllocatedCount())
}
