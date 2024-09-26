package lib

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAfterOneIpBlock(t *testing.T) {
	ip1 := netip.AddrFrom4([4]byte{192, 168, 1, 0})
	ip2 := netip.AddrFrom4([4]byte{192, 168, 2, 0})
	assert.Equal(t, AfterCountIpBlock(ip1, 24, 1), ip2, "next ip mismatch")

	ip2 = netip.AddrFrom4([4]byte{192, 168, 1, 16})
	assert.Equal(t, AfterCountIpBlock(ip1, 28, 1), ip2, "next ip mismatch")

	ip2 = netip.AddrFrom4([4]byte{193, 168, 1, 0})
	assert.Equal(t, AfterCountIpBlock(ip1, 8, 1), ip2, "next ip mismatch")
}

func TestAfterCountIpBlock(t *testing.T) {
	ip1 := netip.AddrFrom4([4]byte{192, 168, 1, 0})
	ip2 := netip.AddrFrom4([4]byte{192, 168, 6, 0})
	assert.Equal(t, AfterCountIpBlock(ip1, 24, 5), ip2)

	ip2 = netip.AddrFrom4([4]byte{192, 168, 1, 64})
	assert.Equal(t, AfterCountIpBlock(ip1, 28, 4), ip2)

	ip2 = netip.AddrFrom4([4]byte{192, 168, 2, 128})
	assert.Equal(t, AfterCountIpBlock(ip1, 25, 3), ip2)
}
