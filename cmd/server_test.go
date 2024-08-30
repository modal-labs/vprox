package cmd

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNextIpBlock(t *testing.T) {
	ip1 := netip.AddrFrom4([4]byte{192, 168, 1, 0})
	ip2 := netip.AddrFrom4([4]byte{192, 168, 2, 0})
	assert.Equal(t, nextIpBlock(ip1, 24), ip2, "next ip mismatch")

	ip2 = netip.AddrFrom4([4]byte{192, 168, 1, 16})
	assert.Equal(t, nextIpBlock(ip1, 28), ip2, "next ip mismatch")

	ip2 = netip.AddrFrom4([4]byte{193, 168, 1, 0})
	assert.Equal(t, nextIpBlock(ip1, 8), ip2, "next ip mismatch")
}
