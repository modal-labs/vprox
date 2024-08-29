package cmd

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNextIpBlock(t *testing.T) {
	ip1 := net.IPv4(192, 168, 1, 0).To4()
	ip2 := net.IPv4(192, 168, 2, 0).To4()
	assert.Equal(t, nextIpBlock(ip1, 24), ip2, "next ip mismatch")

	ip2 = net.IPv4(192, 168, 1, 16).To4()
	assert.Equal(t, nextIpBlock(ip1, 28), ip2, "next ip mismatch")

	ip2 = net.IPv4(193, 168, 1, 0).To4()
	assert.Equal(t, nextIpBlock(ip1, 8), ip2, "next ip mismatch")
}
