package rawclient

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// ConfigureWireguardDevice configures the WireGuard device named ifname the
// specific way the vprox client uses it, via a single WG_CMD_SET_DEVICE
// generic netlink request:
//
//   - set the device private key
//   - replace all peers with a single server peer, identified by
//     serverPublicKey, reachable at endpoint (IPv4 UDP), with a persistent
//     keepalive and allowed IPs replaced by 0.0.0.0/0 (route everything).
//
// This is the wgctrl-free equivalent of
// wgctrl.Client.ConfigureDevice(ifname, wgtypes.Config{...}) as called from
// lib/client.go configureWireguard.
func ConfigureWireguardDevice(
	ifname string,
	privateKey Key,
	serverPublicKey Key,
	endpointIp net.IP,
	endpointPort int,
	keepalive time.Duration,
) error {
	attrs, err := encodeSetDeviceRequest(ifname, privateKey, serverPublicKey, endpointIp, endpointPort, keepalive)
	if err != nil {
		return err
	}

	// Dial a generic netlink socket and resolve the "wireguard" family, whose
	// numeric ID addresses the kernel WireGuard module.
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("failed to dial generic netlink: %v", err)
	}
	defer conn.Close()

	family, err := conn.GetFamily(unix.WG_GENL_NAME)
	if err != nil {
		return fmt.Errorf("wireguard generic netlink family unavailable (is the wireguard module loaded?): %v", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: unix.WG_CMD_SET_DEVICE,
			Version: unix.WG_GENL_VERSION,
		},
		Data: attrs,
	}
	if _, err := conn.Execute(msg, family.ID, netlink.Request|netlink.Acknowledge); err != nil {
		return fmt.Errorf("WG_CMD_SET_DEVICE failed: %w", err)
	}
	return nil
}

// encodeSetDeviceRequest encodes the netlink attribute payload for the
// WG_CMD_SET_DEVICE request described in ConfigureWireguardDevice.
func encodeSetDeviceRequest(
	ifname string,
	privateKey Key,
	serverPublicKey Key,
	endpointIp net.IP,
	endpointPort int,
	keepalive time.Duration,
) ([]byte, error) {
	ip4 := endpointIp.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("endpoint IP %v is not IPv4", endpointIp)
	}

	ae := netlink.NewAttributeEncoder()
	ae.String(unix.WGDEVICE_A_IFNAME, ifname)
	ae.Bytes(unix.WGDEVICE_A_PRIVATE_KEY, privateKey[:])
	// Wipe any existing peers; the client only ever has the one server peer.
	ae.Uint32(unix.WGDEVICE_A_FLAGS, unix.WGDEVICE_F_REPLACE_PEERS)

	ae.Nested(unix.WGDEVICE_A_PEERS, func(nae *netlink.AttributeEncoder) error {
		// Netlink arrays use the attribute type as an array index.
		nae.Nested(0, func(pae *netlink.AttributeEncoder) error {
			pae.Bytes(unix.WGPEER_A_PUBLIC_KEY, serverPublicKey[:])
			pae.Uint32(unix.WGPEER_A_FLAGS, unix.WGPEER_F_REPLACE_ALLOWEDIPS)
			pae.Do(unix.WGPEER_A_ENDPOINT, func() ([]byte, error) {
				var addr [4]byte
				copy(addr[:], ip4)
				sa := unix.RawSockaddrInet4{
					Family: unix.AF_INET,
					Port:   sockaddrPort(endpointPort),
					Addr:   addr,
				}
				return (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:], nil
			})
			pae.Uint16(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, uint16(keepalive.Seconds()))
			pae.Nested(unix.WGPEER_A_ALLOWEDIPS, func(aae *netlink.AttributeEncoder) error {
				// Single allowed IP: 0.0.0.0/0 (all IPv4 traffic).
				aae.Nested(0, func(ipae *netlink.AttributeEncoder) error {
					ipae.Uint16(unix.WGALLOWEDIP_A_FAMILY, unix.AF_INET)
					ipae.Bytes(unix.WGALLOWEDIP_A_IPADDR, net.IPv4zero.To4())
					ipae.Uint8(unix.WGALLOWEDIP_A_CIDR_MASK, 0)
					return nil
				})
				return nil
			})
			return nil
		})
		return nil
	})

	return ae.Encode()
}

// sockaddrPort interprets port as a big endian uint16 for use in sockaddr
// structures passed to the kernel.
func sockaddrPort(port int) uint16 {
	return binary.BigEndian.Uint16(nlenc.Uint16Bytes(uint16(port)))
}
