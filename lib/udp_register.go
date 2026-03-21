// UDP peer registration protocol for vprox.
//
// This implements an encrypted, single-round-trip UDP protocol for peer
// registration as an alternative to the HTTPS /connect endpoint. By
// eliminating TCP handshakes and TLS negotiation, it cuts registration
// latency from ~3s (1000 concurrent TLS 1.3 handshakes) to <100ms.
//
// # Security model
//
// Uses XChaCha20-Poly1305 AEAD with a symmetric key derived from the
// shared VPROX_PASSWORD via HKDF-SHA256. A successfully decrypted packet
// proves the sender knows the password — no additional auth token is
// transmitted. The 24-byte XChaCha20 nonce is safe to generate randomly
// (collision probability is negligible even at billions of packets).
//
// The actual tunnel traffic is protected by WireGuard's Noise_IK protocol
// which provides its own authentication, confidentiality, and forward
// secrecy. This UDP protocol only protects the control-plane registration
// step.
//
// # Wire format
//
// Request (client → server, 81 bytes):
//
//	[0]      message type = 0x01
//	[1:9]    request ID   (8 random bytes, for matching responses)
//	[9:33]   nonce        (24 random bytes for XChaCha20-Poly1305)
//	[33:81]  ciphertext   (32-byte peer public key + 16-byte Poly1305 tag)
//	         AAD = bytes [0:9] (type + request_id, authenticated but not encrypted)
//
// Response (server → client, 89 bytes):
//
//	[0]      message type = 0x81
//	[1:9]    request ID   (echoed from request)
//	[9:33]   nonce        (24 fresh random bytes)
//	[33:89]  ciphertext   (40-byte payload + 16-byte Poly1305 tag)
//	         payload layout:
//	           [0]     status: 0=ok, 1=capacity, 2=unavailable, 3=error
//	           [1:33]  server WireGuard public key (32 bytes)
//	           [33:37] assigned IPv4 address (4 bytes, network order)
//	           [37]    CIDR prefix length
//	           [38:40] WireGuard listen port (big-endian uint16)
//	         AAD = bytes [0:9]
package lib

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// UDPRegisterPort is the UDP port the server listens on for registration
// packets. Port 50228 is one above the WireGuard data port (50227). AWS
// Security Groups that allow a UDP range including 50227 will typically
// also cover 50228. If not, the SG must be updated to allow UDP 50228.
const UDPRegisterPort = 50228

const (
	udpMsgRequest  byte = 0x01
	udpMsgResponse byte = 0x81

	udpHeaderLen = 1 + 8 // type (1) + request_id (8)
	udpNonceLen  = chacha20poly1305.NonceSizeX
	udpTagLen    = 16 // Poly1305 tag

	udpReqPlainLen  = 32                // peer public key
	udpRespPlainLen = 1 + 32 + 4 + 1 + 2 // status + server_key + ipv4 + prefix + port = 40

	UDPRequestPacketLen  = udpHeaderLen + udpNonceLen + udpReqPlainLen + udpTagLen  // 81
	UDPResponsePacketLen = udpHeaderLen + udpNonceLen + udpRespPlainLen + udpTagLen // 89

	// HKDF domain separation.
	udpHKDFSalt = "vprox-udp-register-v1"
	udpHKDFInfo = "xchacha20poly1305-key"

	// Client retry parameters.
	udpMaxAttempts    = 3
	udpAttemptTimeout = 500 * time.Millisecond
)

// Status codes in response packets.
const (
	udpStatusOK          byte = 0
	udpStatusCapacity    byte = 1 // 429-equivalent: too many peers
	udpStatusUnavailable byte = 2 // 503-equivalent: no IPs or queue full
	udpStatusError       byte = 3 // 500-equivalent: internal error
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	errInvalidUDPPacket = errors.New("invalid UDP register packet")
	errPeerCapacity     = errors.New("server at peer capacity")
	errNoAddresses      = errors.New("no IP addresses available")
	errShardQueueFull   = errors.New("peer registration queue full")
	errFlushFailed      = errors.New("failed to flush peer to WireGuard")
)

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

// deriveUDPKey derives a 32-byte symmetric key from the shared password
// using HKDF-SHA256. Both client and server call this with the same
// password to arrive at the same key.
func deriveUDPKey(password string) [32]byte {
	hkdfReader := hkdf.New(sha256.New, []byte(password), []byte(udpHKDFSalt), []byte(udpHKDFInfo))
	var key [32]byte
	// hkdf.New never returns a short read for <= hash output size.
	_, _ = io.ReadFull(hkdfReader, key[:])
	return key
}

// newUDPAEAD creates an XChaCha20-Poly1305 AEAD cipher from the derived
// key. The returned cipher.AEAD is safe for concurrent use.
func newUDPAEAD(key [32]byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key[:])
}

// ---------------------------------------------------------------------------
// Packet marshalling — request
// ---------------------------------------------------------------------------

// marshalRegisterRequest builds an 81-byte encrypted registration request.
func marshalRegisterRequest(aead cipher.AEAD, requestID [8]byte, peerPubKey wgtypes.Key) ([]byte, error) {
	pkt := make([]byte, UDPRequestPacketLen)

	// Header (AAD).
	pkt[0] = udpMsgRequest
	copy(pkt[1:9], requestID[:])
	header := pkt[:udpHeaderLen]

	// Nonce.
	nonce := pkt[udpHeaderLen : udpHeaderLen+udpNonceLen]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand nonce: %w", err)
	}

	// Encrypt public key.
	plaintext := peerPubKey[:]
	ciphertext := aead.Seal(pkt[:udpHeaderLen+udpNonceLen], nonce, plaintext, header)

	// aead.Seal appends ciphertext+tag after the dst prefix we gave it.
	// Verify length.
	if len(ciphertext) != UDPRequestPacketLen {
		return nil, fmt.Errorf("unexpected request packet length: %d", len(ciphertext))
	}
	return ciphertext, nil
}

// unmarshalRegisterRequest decrypts an incoming request and returns the
// request ID and peer public key. Returns an error if the packet is
// malformed or the AEAD authentication fails (wrong password).
func unmarshalRegisterRequest(aead cipher.AEAD, pkt []byte) ([8]byte, wgtypes.Key, error) {
	var requestID [8]byte
	var peerKey wgtypes.Key

	if len(pkt) != UDPRequestPacketLen {
		return requestID, peerKey, errInvalidUDPPacket
	}
	if pkt[0] != udpMsgRequest {
		return requestID, peerKey, errInvalidUDPPacket
	}

	copy(requestID[:], pkt[1:9])
	header := pkt[:udpHeaderLen]
	nonce := pkt[udpHeaderLen : udpHeaderLen+udpNonceLen]
	ciphertext := pkt[udpHeaderLen+udpNonceLen:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return requestID, peerKey, fmt.Errorf("AEAD open: %w", err)
	}
	if len(plaintext) != udpReqPlainLen {
		return requestID, peerKey, errInvalidUDPPacket
	}

	copy(peerKey[:], plaintext)
	return requestID, peerKey, nil
}

// ---------------------------------------------------------------------------
// Packet marshalling — response
// ---------------------------------------------------------------------------

// peerRegistration holds the structured result of a peer registration,
// used internally by both the UDP and (optionally) HTTP handlers.
type peerRegistration struct {
	PeerIP       netip.Addr
	PrefixBits   int
	ServerPubKey wgtypes.Key
	ListenPort   int
}

// toConnectResponse converts a peerRegistration into the string-based
// connectResponse expected by the client's updateInterface / configureWireguard.
func (r peerRegistration) toConnectResponse() connectResponse {
	return connectResponse{
		AssignedAddr:     fmt.Sprintf("%v/%d", r.PeerIP, r.PrefixBits),
		ServerPublicKey:  r.ServerPubKey.String(),
		ServerListenPort: r.ListenPort,
	}
}

// marshalRegisterResponse builds an 89-byte encrypted response packet.
// When status != 0, reg fields may be zero-valued.
func marshalRegisterResponse(aead cipher.AEAD, requestID [8]byte, status byte, reg peerRegistration) ([]byte, error) {
	pkt := make([]byte, UDPResponsePacketLen)

	// Header (AAD).
	pkt[0] = udpMsgResponse
	copy(pkt[1:9], requestID[:])
	header := pkt[:udpHeaderLen]

	// Nonce.
	nonce := pkt[udpHeaderLen : udpHeaderLen+udpNonceLen]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand nonce: %w", err)
	}

	// Plaintext payload.
	var plain [udpRespPlainLen]byte
	plain[0] = status
	copy(plain[1:33], reg.ServerPubKey[:])
	if reg.PeerIP.Is4() {
		ip4 := reg.PeerIP.As4()
		copy(plain[33:37], ip4[:])
	}
	plain[37] = byte(reg.PrefixBits)
	binary.BigEndian.PutUint16(plain[38:40], uint16(reg.ListenPort))

	// Encrypt.
	ciphertext := aead.Seal(pkt[:udpHeaderLen+udpNonceLen], nonce, plain[:], header)
	if len(ciphertext) != UDPResponsePacketLen {
		return nil, fmt.Errorf("unexpected response packet length: %d", len(ciphertext))
	}
	return ciphertext, nil
}

// unmarshalRegisterResponse decrypts a response packet and returns the
// request ID, status code, and a connectResponse suitable for the client.
func unmarshalRegisterResponse(aead cipher.AEAD, pkt []byte) ([8]byte, byte, connectResponse, error) {
	var requestID [8]byte
	empty := connectResponse{}

	if len(pkt) != UDPResponsePacketLen {
		return requestID, 0, empty, errInvalidUDPPacket
	}
	if pkt[0] != udpMsgResponse {
		return requestID, 0, empty, errInvalidUDPPacket
	}

	copy(requestID[:], pkt[1:9])
	header := pkt[:udpHeaderLen]
	nonce := pkt[udpHeaderLen : udpHeaderLen+udpNonceLen]
	ciphertext := pkt[udpHeaderLen+udpNonceLen:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return requestID, 0, empty, fmt.Errorf("AEAD open: %w", err)
	}
	if len(plaintext) != udpRespPlainLen {
		return requestID, 0, empty, errInvalidUDPPacket
	}

	status := plaintext[0]

	var serverKey wgtypes.Key
	copy(serverKey[:], plaintext[1:33])

	var ip4 [4]byte
	copy(ip4[:], plaintext[33:37])
	addr := netip.AddrFrom4(ip4)
	prefixBits := int(plaintext[37])
	listenPort := int(binary.BigEndian.Uint16(plaintext[38:40]))

	resp := connectResponse{
		AssignedAddr:     fmt.Sprintf("%v/%d", addr, prefixBits),
		ServerPublicKey:  serverKey.String(),
		ServerListenPort: listenPort,
	}
	return requestID, status, resp, nil
}

// ---------------------------------------------------------------------------
// Server: core peer registration logic
// ---------------------------------------------------------------------------

// registerPeer is the core peer registration logic shared by both the
// HTTPS /connect handler and the UDP registration handler. It allocates
// an IP, enqueues the peer for batched WireGuard registration, and waits
// for the flush confirmation before returning.
//
// The remoteAddr string is used only for logging.
func (srv *Server) registerPeer(peerKey wgtypes.Key, remoteAddr string) (peerRegistration, error) {
	srv.mu.Lock()

	// Capacity check — reconnects for existing peers are exempt.
	if _, reconnect := srv.peers[peerKey]; !reconnect && len(srv.peers) >= srv.MaxPeers {
		srv.mu.Unlock()
		return peerRegistration{}, errPeerCapacity
	}

	// Fast path: peer already registered (reconnect).
	if existing, ok := srv.peers[peerKey]; ok {
		srv.mu.Unlock()
		return peerRegistration{
			PeerIP:       existing.IP,
			PrefixBits:   srv.WgCidr.Bits(),
			ServerPubKey: srv.Key.PublicKey(),
			ListenPort:   WireguardListenPortBase + int(srv.Index),
		}, nil
	}

	// New peer — allocate an IP and pick a shard while holding the lock.
	peerIp := srv.ipAllocator.Allocate()
	if peerIp.IsUnspecified() {
		srv.mu.Unlock()
		return peerRegistration{}, errNoAddresses
	}
	shard := srv.pickShard()
	srv.peers[peerKey] = peerState{IP: peerIp, CreatedAt: time.Now()}
	srv.mu.Unlock()

	// Sparse logging to avoid lock contention on the log mutex.
	if srv.shardNext.Load()%100 == 0 {
		clientIP := strings.Split(remoteAddr, ":")[0]
		log.Printf("[%v] new peer %v at %v: %v", srv.BindAddr, clientIP, peerIp, peerKey)
	}

	// Enqueue for batched WireGuard registration and wait for flush.
	pp := pendingPeer{
		config: wgtypes.PeerConfig{
			PublicKey:         peerKey,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{prefixToIPNet(netip.PrefixFrom(peerIp, 32))},
		},
		done: make(chan error, 1),
	}

	select {
	case shard.pendingPeers <- pp:
		// Enqueued.
	default:
		// Shard queue full — rollback.
		srv.mu.Lock()
		delete(srv.peers, peerKey)
		srv.mu.Unlock()
		srv.ipAllocator.Free(peerIp)
		return peerRegistration{}, errShardQueueFull
	}

	if flushErr := <-pp.done; flushErr != nil {
		return peerRegistration{}, fmt.Errorf("%w: %v", errFlushFailed, flushErr)
	}

	return peerRegistration{
		PeerIP:       peerIp,
		PrefixBits:   srv.WgCidr.Bits(),
		ServerPubKey: srv.Key.PublicKey(),
		ListenPort:   WireguardListenPortBase + int(srv.Index),
	}, nil
}

// ---------------------------------------------------------------------------
// Server: UDP listener
// ---------------------------------------------------------------------------

// ListenForUDPRegister starts a UDP listener on UDPRegisterPort that
// accepts encrypted peer registration packets. It blocks until the
// server context is cancelled. Intended to be called as a goroutine
// alongside ListenForHttps:
//
//	go srv.ListenForUDPRegister()
func (srv *Server) ListenForUDPRegister() error {
	key := deriveUDPKey(srv.Password)
	aead, err := newUDPAEAD(key)
	if err != nil {
		return fmt.Errorf("failed to create AEAD cipher: %w", err)
	}

	addr := fmt.Sprintf("%v:%d", srv.BindAddr, UDPRegisterPort)
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	// Increase socket buffers for high-concurrency bursts. With 1000
	// clients sending 81-byte packets, even a 1MB buffer holds ~12,000
	// packets — more than enough to absorb a burst while goroutines
	// drain the queue.
	if udpConn, ok := conn.(*net.UDPConn); ok {
		_ = udpConn.SetReadBuffer(4 << 20)  // 4 MiB
		_ = udpConn.SetWriteBuffer(4 << 20) // 4 MiB
	}

	log.Printf("[%v] UDP register listening on %s", srv.BindAddr, addr)

	// Close the socket when the server shuts down, which unblocks ReadFrom.
	go func() {
		<-srv.Ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 256) // max valid packet is 81 bytes
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if srv.Ctx.Err() != nil {
				return nil // clean shutdown
			}
			// Transient read errors (e.g. ICMP unreachable) are common on
			// UDP sockets; log and continue.
			log.Printf("[%v] UDP read error: %v", srv.BindAddr, err)
			continue
		}

		// Copy the packet — buf is reused on the next iteration.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		go srv.handleUDPRegister(conn, remoteAddr, pkt, aead)
	}
}

// handleUDPRegister processes a single UDP registration request: decrypts
// the packet, registers the peer, and sends an encrypted response. Runs
// in its own goroutine so the read loop isn't blocked by the flush wait.
func (srv *Server) handleUDPRegister(conn net.PacketConn, remoteAddr net.Addr, pkt []byte, aead cipher.AEAD) {
	requestID, peerKey, err := unmarshalRegisterRequest(aead, pkt)
	if err != nil {
		// Invalid or unauthenticated packet. Drop silently — this is the
		// correct behaviour for an encrypted protocol: never reveal to an
		// attacker whether a packet was valid. Could be a port scan, a
		// packet from a client with the wrong password, or random garbage.
		return
	}

	reg, regErr := srv.registerPeer(peerKey, remoteAddr.String())

	var status byte
	switch {
	case regErr == nil:
		status = udpStatusOK
	case errors.Is(regErr, errPeerCapacity):
		status = udpStatusCapacity
	case errors.Is(regErr, errNoAddresses), errors.Is(regErr, errShardQueueFull):
		status = udpStatusUnavailable
	default:
		status = udpStatusError
	}

	respPkt, err := marshalRegisterResponse(aead, requestID, status, reg)
	if err != nil {
		log.Printf("[%v] UDP marshal error: %v", srv.BindAddr, err)
		return
	}

	if _, err := conn.WriteTo(respPkt, remoteAddr); err != nil {
		// WriteTo failures on UDP are usually transient (buffer full,
		// ICMP unreachable). Not worth logging at high volume.
		return
	}
}

// ---------------------------------------------------------------------------
// Client: UDP registration
// ---------------------------------------------------------------------------

// ConnectUDP performs a full connection cycle using UDP registration
// instead of HTTPS. It encrypts the registration request, sends it
// to the server, waits for the encrypted response, and then configures
// the local WireGuard interface identically to Connect().
//
// The client must already have a WireGuard interface created via
// CreateInterface() before calling ConnectUDP().
func (c *Client) ConnectUDP() error {
	resp, err := c.sendUDPRegistration()
	if err != nil {
		return err
	}

	link := c.link()
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("error setting up vprox interface: %v", err)
	}

	if err := c.updateInterface(resp); err != nil {
		return err
	}

	if err := c.configureWireguard(resp); err != nil {
		return fmt.Errorf("error configuring wireguard interface: %v", err)
	}

	return nil
}

// sendUDPRegistration sends an encrypted registration request to the
// server over UDP and returns the parsed response. Retries up to
// udpMaxAttempts times on timeout (packet loss).
func (c *Client) sendUDPRegistration() (connectResponse, error) {
	key := deriveUDPKey(c.Password)
	aead, err := newUDPAEAD(key)
	if err != nil {
		return connectResponse{}, fmt.Errorf("AEAD init: %w", err)
	}

	pubKey := c.Key.PublicKey()

	// Generate a random request ID for response matching.
	var requestID [8]byte
	if _, err := rand.Read(requestID[:]); err != nil {
		return connectResponse{}, fmt.Errorf("rand request ID: %w", err)
	}

	reqPkt, err := marshalRegisterRequest(aead, requestID, pubKey)
	if err != nil {
		return connectResponse{}, fmt.Errorf("marshal request: %w", err)
	}

	// Connected UDP socket: kernel filters replies to this server only.
	serverAddr := fmt.Sprintf("%s:%d", c.ServerIp, UDPRegisterPort)
	conn, err := net.DialTimeout("udp4", serverAddr, 2*time.Second)
	if err != nil {
		return connectResponse{}, fmt.Errorf("UDP dial %s: %w", serverAddr, err)
	}
	defer conn.Close()

	buf := make([]byte, 256)

	for attempt := 0; attempt < udpMaxAttempts; attempt++ {
		deadline := time.Now().Add(udpAttemptTimeout)
		_ = conn.SetDeadline(deadline)

		if _, err := conn.Write(reqPkt); err != nil {
			return connectResponse{}, fmt.Errorf("UDP send: %w", err)
		}

		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // packet lost, retry
			}
			return connectResponse{}, fmt.Errorf("UDP recv: %w", err)
		}

		respID, status, resp, err := unmarshalRegisterResponse(aead, buf[:n])
		if err != nil {
			// Garbled or unauthenticated response — could be spoofed.
			// Retry in case the real response is still in flight.
			continue
		}
		if respID != requestID {
			// Stale response from a previous attempt. Ignore and keep
			// reading (the real response may arrive in the same window).
			continue
		}

		switch status {
		case udpStatusOK:
			return resp, nil
		case udpStatusCapacity:
			return connectResponse{}, ErrResourceExhausted
		case udpStatusUnavailable:
			// Transient — retry.
			continue
		default:
			return connectResponse{}, fmt.Errorf("server error (UDP status %d)", status)
		}
	}

	return connectResponse{}, fmt.Errorf("UDP registration to %s timed out after %d attempts", serverAddr, udpMaxAttempts)
}
