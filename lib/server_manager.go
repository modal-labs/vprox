package lib

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/fatih/color"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type ServerInfo struct {
	i      uint16
	cancel context.CancelFunc
	srv    *Server
}

// ServerManager handles creating and terminating servers on ips
// ServerManager is not thread safe for concurrent access.
type ServerManager struct {
	wgClient      *wgctrl.Client
	ipt           *iptables.IPTables
	key           wgtypes.Key
	auth          *Authenticator
	ctx           context.Context
	waitGroup     *sync.WaitGroup
	wgBlock       netip.Prefix
	wgBlockPerIp  uint
	activeServers map[netip.Addr]ServerInfo

	// freeIndices and nextFreeIndex together track usage of the range 0..numWgBlocks
	freeIndices   []uint16 // stack of indices that are free
	nextFreeIndex uint16   // next free index not in the stack

	// takeover indicates servers should take over existing WireGuard state
	// instead of creating fresh interfaces. Used for non-disruptive upgrades.
	takeover bool
}

// NewServerManager creates a new server manager
func NewServerManager(wgBlock netip.Prefix, wgBlockPerIp uint, ctx context.Context, key wgtypes.Key, auth *Authenticator, takeover bool) (*ServerManager, error) {
	// Make a shared WireGuard client.
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize wgctrl: %v", err)
	}

	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(5))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize iptables: %v", err)
	}

	// Display the public key, just for information.
	fmt.Printf("%s %s\n",
		color.New(color.Bold).Sprint("server public key:"),
		key.PublicKey().String())

	StartMetricsServer(ctx)

	sm := new(ServerManager)
	sm.wgClient = wgClient
	sm.ipt = ipt
	sm.key = key
	sm.auth = auth
	sm.ctx = ctx
	sm.waitGroup = new(sync.WaitGroup)
	sm.wgBlock = wgBlock.Masked()
	sm.wgBlockPerIp = wgBlockPerIp
	sm.activeServers = make(map[netip.Addr]ServerInfo)
	sm.takeover = takeover
	return sm, nil
}

// allocateIndex attempts to allocate a new index for a server
func (sm *ServerManager) allocateIndex() (uint16, error) {
	l := len(sm.freeIndices)
	if l > 0 {
		defer func() {
			sm.freeIndices = sm.freeIndices[:l-1]
		}()
		return sm.freeIndices[l-1], nil
	} else {
		wgBlockCount := uint16(1) << (sm.wgBlockPerIp - uint(sm.wgBlock.Bits()))
		if sm.nextFreeIndex == wgBlockCount {
			return 0xFFFF, fmt.Errorf("no more free indices for provided number of wireguard blocks")
		}
		defer func() {
			sm.nextFreeIndex += 1
		}()
		return sm.nextFreeIndex, nil
	}
}

// freeIndex frees the specified index
func (sm *ServerManager) freeIndex(i uint16) {
	sm.freeIndices = append(sm.freeIndices, i)
}

// Start creates a new server on the specified ip.
func (sm *ServerManager) Start(ip netip.Addr) error {
	return sm.startInternal(ip, nil)
}

// StartWithListener creates a new server on the specified ip, reusing an
// existing TCP listener instead of binding a new one. This is used during
// upgrades when the old process hands off its listener FDs via a Unix socket.
func (sm *ServerManager) StartWithListener(ip netip.Addr, listener net.Listener) error {
	return sm.startInternal(ip, listener)
}

// startInternal is the shared implementation for Start and StartWithListener.
// If listener is non-nil it is passed to the Server as an InheritedListener.
func (sm *ServerManager) startInternal(ip netip.Addr, listener net.Listener) error {
	// Idempotency: if a server is already running on this IP, skip.
	if _, exists := sm.activeServers[ip]; exists {
		log.Printf("[%v] server already running, skipping", ip)
		return nil
	}

	i, err := sm.allocateIndex()
	if err != nil {
		return err
	}
	subctx, cancel := context.WithCancel(sm.ctx)

	subnetStart := AfterCountIpBlock(sm.wgBlock.Addr(), sm.wgBlockPerIp, uint(i))
	wgCidr := netip.PrefixFrom(subnetStart.Next(), int(sm.wgBlockPerIp))

	srv := &Server{
		Key:               sm.key,
		BindAddr:          ip,
		Auth:              sm.auth,
		Index:             i,
		Ipt:               sm.ipt,
		WgClient:          sm.wgClient,
		WgCidr:            wgCidr,
		Ctx:               subctx,
		takeover:          sm.takeover,
		InheritedListener: listener,
	}
	if listener != nil {
		srv.Serving = make(chan struct{})
	}
	if err := srv.InitState(); err != nil {
		_ = cancel // cancel should be discarded
		sm.freeIndex(i)
		return err
	}

	sm.waitGroup.Add(1)
	go func() {
		defer sm.waitGroup.Done()
		defer sm.freeIndex(i)

		if err := srv.StartWireguard(); err != nil {
			log.Printf("[%v] failed to start WireGuard: %v", ip, err)
			return
		}
		defer srv.CleanupWireguard()

		if err := srv.StartIptables(); err != nil {
			log.Printf("[%v] failed to start iptables: %v", ip, err)
			return
		}
		defer srv.CleanupIptables()

		if err := srv.ListenForHttps(); err != nil {
			log.Printf("[%v] https server failed: %v", ip, err)
			return
		}
	}()

	sm.activeServers[ip] = ServerInfo{i, cancel, srv}
	return nil
}

// Wait blocks until the running servers exit.
func (sm *ServerManager) Wait() {
	sm.waitGroup.Wait()
}

// Stop stops the server at the specified ip address
func (sm *ServerManager) Stop(ip netip.Addr) {
	server, ok := sm.activeServers[ip]
	if !ok {
		log.Printf("tried to stop, but no server started at %v", ip)
		return
	}
	server.cancel()
}

// RelinquishServer marks the server at the given IP as relinquished (preserving
// WireGuard state on exit) and then cancels it so it shuts down gracefully.
// This is used during upgrades so the new binary can take over the interfaces.
func (sm *ServerManager) RelinquishServer(ip netip.Addr) {
	sm.MarkRelinquished(ip)
	sm.Stop(ip)
}

// MarkRelinquished sets the relinquished flag on the server at the given IP
// without cancelling its context. The server will start returning 503 on
// /connect and /disconnect, and will skip WireGuard + iptables cleanup when
// it eventually shuts down. This is the first half of a two-phase upgrade;
// CancelAll provides the second half after FD handoff completes.
func (sm *ServerManager) MarkRelinquished(ip netip.Addr) {
	server, ok := sm.activeServers[ip]
	if !ok {
		log.Printf("tried to mark relinquished, but no server at %v", ip)
		return
	}
	server.srv.mu.Lock()
	server.srv.relinquished = true
	server.srv.mu.Unlock()
	log.Printf("[%v] server marked relinquished — WireGuard state will be preserved on exit", ip)
}

// CancelAll cancels every active server's context, triggering graceful
// shutdown of their HTTPS listeners. Used after FD handoff to let the old
// process exit while the new process is already accepting connections.
func (sm *ServerManager) CancelAll() {
	for ip, server := range sm.activeServers {
		log.Printf("[%v] cancelling server context", ip)
		server.cancel()
	}
}

// CollectListenerFiles returns a dup'd *os.File for every active server's
// TCP listener, along with matching metadata. The caller must close the
// returned files when done. The files can be sent to another process via
// SCM_RIGHTS for a zero-downtime listener handoff.
func (sm *ServerManager) CollectListenerFiles() ([]*os.File, []ListenerMeta, error) {
	var files []*os.File
	var meta []ListenerMeta
	for ip, info := range sm.activeServers {
		f, err := info.srv.ListenerFile()
		if err != nil {
			// Close any files we already collected.
			for _, f := range files {
				f.Close()
			}
			return nil, nil, fmt.Errorf("failed to get listener FD for %v: %v", ip, err)
		}
		files = append(files, f)
		meta = append(meta, ListenerMeta{
			BindAddr: ip.String(),
			Index:    info.i,
		})
	}
	return files, meta, nil
}

// WaitAllServing blocks until every active server whose Serving channel is
// non-nil has closed it (i.e. is actively calling Accept on its listener).
// This is used during upgrades so the handoff ack is deferred until the new
// process is ready to handle requests.
func (sm *ServerManager) WaitAllServing() {
	for _, info := range sm.activeServers {
		if info.srv.Serving != nil {
			<-info.srv.Serving
		}
	}
}

// ActiveIPs returns the list of currently active server IP addresses.
func (sm *ServerManager) ActiveIPs() []netip.Addr {
	ips := make([]netip.Addr, 0, len(sm.activeServers))
	for ip := range sm.activeServers {
		ips = append(ips, ip)
	}
	return ips
}

// WgBlock returns the WireGuard CIDR block.
func (sm *ServerManager) WgBlock() netip.Prefix {
	return sm.wgBlock
}

// WgBlockPerIp returns the per-IP WireGuard block size.
func (sm *ServerManager) WgBlockPerIp() uint {
	return sm.wgBlockPerIp
}
