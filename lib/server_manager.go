package lib

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/fatih/color"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// runningServer is the manager's handle on one started server.
type runningServer struct {
	index       uint16
	cancelToken context.CancelFunc
}

// ServerManager is the set of servers running on this host, one per bind
// address, plus the resources they share. It is not safe for concurrent use.
type ServerManager struct {
	wgClient      *wgctrl.Client
	ipt           *iptables.IPTables
	key           wgtypes.Key
	auth          *Authenticator
	ctx           context.Context
	waitGroup     *sync.WaitGroup
	wgBlock       netip.Prefix
	wgBlockPerIp  uint
	activeServers map[netip.Addr]runningServer

	// freeIndices is a stack of server indices below nextFreeIndex that are
	// not in use.
	freeIndices []uint16

	// nextFreeIndex is the lowest server index that has never been handed out.
	nextFreeIndex uint16

	// takeover is whether new servers adopt WireGuard state left behind by a
	// previous server instance instead of creating fresh interfaces.
	takeover bool
}

// NewServerManager returns a ServerManager that carves per-server WireGuard
// CIDRs of size wgBlockPerIp out of wgBlock, and starts the metrics server.
func NewServerManager(wgBlock netip.Prefix, wgBlockPerIp uint, ctx context.Context, key wgtypes.Key, auth *Authenticator, takeover bool) (*ServerManager, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize wgctrl: %v", err)
	}

	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(5))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize iptables: %v", err)
	}

	fmt.Printf("%s %s\n",
		color.New(color.Bold).Sprint("server public key:"),
		key.PublicKey().String())

	startMetricsServer()

	return &ServerManager{
		wgClient:      wgClient,
		ipt:           ipt,
		key:           key,
		auth:          auth,
		ctx:           ctx,
		waitGroup:     new(sync.WaitGroup),
		wgBlock:       wgBlock.Masked(),
		wgBlockPerIp:  wgBlockPerIp,
		activeServers: make(map[netip.Addr]runningServer),
		takeover:      takeover,
	}, nil
}

// StartServerOnAddress starts a server bound to bindAddr in the background and
// returns once its state is initialized. Returns an error if no server index is
// free or if the server's state could not be initialized.
func StartServerOnAddress(manager *ServerManager, bindAddr netip.Addr) error {
	index, err := allocateServerIndex(manager)
	if err != nil {
		return err
	}

	serverCtx, cancelToken := context.WithCancel(manager.ctx)
	server, err := newServer(serverCtx, manager.key, manager.auth, manager.ipt, manager.wgClient,
		bindAddr, index, serverWireguardCidr(manager, index))
	if err != nil {
		cancelToken()
		freeServerIndex(manager, index)
		return err
	}

	if manager.takeover && wireguardInterfaceExists(server) {
		log.Printf("[%v] takeover: inheriting state from existing WireGuard device", bindAddr)
		if err := inheritPeersFromWireguardInterface(server); err != nil {
			cancelToken()
			freeServerIndex(manager, index)
			return fmt.Errorf("failed to initialize state from WireGuard: %v", err)
		}
		runServerInBackground(manager, server, reuseExistingWireguardInterface)
	} else {
		if manager.takeover {
			log.Printf("[%v] takeover: WireGuard device not found, starting fresh", bindAddr)
		}
		runServerInBackground(manager, server, createFreshWireguardInterface)
	}

	manager.activeServers[bindAddr] = runningServer{index, cancelToken}
	return nil
}

// runServerInBackground brings up the server's WireGuard interface with
// setUpWireguardInterface, installs its iptables rules, and serves its control
// API in a goroutine that tears everything down and frees the server's index
// when the server's context is done.
func runServerInBackground(manager *ServerManager, server *Server, setUpWireguardInterface func(*Server) error) {
	manager.waitGroup.Add(1)
	go func() {
		defer manager.waitGroup.Done()
		defer freeServerIndex(manager, server.Index)

		if err := setUpWireguardInterface(server); err != nil {
			log.Printf("[%v] failed to start WireGuard: %v", server.BindAddr, err)
			return
		}
		defer deleteWireguardInterfaceUnlessRelinquished(server)

		if err := addIptablesRules(server); err != nil {
			log.Printf("[%v] failed to start iptables: %v", server.BindAddr, err)
			return
		}
		defer removeIptablesRules(server)

		if err := listenForHttps(server); err != nil {
			log.Printf("[%v] https server failed: %v", server.BindAddr, err)
			return
		}
	}()
}

// StopServerOnAddress cancels the server bound to bindAddr. Its WireGuard
// interface and iptables rules are torn down by the server's own goroutine.
func StopServerOnAddress(manager *ServerManager, bindAddr netip.Addr) {
	server, ok := manager.activeServers[bindAddr]
	if !ok {
		log.Printf("tried to stop, but no server started at %v", bindAddr)
		return
	}
	server.cancelToken()
	delete(manager.activeServers, bindAddr)
}

// WaitForServersToExit blocks until every started server has exited.
func WaitForServersToExit(manager *ServerManager) {
	manager.waitGroup.Wait()
}

// serverWireguardCidr returns the WireGuard CIDR for the server at index, which
// is the index-th block of size wgBlockPerIp within the manager's wgBlock.
func serverWireguardCidr(manager *ServerManager, index uint16) netip.Prefix {
	blockStart := AfterCountIpBlock(manager.wgBlock.Addr(), manager.wgBlockPerIp, uint(index))
	return netip.PrefixFrom(blockStart.Next(), int(manager.wgBlockPerIp))
}

// allocateServerIndex returns the lowest free server index, preferring indices
// that were previously freed. Returns an error if every index that fits in the
// manager's wgBlock is in use.
func allocateServerIndex(manager *ServerManager) (uint16, error) {
	if freeCount := len(manager.freeIndices); freeCount > 0 {
		index := manager.freeIndices[freeCount-1]
		manager.freeIndices = manager.freeIndices[:freeCount-1]
		return index, nil
	}

	wgBlockCount := uint16(1) << (manager.wgBlockPerIp - uint(manager.wgBlock.Bits()))
	if manager.nextFreeIndex == wgBlockCount {
		return 0xFFFF, fmt.Errorf("no more free indices for provided number of wireguard blocks")
	}
	index := manager.nextFreeIndex
	manager.nextFreeIndex += 1
	return index, nil
}

func freeServerIndex(manager *ServerManager, index uint16) {
	manager.freeIndices = append(manager.freeIndices, index)
}
