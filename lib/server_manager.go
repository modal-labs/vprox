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

type ServerInfo struct {
	i      uint16
	cancel context.CancelFunc
}

// ServerManager handles creating and terminating servers on ips
// ServerManager is not thread safe for concurrent access.
type ServerManager struct {
	wgClient      *wgctrl.Client
	ipt           *iptables.IPTables
	key           wgtypes.Key
	password      string
	ctx           context.Context
	waitGroup     *sync.WaitGroup
	wgBlock       netip.Prefix
	wgBlockPerIp  uint
	activeServers map[netip.Addr]ServerInfo

	// freeIndices and nextFreeIndex together track usage of the range 0..numWgBlocks
	freeIndices   []uint16 // stack of indices that are free
	nextFreeIndex uint16   // next free index not in the stack
}

// NewServerManager creates a new server manager
func NewServerManager(wgBlock netip.Prefix, wgBlockPerIp uint, ctx context.Context, key wgtypes.Key, password string) (*ServerManager, error) {
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

	sm := new(ServerManager)
	sm.wgClient = wgClient
	sm.ipt = ipt
	sm.key = key
	sm.password = password
	sm.ctx = ctx
	sm.waitGroup = new(sync.WaitGroup)
	sm.wgBlock = wgBlock.Masked()
	sm.wgBlockPerIp = wgBlockPerIp
	sm.activeServers = make(map[netip.Addr]ServerInfo)
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
	i, err := sm.allocateIndex()
	if err != nil {
		return err
	}
	subctx, cancel := context.WithCancel(sm.ctx)

	subnetStart := AfterCountIpBlock(sm.wgBlock.Addr(), sm.wgBlockPerIp, uint(i))
	wgCidr := netip.PrefixFrom(subnetStart.Next(), int(sm.wgBlockPerIp))

	srv := &Server{
		Key:      sm.key,
		BindAddr: ip,
		Password: sm.password,
		Index:    i,
		Ipt:      sm.ipt,
		WgClient: sm.wgClient,
		WgCidr:   wgCidr,
		Ctx:      subctx,
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

	sm.activeServers[ip] = ServerInfo{i, cancel}
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
