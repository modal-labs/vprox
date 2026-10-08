package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/modal-labs/vprox/lib"
)

// awsPollInterval is how often AWS metadata is polled for bind address changes.
const awsPollInterval = 5 * time.Second

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start a VPN server, listening for new WireGuard peers",
	RunE:  runServerCommand,
}

var serverCmdArgs struct {
	ip           []string
	wgBlock      string
	wgBlockPerIp string
	cloud        string
	takeover     bool
}

// serverConfig is the validated configuration parsed from the server command's flags.
type serverConfig struct {
	// bindAddrs is the set of addresses to serve on when not discovering them from a cloud provider.
	bindAddrs []netip.Addr

	// wgBlock is the block of tunnel addresses shared by all servers on this host.
	wgBlock netip.Prefix

	// wgBlockPerIp is the prefix length of the tunnel address block given to each server.
	wgBlockPerIp uint

	// cloud is the cloud provider to discover bind addresses from, or empty to use bindAddrs.
	cloud string

	takeover bool
}

func init() {
	ServerCmd.Flags().StringArrayVar(&serverCmdArgs.ip, "ip",
		[]string{}, "IPv4 address to bind to")
	ServerCmd.Flags().StringVar(&serverCmdArgs.wgBlock, "wg-block",
		"", "Block of IPs for WireGuard peers, must be unique between servers")
	ServerCmd.Flags().StringVar(&serverCmdArgs.wgBlockPerIp, "wg-block-per-ip",
		"", "WireGuard block size for each --ip flag, if multiple are provided")
	ServerCmd.Flags().StringVar(&serverCmdArgs.cloud, "cloud",
		"", "Cloud provider for IP metadata (watches for changes)")
	ServerCmd.Flags().BoolVar(&serverCmdArgs.takeover, "takeover",
		false, "Take over existing WireGuard state from a previous server instance (for non-disruptive upgrades)")
}

func runServerCommand(cmd *cobra.Command, args []string) error {
	config, err := parseServerConfig(serverCmdArgs.ip, serverCmdArgs.wgBlock, serverCmdArgs.wgBlockPerIp, serverCmdArgs.cloud, serverCmdArgs.takeover)
	if err != nil {
		return err
	}

	key, err := lib.GetServerKey()
	if err != nil {
		return fmt.Errorf("failed to load server key: %v", err)
	}

	auth, err := lib.GetAuthenticator()
	if err != nil {
		return err
	}

	ctx, stopSignalHandling := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignalHandling()

	manager, err := lib.NewServerManager(config.wgBlock, config.wgBlockPerIp, ctx, key, auth, config.takeover)
	if err != nil {
		return err
	}
	defer lib.WaitForServersToExit(manager)

	if config.cloud == "aws" {
		return serveOnAwsAddresses(ctx, manager)
	}
	return serveOnFixedAddresses(manager, config.bindAddrs)
}

// parseServerConfig validates the server command's flag values and returns the
// resulting configuration.
func parseServerConfig(ipFlags []string, wgBlockFlag string, wgBlockPerIpFlag string, cloud string, takeover bool) (serverConfig, error) {
	if cloud != "" && cloud != "aws" {
		return serverConfig{}, fmt.Errorf("unknown value of --cloud: %v", cloud)
	}
	if cloud == "" && len(ipFlags) == 0 {
		return serverConfig{}, errors.New("missing required flag: --ip")
	}
	if len(ipFlags) > 1024 {
		return serverConfig{}, errors.New("too many --ip flags")
	}
	if wgBlockFlag == "" {
		return serverConfig{}, errors.New("missing required flag: --wg-block")
	}

	wgBlock, err := netip.ParsePrefix(wgBlockFlag)
	if err != nil || !wgBlock.Addr().Is4() {
		return serverConfig{}, fmt.Errorf("failed to parse --wg-block: %s", wgBlockFlag)
	}
	wgBlock = wgBlock.Masked()

	wgBlockPerIp := uint(wgBlock.Bits())
	if wgBlockPerIpFlag != "" {
		if wgBlockPerIpFlag[0] != '/' {
			return serverConfig{}, errors.New("--wg-block-per-ip must start with '/'")
		}
		parsedBits, err := strconv.ParseUint(wgBlockPerIpFlag[1:], 10, 0)
		if err != nil {
			return serverConfig{}, fmt.Errorf("failed to parse --wg-block-per-ip: %v", err)
		}
		wgBlockPerIp = uint(parsedBits)
	}
	if wgBlockPerIp > 30 || wgBlockPerIp < uint(wgBlock.Bits()) {
		return serverConfig{}, fmt.Errorf("invalid value of --wg-block-per-ip: %v", wgBlockPerIp)
	}

	wgBlockCount := 1 << (wgBlockPerIp - uint(wgBlock.Bits()))
	if len(ipFlags) > wgBlockCount {
		return serverConfig{}, fmt.Errorf(
			"not enough IPs in --wg-block for %v --ip flags, please set --wg-block-per-ip",
			len(ipFlags))
	}

	bindAddrs := make([]netip.Addr, 0, len(ipFlags))
	for _, ipFlag := range ipFlags {
		bindAddr, err := netip.ParseAddr(ipFlag)
		if err != nil || !bindAddr.Is4() {
			return serverConfig{}, fmt.Errorf("invalid IPv4 address: %q", ipFlag)
		}
		bindAddrs = append(bindAddrs, bindAddr)
	}

	return serverConfig{
		bindAddrs:    bindAddrs,
		wgBlock:      wgBlock,
		wgBlockPerIp: wgBlockPerIp,
		cloud:        cloud,
		takeover:     takeover,
	}, nil
}

// serveOnFixedAddresses starts a server on each of bindAddrs and blocks until
// they all exit.
func serveOnFixedAddresses(manager *lib.ServerManager, bindAddrs []netip.Addr) error {
	for _, bindAddr := range bindAddrs {
		if err := lib.StartServerOnAddress(manager, bindAddr); err != nil {
			return err
		}
	}
	lib.WaitForServersToExit(manager)
	return nil
}

// serveOnAwsAddresses starts a server on each private IP of this instance's
// primary network interface, then keeps the running servers in sync with the
// instance's private IPs every awsPollInterval until ctx is done.
func serveOnAwsAddresses(ctx context.Context, manager *lib.ServerManager) error {
	awsMetadata := lib.NewAwsMetadata()
	servedAddrs, err := reconcileServersWithAwsAddresses(awsMetadata, make(addrSet), manager)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(awsPollInterval)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			servedAddrs, err = reconcileServersWithAwsAddresses(awsMetadata, servedAddrs, manager)
			if err != nil {
				fmt.Printf("error during aws poll: %v", err)
			}
		}
	}
}

type addrSet map[netip.Addr]struct{}

// parseAddrSet returns the set of IPv4 addresses parsed from ipStrs.
func parseAddrSet(ipStrs []string) (addrSet, error) {
	addrs := make(addrSet)
	for _, ipStr := range ipStrs {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("invalid IPv4 address: %v", ipStr)
		}
		addrs[addr] = struct{}{}
	}
	return addrs, nil
}

// reconcileServersWithAwsAddresses stops servers on addresses that the AWS
// instance no longer has and starts servers on addresses it has gained.
// Returns the set of addresses that have a server after reconciling.
func reconcileServersWithAwsAddresses(awsMetadata *lib.AwsMetadata, servedAddrs addrSet, manager *lib.ServerManager) (addrSet, error) {
	interfaces, err := awsMetadata.GetAddresses()
	if err != nil {
		return servedAddrs, fmt.Errorf("failed to get AWS MAC addresses: %v", err)
	}

	instanceAddrs, err := parseAddrSet(interfaces[0].PrivateIps)
	if err != nil {
		return servedAddrs, err
	}

	for addr := range servedAddrs {
		if _, ok := instanceAddrs[addr]; !ok {
			lib.StopServerOnAddress(manager, addr)
			delete(servedAddrs, addr)
		}
	}

	for addr := range instanceAddrs {
		if _, ok := servedAddrs[addr]; !ok {
			if err := lib.StartServerOnAddress(manager, addr); err != nil {
				return servedAddrs, fmt.Errorf("error starting new ip: %v", err)
			}
			servedAddrs[addr] = struct{}{}
		}
	}
	return servedAddrs, nil
}
