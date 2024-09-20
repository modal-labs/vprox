package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/modal-labs/vprox/lib"
)

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start a VPN server, listening for new WireGuard peers",
	RunE:  runServer,
}

var serverCmdArgs struct {
	ip           []string
	wgBlock      string
	wgBlockPerIp string
	cloud        string
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
}

func runServer(cmd *cobra.Command, args []string) error {
	cloud := serverCmdArgs.cloud
	if cloud == "aws" {
		client := lib.NewAwsMetadata()
		interfaces, err := client.GetAddresses()
		if err != nil {
			return fmt.Errorf("failed to get AWS MAC addresses: %v", err)
		}
		fmt.Printf("%+v\n", interfaces)
		return errors.New("todo: unimplemented")
	} else if cloud != "" {
		return fmt.Errorf("unknown value of --cloud: %v", cloud)
	}

	if len(serverCmdArgs.ip) == 0 {
		return errors.New("missing required flag: --ip")
	}
	if len(serverCmdArgs.ip) > 1024 {
		return errors.New("too many --ip flags")
	}
	if serverCmdArgs.wgBlock == "" {
		return errors.New("missing required flag: --wg-block")
	}

	wgBlock, err := netip.ParsePrefix(serverCmdArgs.wgBlock)
	if err != nil || !wgBlock.Addr().Is4() {
		return fmt.Errorf("failed to parse --wg-block: %s", serverCmdArgs.wgBlock)
	}
	wgBlock = wgBlock.Masked()

	wgBlockPerIp := wgBlock.Bits()
	if serverCmdArgs.wgBlockPerIp != "" {
		if serverCmdArgs.wgBlockPerIp[0] != '/' {
			return errors.New("--wg-block-per-ip must start with '/'")
		}
		wgBlockPerIp, err = strconv.Atoi(serverCmdArgs.wgBlockPerIp[1:])
		if err != nil {
			return fmt.Errorf("failed to parse --wg-block-per-ip: %v", err)
		}
	}

	if wgBlockPerIp > 30 || wgBlockPerIp < wgBlock.Bits() {
		return fmt.Errorf("invalid value of --wg-block-per-ip: %v", wgBlockPerIp)
	}
	wgBlockCount := 1 << (wgBlockPerIp - wgBlock.Bits())
	if len(serverCmdArgs.ip) > wgBlockCount {
		return fmt.Errorf(
			"not enough IPs in --wg-block for %v --ip flags, please set --wg-block-per-ip",
			len(serverCmdArgs.ip))
	}

	key, err := lib.GetServerKey()
	if err != nil {
		return fmt.Errorf("failed to load server key: %v", err)
	}

	password, err := lib.GetVproxPassword()
	if err != nil {
		return err
	}

	// Make a shared WireGuard client.
	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to initialize wgctrl: %v", err)
	}

	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(5))
	if err != nil {
		return fmt.Errorf("failed to initialize iptables: %v", err)
	}

	// Display the public key, just for information.
	fmt.Printf("%s %s\n",
		color.New(color.Bold).Sprint("server public key:"),
		key.PublicKey().String())

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()
	g, ctx := errgroup.WithContext(ctx)

	wgIp := nextIpBlock(wgBlock.Addr(), 32) // get the ".1" gateway IP address
	for i, ipStr := range serverCmdArgs.ip {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("invalid IPv4 address: %v", ipStr)
		}

		srv := &lib.Server{
			Key:      key,
			BindAddr: ip,
			Password: password,
			Index:    uint16(i),
			Ipt:      ipt,
			WgClient: wgClient,
			WgCidr:   netip.PrefixFrom(wgIp, wgBlockPerIp),
			Ctx:      ctx,
		}
		if err := srv.InitState(); err != nil {
			return err
		}

		// Increment wgIp to be the next block.
		wgIp = nextIpBlock(wgIp, uint(wgBlockPerIp))

		g.Go(func() error {
			if err := srv.StartWireguard(); err != nil {
				return fmt.Errorf("failed to start WireGuard: %v", err)
			}
			defer srv.CleanupWireguard()

			if err := srv.StartIptables(); err != nil {
				return fmt.Errorf("failed to start iptables: %v", err)
			}
			defer srv.CleanupIptables()

			if err := srv.ListenForHttps(); err != nil {
				return fmt.Errorf("https server failed: %v", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

// Increments the given IP address by the given CIDR block size.
func nextIpBlock(ip netip.Addr, size uint) netip.Addr {
	// Copy the IP address to avoid modifying the original.
	ipBytes := ip.As4()

	bits := 8 * uint(len(ipBytes))
	if size > bits {
		log.Panicf("nextIpBlock block size of %v is larger than ip bits %v", size, bits)
	}
	for size > 0 {
		byteIndex := (size - 1) / 8
		bitIndex := 7 - (size-1)%8
		ipBytes[byteIndex] ^= 1 << bitIndex
		if ipBytes[byteIndex]&(1<<bitIndex) > 0 {
			break
		}
		size -= 1
	}

	return netip.AddrFrom4(ipBytes)
}
