package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/netip"
	"os/signal"
	"syscall"
	"time"

	"github.com/modal-labs/vprox/lib"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var ConnectCmd = &cobra.Command{
	Use:        "connect [flags] <ip>",
	Short:      "Peer a client connection to a VPN server",
	Args:       cobra.ExactArgs(1),
	ArgAliases: []string{"ip"},
	RunE:       runConnect,
}

var connectCmdArgs struct {
	ifname string
}

func init() {
	ConnectCmd.Flags().StringVar(&connectCmdArgs.ifname, "interface",
		"vprox0", "Interface name to proxy traffic through the VPN")
}

func runConnect(cmd *cobra.Command, args []string) error {
	serverIp, err := netip.ParseAddr(args[0])
	if err != nil || !serverIp.Is4() {
		return fmt.Errorf("invalid IP address %s", args[0])
	}

	key, err := lib.GetClientKey(connectCmdArgs.ifname)
	if err != nil {
		return fmt.Errorf("failed to load server key: %v", err)
	}

	password, err := lib.GetVproxPassword()
	if err != nil {
		return err
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to initialize wgctrl: %v", err)
	}

	client := &lib.Client{
		Key:      key,
		Ifname:   connectCmdArgs.ifname,
		ServerIp: serverIp,
		Password: password,
		WgClient: wgClient,
		Http: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	err = client.CreateInterface()
	if err != nil {
		return err
	}
	defer client.DeleteInterface()

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

loop:
	for {
		fmt.Println("running...")
		select {
		case <-ctx.Done():
			break loop
		case <-time.After(5 * time.Second):
		}
	}

	return nil
}
