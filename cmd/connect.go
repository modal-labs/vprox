package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/modal-labs/vprox/lib"
)

var HEALTH_CHECK_INTERVAL = 3 * time.Second // when we're healthy, how frequently do we
// check if we're healthy? (note that this dosen't include the time spent checking, which is at least 2 seconds)

var HEALTH_CHECK_TIMEOUT = 5 * time.Second // how long do we wait before the health check times out?
var RECONNECT_INTERVAL = 2 * time.Second   // when we're unhealthy, how frequently do we try reconnecting?

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

	err = client.Connect()
	if err != nil {
		return err
	}
	defer client.DeleteInterface()

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	log.Println("Connected...")
	if !client.CheckConnection(HEALTH_CHECK_TIMEOUT, ctx) {
		return fmt.Errorf("connection immediately turned bad after connecting: %v", err)
	}

	for {
		// currently in a healthy state
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(HEALTH_CHECK_INTERVAL):
		}

		currentStatus := client.CheckConnection(HEALTH_CHECK_TIMEOUT, ctx)

		if !currentStatus {
			log.Println("No longer connected. Attempting to reconnect...")
		unhealthy_loop:
			for {
				// currently in an unhealthy state
				err = client.Reconnect()
				if err == nil {
					log.Println("Reconnected...")
					break unhealthy_loop
				}

				select {
				case <-ctx.Done():
					break unhealthy_loop
				case <-time.After(RECONNECT_INTERVAL):
				}
			}
		}
	}
}
