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

	"github.com/modal-labs/vprox/lib"
	client "github.com/modal-labs/vprox/rawclient"
)

// ConnectRawCmd is a wgctrl-free variant of ConnectCmd, built on the
// rawclient package's free functions. It exists to map out exactly what a
// minimal client implementation needs.
var ConnectRawCmd = &cobra.Command{
	Use:        "connect-raw [flags] <ip>",
	Short:      "Peer a client connection to a VPN server (wgctrl-free variant)",
	Args:       cobra.ExactArgs(1),
	ArgAliases: []string{"ip"},
	RunE:       runConnectRaw,
}

var connectRawCmdArgs struct {
	ifname string
}

func init() {
	ConnectRawCmd.Flags().StringVar(&connectRawCmdArgs.ifname, "interface",
		"vprox0", "Interface name to proxy traffic through the VPN")
}

// waitForHealthyConnectionRaw sends pings to the vprox server over the
// wireguard tunnel until one succeeds or the deadline is exceeded.
func waitForHealthyConnectionRaw(ctx context.Context, ifname string, wgCidr netip.Prefix) bool {
	// Retry failed healthchecks for up to 20s before declaring the connection unhealthy.
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for {
		if client.CheckConnection(ifname, wgCidr, healthCheckTimeout, ctx) {
			return true
		}
		log.Printf("health check failed, retrying...")
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func runConnectRaw(cmd *cobra.Command, args []string) error {
	serverIp, err := netip.ParseAddr(args[0])
	if err != nil || !serverIp.Is4() {
		return fmt.Errorf("invalid IP address %s", args[0])
	}

	ifname := connectRawCmdArgs.ifname

	key, err := client.LoadOrGenerateClientKey(ifname)
	if err != nil {
		return fmt.Errorf("failed to load client key: %v", err)
	}

	token, err := lib.GetClientToken()
	if err != nil {
		return err
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     dialWithRetry,
		},
	}

	// Protect resource-cleanup work (executed in defer statements below) by
	// registering a signal handler. We make sure that cleanup work is done when
	// we receive a SIGINT/SIGKILL.
	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	if err = client.CreateInterface(ifname); err != nil {
		return err
	}
	defer client.DeleteInterface(ifname)

	resp, wgCidr, err := client.RequestPeerIP(httpClient, serverIp, token, key, ifname)
	if err != nil {
		return err
	}
	if err = client.AddInterfaceAddr(ifname, wgCidr); err != nil {
		return err
	}
	if err = client.ConfigurePeer(resp, serverIp, key, ifname); err != nil {
		return err
	}
	// Notify the server when we disconnect so it can reclaim resources immediately.
	defer func() {
		log.Println("About send /disconnect request to server.")
		if err := client.Disconnect(httpClient, serverIp, token, key); err != nil {
			log.Printf("warning: failed to disconnect from server: %v", err)
		}
	}()

	log.Println("Connected...")
	if !waitForHealthyConnectionRaw(ctx, ifname, wgCidr) {
		return fmt.Errorf("connection failed initial healthcheck")
	}

	for {
		// currently in a healthy state
		select {
		case <-ctx.Done():
			log.Println("Context is Done. Returning from runConnectRaw.")
			return nil
		case <-time.After(healthCheckInterval):
		}

		currentStatus := client.CheckConnection(ifname, wgCidr, healthCheckTimeout, ctx)

		if !currentStatus {
			log.Println("No longer connected. Attempting to reconnect...")
		unhealthy_loop:
			for {
				// currently in an unhealthy state
				var resp client.ConnectResponse
				var newCidr netip.Prefix
				resp, newCidr, err = client.RequestPeerIP(httpClient, serverIp, token, key, ifname)
				if err == nil && newCidr != wgCidr {
					client.RemoveInterfaceAddr(ifname, wgCidr)
					err = client.AddInterfaceAddr(ifname, newCidr)
				}
				if err == nil {
					err = client.ConfigurePeer(resp, serverIp, key, ifname)
				}
				if err == nil {
					wgCidr = newCidr
					log.Println("Reconnected...")
					break unhealthy_loop
				}
				if !client.IsRecoverableError(err) {
					return fmt.Errorf("unrecoverable connection error: %w", err)
				}
				log.Printf("Failed to reconnect: %v", err)
				select {
				case <-ctx.Done():
					log.Println("Context is Done; received SIGINT or SIGTERM. Breaking out of unhealthy_loop.")
					break unhealthy_loop
				case <-time.After(reconnectInterval):
				}
			}
		}
	}
}
