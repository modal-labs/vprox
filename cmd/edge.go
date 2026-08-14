package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/modal-labs/vprox/lib"
)

const edgeHealthCheckInterval = 2 * time.Second
const edgeHealthCheckTimeout = 5 * time.Second
const edgeReconnectInterval = 2 * time.Second

var EdgeCmd = &cobra.Command{
	Use:        "edge [flags] <server-ip>",
	Short:      "Connect to a VPN server as an edge node, advertising local routes",
	Args:       cobra.ExactArgs(1),
	ArgAliases: []string{"server-ip"},
	RunE:       runEdge,
}

var edgeCmdArgs struct {
	ifname string
	routes string
}

func init() {
	EdgeCmd.Flags().StringVar(&edgeCmdArgs.ifname, "interface",
		"vprox-edge0", "WireGuard interface name for the edge tunnel")
	EdgeCmd.Flags().StringVar(&edgeCmdArgs.routes, "routes",
		"", "Comma-separated CIDR prefixes to advertise (e.g. 10.0.5.0/24,172.16.0.0/12)")
}

func runEdge(cmd *cobra.Command, args []string) error {
	serverIp, err := netip.ParseAddr(args[0])
	if err != nil || !serverIp.Is4() {
		return fmt.Errorf("invalid IPv4 address: %s", args[0])
	}

	if edgeCmdArgs.routes == "" {
		return errors.New("missing required flag: --routes")
	}

	// Parse and validate routes.
	var routes []netip.Prefix
	for _, r := range strings.Split(edgeCmdArgs.routes, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(r)
		if err != nil {
			return fmt.Errorf("invalid route CIDR %q: %v", r, err)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("only IPv4 routes are supported: %q", r)
		}
		routes = append(routes, prefix.Masked())
	}
	if len(routes) == 0 {
		return errors.New("at least one route must be specified with --routes")
	}

	key, err := lib.GetClientKey(edgeCmdArgs.ifname)
	if err != nil {
		return fmt.Errorf("failed to load edge key: %v", err)
	}

	token, err := lib.GetClientToken()
	if err != nil {
		return err
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to initialize wgctrl: %v", err)
	}

	edge := &lib.EdgeClient{
		Key:      key,
		Ifname:   edgeCmdArgs.ifname,
		ServerIp: serverIp,
		Token:    token,
		Routes:   routes,
		WgClient: wgClient,
		Http: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialWithRetry(ctx, network, addr)
				},
			},
		},
	}

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	if err := edge.CreateInterface(); err != nil {
		return err
	}
	defer edge.DeleteInterface()

	if err := edge.Connect(); err != nil {
		return err
	}
	defer func() {
		log.Println("Sending /edge-disconnect request to server.")
		if err := edge.Disconnect(); err != nil {
			log.Printf("warning: failed to disconnect from server: %v", err)
		}
	}()

	if err := edge.SetupForwarding(); err != nil {
		return fmt.Errorf("failed to set up forwarding: %v", err)
	}
	defer func() {
		if err := edge.CleanupForwarding(); err != nil {
			log.Printf("warning: failed to clean up forwarding rules: %v", err)
		}
	}()

	log.Printf("Edge connected, advertising routes: %v", routes)
	if !edge.CheckConnection(edgeHealthCheckTimeout, ctx) {
		return fmt.Errorf("edge connection failed initial healthcheck after %v", edgeHealthCheckTimeout)
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("Context done. Returning from runEdge.")
			return nil
		case <-time.After(edgeHealthCheckInterval):
		}

		if !edge.CheckConnection(edgeHealthCheckTimeout, ctx) {
			log.Println("Edge tunnel unhealthy. Attempting to reconnect...")
		unhealthy_loop:
			for {
				err = edge.Connect()
				if err == nil {
					log.Println("Edge reconnected.")
					break unhealthy_loop
				}
				if !lib.IsRecoverableError(err) {
					return fmt.Errorf("unrecoverable edge connection error: %w", err)
				}
				log.Printf("Failed to reconnect edge: %v", err)
				select {
				case <-ctx.Done():
					log.Println("Context done during reconnect. Breaking out.")
					break unhealthy_loop
				case <-time.After(edgeReconnectInterval):
				}
			}
		}
	}
}
