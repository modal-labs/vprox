package cmd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	serverIp := net.ParseIP(args[0])
	if serverIp == nil {
		return errors.New("invalid IP address")
	}
	serverIp = serverIp.To4()
	if serverIp == nil {
		return errors.New("only IPv4 addresses are supported")
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

	for {
		fmt.Println("running...")
		time.Sleep(5 * time.Second)
	}
}
