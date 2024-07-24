package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start a VPN server, listening for new WireGuard peers",
	RunE:  runServer,
}

func runServer(cmd *cobra.Command, args []string) error {
	return errors.New("unimplemented")
}
