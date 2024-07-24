package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

var ConnectCmd = &cobra.Command{
	Use:        "connect [flags] <interface>",
	Short:      "Peer a client connection to a VPN server",
	Args:       cobra.ExactArgs(1),
	ArgAliases: []string{"interface"},
	RunE:       runConnect,
}

func runConnect(cmd *cobra.Command, args []string) error {
	ifname := args[0]
	_ = ifname
	return errors.New("unimplemented")
}
