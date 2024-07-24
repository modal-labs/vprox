package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "Print out all WireGuard devices",
	RunE:  runList,
}

func runList(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return errors.New("list command does not take any arguments")
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to initialize wgctrl: %v", err)
	}

	devices, err := client.Devices()
	if err != nil {
		return fmt.Errorf("failed to get devices: %v", err)
	}

	fmt.Printf("found %d device(s)\n", len(devices))
	for i, device := range devices {
		fmt.Printf("device %v: %s\n", i, device.Name)
	}

	return nil
}
