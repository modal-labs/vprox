package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func runList(cmd *cobra.Command, args []string) {
	client, err := wgctrl.New()
	if err != nil {
		log.Fatalf("failed to initialize wgctrl: %v", err)
	}

	devices, err := client.Devices()
	if err != nil {
		log.Fatalf("failed to get devices: %v", err)
	}

	fmt.Printf("found %d device(s)\n", len(devices))
	for i, device := range devices {
		fmt.Printf("device %v: %s\n", i, device.Name)
	}
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "vprox",
		Short: "High-availability network proxy / VPN server, powered by WireGuard",
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "Print out all WireGuard devices",
		Run:   runList,
	}

	rootCmd.AddCommand(listCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
