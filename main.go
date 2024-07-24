package main

import (
	"os"

	"github.com/fatih/color"
	"github.com/modal-labs/vprox/cmd"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vprox",
	Short: "High-availability network proxy / VPN server, powered by WireGuard",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
	rootCmd.AddCommand(cmd.ListCmd)
	rootCmd.AddCommand(cmd.ServerCmd)
	rootCmd.AddCommand(cmd.ConnectCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		color.New(color.FgRed).Add(color.Bold).Print("error: ")
		color.Red(err.Error())
		os.Exit(1)
	}
}
