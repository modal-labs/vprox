package cmd

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RunDir is the path for runtime data that should be kept across restarts.
const RunDir string = "/run/vprox"

func createRunDir() error {
	return os.MkdirAll(RunDir, 0700)
}

func getServerKey() (key wgtypes.Key, err error) {
	if err = createRunDir(); err != nil {
		return
	}
	keyFile := path.Join(RunDir, "server-key")
	contents, err := os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		// Generate a private key for the server. This private key will be reused in
		// event of a server restart, so we save it in `/run/vprox/key`.
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return
		}
		if err = os.WriteFile(keyFile, []byte(key.String()), 0600); err != nil {
			return
		}
		return
	} else if err != nil {
		return
	}
	return wgtypes.ParseKey(strings.TrimSpace(string(contents)))
}

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start a VPN server, listening for new WireGuard peers",
	RunE:  runServer,
}

func runServer(cmd *cobra.Command, args []string) error {
	key, err := getServerKey()
	if err != nil {
		return fmt.Errorf("failed to load server key: %v", err)
	}

	// Display the public key, just for information.
	fmt.Printf("Server public key: %s\n", key.PublicKey().String())

	return errors.New("unimplemented")
}
