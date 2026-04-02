package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/modal-labs/vprox/lib"
)

var UpgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade a running vprox server by taking over its WireGuard state",
	Long: `Connects to the control port of a running vprox server, retrieves its
configuration, triggers a graceful shutdown (preserving WireGuard state),
and then starts the current binary as the new server with --takeover.

The old server passes its HTTPS listener file descriptors to the new process
via a Unix socket (SCM_RIGHTS), so there is zero control-plane downtime.
Connected WireGuard peers are completely unaffected.

The old server must have been started with the control server enabled.
The control server listens on localhost only, so no authentication is required.`,
	RunE: runUpgrade,
}

var upgradeCmdArgs struct {
	controlAddr string
	controlPort int
	timeout     int
}

func init() {
	UpgradeCmd.Flags().StringVar(&upgradeCmdArgs.controlAddr, "server",
		"localhost", "Address of the running vprox control server")
	UpgradeCmd.Flags().IntVar(&upgradeCmdArgs.controlPort, "port",
		lib.DefaultControlPort, "Port of the running vprox control server")
	UpgradeCmd.Flags().IntVar(&upgradeCmdArgs.timeout, "timeout",
		30, "Timeout in seconds to wait for the upgrade to complete")
}

// upgradeInfoResponse mirrors lib.controlInfoResponse for the client side.
type upgradeInfoResponse struct {
	GitCommit    string   `json:"git_commit"`
	GitTag       string   `json:"git_tag"`
	WgBlock      string   `json:"wg_block"`
	WgBlockPerIp uint     `json:"wg_block_per_ip"`
	ActiveIPs    []string `json:"active_ips"`
	Cloud        string   `json:"cloud"`
	Takeover     bool     `json:"takeover"`
}

// upgradeListenerMeta mirrors lib.ListenerMeta for the client side.
type upgradeListenerMeta struct {
	BindAddr string `json:"bind_addr"`
	Index    uint16 `json:"index"`
}

type upgradeShutdownResponse struct {
	Status          string                `json:"status"`
	RelinquishedIPs []string              `json:"relinquished_ips"`
	FDSocket        string                `json:"fd_socket"`
	Listeners       []upgradeListenerMeta `json:"listeners"`
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	controlBase := fmt.Sprintf("http://%s:%d", upgradeCmdArgs.controlAddr, upgradeCmdArgs.controlPort)
	httpClient := &http.Client{Timeout: 10 * time.Second}

	info, err := getControlInfo(httpClient, controlBase)
	if err != nil {
		return fmt.Errorf("failed to get server info: %v", err)
	}
	log.Printf("upgrade: old=%s (%s), new=%s (%s), ips=[%s], wg-block=%s",
		info.GitTag, info.GitCommit, lib.GitTag, lib.GitCommit,
		strings.Join(info.ActiveIPs, ", "), info.WgBlock)

	shutdownResp, err := requestControlShutdown(httpClient, controlBase)
	if err != nil {
		return fmt.Errorf("failed to request shutdown: %v", err)
	}
	log.Printf("upgrade: relinquished %d IP(s), handing off %d listener(s) via %s",
		len(shutdownResp.RelinquishedIPs), len(shutdownResp.Listeners), shutdownResp.FDSocket)

	log.Printf("upgrade: starting new server with --takeover --inherit-listeners")
	return execNewServer(info, shutdownResp.FDSocket)
}

func getControlInfo(client *http.Client, baseURL string) (*upgradeInfoResponse, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/info", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to control server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("control server returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var info upgradeInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &info, nil
}

func requestControlShutdown(client *http.Client, baseURL string) (*upgradeShutdownResponse, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL+"/shutdown", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send shutdown request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("control server returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var shutdownResp upgradeShutdownResponse
	if err := json.Unmarshal(body, &shutdownResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &shutdownResp, nil
}

// execNewServer starts the current binary as a new vprox server with --takeover
// and --inherit-listeners pointing at the Unix socket where the old process is
// waiting to hand off its HTTPS listener FDs.
func execNewServer(info *upgradeInfoResponse, fdSocket string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine current executable path: %v", err)
	}

	serverArgs := []string{
		"server",
		"--takeover",
		"--wg-block", info.WgBlock,
		"--inherit-listeners", fdSocket,
	}

	if info.WgBlockPerIp > 0 {
		serverArgs = append(serverArgs, "--wg-block-per-ip",
			"/"+strconv.FormatUint(uint64(info.WgBlockPerIp), 10))
	}

	if info.Cloud != "" {
		serverArgs = append(serverArgs, "--cloud", info.Cloud)
	} else {
		// Pass explicit IPs so they show up in ps(1) output and satisfy
		// flag validation, even though the actual sockets come from the
		// inherited listeners.
		for _, ip := range info.ActiveIPs {
			serverArgs = append(serverArgs, "--ip", ip)
		}
	}

	log.Printf("exec: %s %v", self, serverArgs)

	execCmd := exec.Command(self, serverArgs...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	return execCmd.Run()
}
