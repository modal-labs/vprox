package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/modal-labs/vprox/lib"
)

var UpgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade a running vprox server by taking over its WireGuard state",
	Long: `Connects to the control port of a running vprox server, retrieves its
configuration, triggers a graceful shutdown (preserving WireGuard state),
and then starts the current binary as the new server with --takeover.

The old server must have been started with the control server enabled.
Both the old and new binaries must share the same VPROX_PASSWORD or auth config.`,
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
		30, "Timeout in seconds to wait for old server to exit")
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

type upgradeShutdownResponse struct {
	Status          string   `json:"status"`
	RelinquishedIPs []string `json:"relinquished_ips"`
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	token, err := lib.GetClientToken()
	if err != nil {
		return fmt.Errorf("failed to get auth token: %v", err)
	}

	controlBase := fmt.Sprintf("http://%s:%d", upgradeCmdArgs.controlAddr, upgradeCmdArgs.controlPort)
	httpClient := &http.Client{Timeout: 10 * time.Second}

	// Step 1: Get info from running server.
	bold := color.New(color.Bold)
	fmt.Printf("%s Connecting to control server at %s\n", bold.Sprint("==>"), controlBase)

	info, err := getControlInfo(httpClient, controlBase, token)
	if err != nil {
		return fmt.Errorf("failed to get server info: %v", err)
	}

	fmt.Printf("    Running server version: %s (%s)\n", info.GitTag, info.GitCommit)
	fmt.Printf("    New binary version:     %s (%s)\n", lib.GitTag, lib.GitCommit)
	fmt.Printf("    WG block:               %s (per-ip: /%d)\n", info.WgBlock, info.WgBlockPerIp)
	fmt.Printf("    Active IPs:             %v\n", info.ActiveIPs)
	fmt.Printf("    Cloud:                  %s\n", info.Cloud)

	// Step 2: Request graceful shutdown.
	fmt.Printf("\n%s Requesting graceful shutdown (preserving WireGuard state)...\n", bold.Sprint("==>"))

	shutdownResp, err := requestControlShutdown(httpClient, controlBase, token)
	if err != nil {
		return fmt.Errorf("failed to request shutdown: %v", err)
	}

	fmt.Printf("    Status: %s\n", shutdownResp.Status)
	fmt.Printf("    Relinquished IPs: %v\n", shutdownResp.RelinquishedIPs)

	// Step 3: Wait for old process to release the control port.
	fmt.Printf("\n%s Waiting for old server to exit...\n", bold.Sprint("==>"))

	deadline := time.Now().Add(time.Duration(upgradeCmdArgs.timeout) * time.Second)
	if err := waitForPortFree(upgradeCmdArgs.controlPort, deadline); err != nil {
		return fmt.Errorf("timed out waiting for old server to exit: %v", err)
	}

	fmt.Printf("    Old server has exited.\n")

	// Step 4: Start the new server with --takeover.
	fmt.Printf("\n%s Starting new server with --takeover...\n", bold.Sprint("==>"))

	return execNewServer(info)
}

func getControlInfo(client *http.Client, baseURL, token string) (*upgradeInfoResponse, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/info", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

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

func requestControlShutdown(client *http.Client, baseURL, token string) (*upgradeShutdownResponse, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL+"/shutdown", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

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

// waitForPortFree polls until the given TCP port is no longer listening.
func waitForPortFree(port int, deadline time.Time) error {
	addr := fmt.Sprintf("localhost:%d", port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			// Port is free — old server has exited.
			return nil
		}
		conn.Close()
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("port %d still in use after timeout", port)
}

// execNewServer starts the current binary as a new vprox server with --takeover.
func execNewServer(info *upgradeInfoResponse) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine current executable path: %v", err)
	}

	serverArgs := []string{"server", "--takeover", "--wg-block", info.WgBlock}

	if info.WgBlockPerIp > 0 {
		serverArgs = append(serverArgs, "--wg-block-per-ip", "/"+strconv.FormatUint(uint64(info.WgBlockPerIp), 10))
	}

	if info.Cloud != "" {
		serverArgs = append(serverArgs, "--cloud", info.Cloud)
	} else {
		// No cloud mode — pass IPs explicitly.
		for _, ip := range info.ActiveIPs {
			serverArgs = append(serverArgs, "--ip", ip)
		}
	}

	log.Printf("exec: %s %v", self, serverArgs)

	execCmd := exec.Command(self, serverArgs...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	// Replace the current process.
	return execCmd.Run()
}
