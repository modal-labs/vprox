package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/modal-labs/vprox/lib"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type ConnectionResult struct {
	Index             int
	Ifname            string
	ConnectDuration   time.Duration
	HealthCheckPassed bool
	Error             error
	Client            *lib.Client // Keep reference for cleanup
}

var BenchCmd = &cobra.Command{
	Use:        "bench [flags] <ip>",
	Short:      "Peer a client connection to a VPN server",
	Args:       cobra.ExactArgs(1),
	ArgAliases: []string{"ip"},
	RunE:       runParallelConnect,
}
var benchCmdArgs struct {
	ifname         string
	numConnections int
}

func init() {
	BenchCmd.Flags().StringVar(&benchCmdArgs.ifname, "interface",
		"vprox-bench-", "Interface name to proxy traffic through the VPN")
	BenchCmd.Flags().IntVarP(&benchCmdArgs.numConnections, "num-connections", "n",
		1, "Number of parallel connections to establish for benchmarking")
}

func runParallelConnect(cmd *cobra.Command, args []string) error {
	serverIp, err := netip.ParseAddr(args[0])
	if err != nil || !serverIp.Is4() {
		return fmt.Errorf("invalid IP address %s", args[0])
	}

	password, err := lib.GetVproxPassword()
	if err != nil {
		return err
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to initialize wgctrl: %v", err)
	}

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	if benchCmdArgs.numConnections == 1 {
		// Single connection mode (original behavior)
		return runSingleConnection(ctx, serverIp, password, wgClient)
	}

	// Benchmark mode with N parallel connections
	return runParallelConnections(ctx, serverIp, password, wgClient, benchCmdArgs.numConnections)
}

func runSingleConnection(ctx context.Context, serverIp netip.Addr, password string, wgClient *wgctrl.Client) error {
	key, err := lib.GetClientKey(benchCmdArgs.ifname)
	if err != nil {
		return fmt.Errorf("failed to load server key: %v", err)
	}

	client := &lib.Client{
		Key:      key,
		Ifname:   benchCmdArgs.ifname,
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

	err = client.Connect()
	if err != nil {
		return err
	}

	log.Println("Connected...")
	if !client.CheckConnection(healthCheckTimeout, ctx) {
		return fmt.Errorf("connection failed initial healthcheck after %v", healthCheckTimeout)
	}
	return nil
}

func runParallelConnections(ctx context.Context, serverIp netip.Addr, password string, wgClient *wgctrl.Client, numConnections int) error {
	log.Printf("Starting benchmark with %d parallel connections...\n", numConnections)

	var wg sync.WaitGroup
	results := make(chan ConnectionResult, numConnections)
	startTime := time.Now()

	// Launch N goroutines to establish connections in parallel
	for i := range numConnections {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			result := establishConnection(ctx, index, serverIp, password, wgClient)
			results <- result
		}(i)
	}

	// Wait for all connections to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and display results
	var (
		successCount     int
		failedCount      int
		totalConnectTime time.Duration
		minConnectTime   time.Duration
		maxConnectTime   time.Duration
		clients          []*lib.Client
	)

	for result := range results {
		if result.Error != nil {
			failedCount++
			log.Printf("[Connection %d] FAILED: %v\n", result.Index, result.Error)
		} else {
			successCount++
			log.Printf("[Connection %d] SUCCESS: Connect=%v, HealthCheck=%v\n",
				result.Index, result.ConnectDuration, result.HealthCheckPassed)

			totalConnectTime += result.ConnectDuration
			if minConnectTime == 0 || result.ConnectDuration < minConnectTime {
				minConnectTime = result.ConnectDuration
			}
			if result.ConnectDuration > maxConnectTime {
				maxConnectTime = result.ConnectDuration
			}

			// Store client for cleanup
			if result.Client != nil {
				clients = append(clients, result.Client)
			}
		}
	}

	totalTime := time.Since(startTime)

	// Print benchmark summary
	fmt.Println("\nBENCHMARK SUMMARY")
	fmt.Printf("Total Connections Attempted: %d\n", numConnections)
	fmt.Printf("Successful:                  %d\n", successCount)
	fmt.Printf("Failed:                      %d\n", failedCount)
	fmt.Printf("Success Rate:                %.2f%%\n", float64(successCount)/float64(numConnections)*100)
	fmt.Println()
	fmt.Printf("Total Benchmark Time:        %v\n", totalTime)
	if successCount > 0 {
		avgConnectTime := totalConnectTime / time.Duration(successCount)
		fmt.Printf("Average Connect Time:        %v\n", avgConnectTime)
		fmt.Printf("Min Connect Time:            %v\n", minConnectTime)
		fmt.Printf("Max Connect Time:            %v\n", maxConnectTime)
		fmt.Printf("Connections/Second:          %.2f\n", float64(successCount)/totalTime.Seconds())
	}

	// Clean up all successful connections
	for _, client := range clients {
		if client != nil {
			client.DeleteInterface()
		}
	}

	if failedCount > 0 {
		return fmt.Errorf("%d out of %d connections failed", failedCount, numConnections)
	}

	return nil
}

func establishConnection(ctx context.Context, index int, serverIp netip.Addr, password string, wgClient *wgctrl.Client) ConnectionResult {
	result := ConnectionResult{
		Index:  index,
		Ifname: fmt.Sprintf("%s-%d", connectCmdArgs.ifname, index),
	}

	// Load client key
	key, err := lib.GetClientKey(result.Ifname)
	if err != nil {
		result.Error = fmt.Errorf("failed to load client key: %v", err)
		return result
	}

	// Create client
	client := &lib.Client{
		Key:      key,
		Ifname:   result.Ifname,
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

	// Create interface
	err = client.CreateInterface()
	if err != nil {
		result.Error = fmt.Errorf("failed to create interface: %v", err)
		return result
	}

	// Measure connection time
	connectStart := time.Now()
	err = client.Connect()
	result.ConnectDuration = time.Since(connectStart)

	if err != nil {
		client.DeleteInterface()
		result.Error = fmt.Errorf("failed to connect: %v", err)
		return result
	}

	// Run health check
	result.HealthCheckPassed = client.CheckConnection(healthCheckTimeout, ctx)
	if !result.HealthCheckPassed {
		client.DeleteInterface()
		result.Error = fmt.Errorf("health check failed")
		return result
	}

	// Return client for cleanup later
	result.Client = client
	return result
}
