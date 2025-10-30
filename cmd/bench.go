package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
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
	ifname           string
	numConnections   int
	subprocessChurn  bool
	churnIterations  int
	churnBatchSize   int
	churnDelayMs     int
}

func init() {
	BenchCmd.Flags().StringVar(&benchCmdArgs.ifname, "interface",
		"vprox-bench-", "Interface name to proxy traffic through the VPN")
	BenchCmd.Flags().IntVarP(&benchCmdArgs.numConnections, "num-connections", "n",
		1, "Number of parallel connections to establish for benchmarking")
	BenchCmd.Flags().BoolVar(&benchCmdArgs.subprocessChurn, "subprocess-churn",
		false, "Enable subprocess churn testing mode")
	BenchCmd.Flags().IntVar(&benchCmdArgs.churnIterations, "churn-iterations",
		2000, "Total number of subprocesses to create in churn test")
	BenchCmd.Flags().IntVar(&benchCmdArgs.churnBatchSize, "churn-batch-size",
		20, "Number of concurrent subprocesses per batch in churn test")
	BenchCmd.Flags().IntVar(&benchCmdArgs.churnDelayMs, "churn-delay-ms",
		100, "Milliseconds to wait before killing each batch in churn test")
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

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	// Check if subprocess churn mode is enabled
	if benchCmdArgs.subprocessChurn {
		return runSubprocessChurn(ctx, serverIp)
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to initialize wgctrl: %v", err)
	}

	if benchCmdArgs.numConnections == 1 {
		// Single connection mode (original behavior)
		return runSingleConnection(ctx, serverIp, password, wgClient)
	}

	// Benchmark mode with N parallel connections
	return runParallelConnections(ctx, serverIp, password, wgClient, benchCmdArgs.numConnections)
}

func runSubprocessChurn(ctx context.Context, serverIp netip.Addr) error {
	iterations := benchCmdArgs.churnIterations
	batchSize := benchCmdArgs.churnBatchSize
	delayMs := benchCmdArgs.churnDelayMs

	numBatches := (iterations + batchSize - 1) / batchSize // Round up division

	log.Printf("Starting subprocess churn test...")
	log.Printf("  Total subprocesses: %d", iterations)
	log.Printf("  Batch size: %d", batchSize)
	log.Printf("  Number of batches: %d", numBatches)
	log.Printf("  Delay per batch: %dms", delayMs)
	log.Println()

	var (
		totalStarted     int
		totalCleanExits  int
		totalErrors      int
		totalKilled      int
	)

	startTime := time.Now()
	subprocessIdx := 0

	for batch := 0; batch < numBatches; batch++ {
		// Calculate how many subprocesses to start in this batch
		remaining := iterations - subprocessIdx
		currentBatchSize := batchSize
		if remaining < batchSize {
			currentBatchSize = remaining
		}

		batchStartTime := time.Now()

		// Start concurrent subprocesses
		type subprocessResult struct {
			index   int
			cmd     *exec.Cmd
			started bool
			err     error
		}

		results := make([]subprocessResult, currentBatchSize)
		var wg sync.WaitGroup

		// Start all subprocesses in this batch concurrently
		for i := 0; i < currentBatchSize; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				globalIdx := subprocessIdx + idx
				ifname := fmt.Sprintf("vprox-churn-%d", globalIdx)

				// Get the path to the current vprox binary
				vproxPath, err := os.Executable()
				if err != nil {
					results[idx] = subprocessResult{index: globalIdx, started: false, err: err}
					return
				}

				cmd := exec.Command(vproxPath, "connect", "--interface", ifname, serverIp.String())
				cmd.Stdout = nil
				cmd.Stderr = nil

				err = cmd.Start()
				if err != nil {
					results[idx] = subprocessResult{index: globalIdx, started: false, err: err}
					return
				}

				results[idx] = subprocessResult{index: globalIdx, cmd: cmd, started: true, err: nil}
			}(i)
		}

		// Wait for all starts to complete
		wg.Wait()

		// Count successful starts
		var cmds []*exec.Cmd
		for _, result := range results {
			if result.started {
				totalStarted++
				cmds = append(cmds, result.cmd)
			} else {
				totalErrors++
				if result.err != nil {
					log.Printf("  [Batch %d] Failed to start subprocess %d: %v", batch, result.index, result.err)
				}
			}
		}

		// Wait for the configured delay
		time.Sleep(time.Duration(delayMs) * time.Millisecond)

		// Kill all subprocesses in this batch
		for i, cmd := range cmds {
			if cmd != nil && cmd.Process != nil {
				err := cmd.Process.Signal(syscall.SIGTERM)
				if err != nil {
					log.Printf("  [Batch %d] Failed to send SIGTERM to subprocess: %v", batch, err)
				}
			}

			// Wait for the process to exit
			if cmd != nil {
				err := cmd.Wait()
				if err != nil {
					// Check if it was killed by signal (expected)
					if exitErr, ok := err.(*exec.ExitError); ok {
						if exitErr.String() == "signal: terminated" || exitErr.String() == "signal: killed" {
							totalKilled++
						} else {
							totalErrors++
						}
					} else {
						totalErrors++
					}
				} else {
					// Clean exit (exit code 0)
					totalCleanExits++
				}
			}

			// Update index for logging
			_ = i
		}

		batchDuration := time.Since(batchStartTime)
		subprocessIdx += currentBatchSize

		// Log progress every 10 batches
		if (batch+1)%10 == 0 || batch == numBatches-1 {
			log.Printf("  Completed batch %d/%d (duration: %v, total processed: %d/%d)",
				batch+1, numBatches, batchDuration, subprocessIdx, iterations)
		}

		// Check for context cancellation
		select {
		case <-ctx.Done():
			log.Println("Churn test interrupted by user")
			return ctx.Err()
		default:
		}
	}

	totalDuration := time.Since(startTime)

	// Print summary
	fmt.Println("\n=== SUBPROCESS CHURN TEST SUMMARY ===")
	fmt.Printf("Total subprocesses attempted:  %d\n", iterations)
	fmt.Printf("Successfully started:          %d\n", totalStarted)
	fmt.Printf("Clean exits:                   %d\n", totalCleanExits)
	fmt.Printf("Killed by signal:              %d\n", totalKilled)
	fmt.Printf("Errors:                        %d\n", totalErrors)
	fmt.Println()
	fmt.Printf("Total duration:                %v\n", totalDuration)
	fmt.Printf("Average time per batch:        %v\n", totalDuration/time.Duration(numBatches))
	fmt.Printf("Subprocesses per second:       %.2f\n", float64(totalStarted)/totalDuration.Seconds())

	if totalErrors > 0 {
		return fmt.Errorf("churn test completed with %d errors", totalErrors)
	}

	return nil
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

	// Clean up all successful connections concurrently
	var cleanupWg sync.WaitGroup
	for _, client := range clients {
		if client != nil {
			cleanupWg.Add(1)
			go func(c *lib.Client) {
				defer cleanupWg.Done()
				c.DeleteInterface()
			}(client)
		}
	}
	cleanupWg.Wait()

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
