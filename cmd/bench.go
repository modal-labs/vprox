package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os/signal"
	"sort"
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
	VerifyDuration    time.Duration
	HealthCheckPassed bool
	Error             error
	Client            *lib.Client
}

var BenchCmd = &cobra.Command{
	Use:   "bench [flags] <ip>",
	Short: "Benchmark parallel VPN connections to a server",
	Args:  cobra.ExactArgs(1),
	RunE:  runBench,
}

var benchCmdArgs struct {
	ifprefix        string
	numConnections  int
	skipHealthCheck bool
	verify          bool
	timeout         time.Duration
}

func init() {
	BenchCmd.Flags().StringVar(&benchCmdArgs.ifprefix, "interface",
		"vbench", "Interface name prefix (suffixed with connection index)")
	BenchCmd.Flags().IntVarP(&benchCmdArgs.numConnections, "num-connections", "n",
		1, "Number of parallel connections to establish")
	BenchCmd.Flags().BoolVar(&benchCmdArgs.skipHealthCheck, "skip-healthcheck",
		false, "Skip the post-connect health check ping")
	BenchCmd.Flags().BoolVar(&benchCmdArgs.verify, "verify",
		false, "Run full interface verification (UP + handshake + ping) matching production checks")
	BenchCmd.Flags().DurationVar(&benchCmdArgs.timeout, "timeout",
		5*time.Second, "HTTP timeout for each /connect request")
}

func runBench(cmd *cobra.Command, args []string) error {
	serverIp, err := netip.ParseAddr(args[0])
	if err != nil || !serverIp.Is4() {
		return fmt.Errorf("invalid IPv4 address: %s", args[0])
	}

	password, err := lib.GetVproxPassword()
	if err != nil {
		return err
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to initialize wgctrl: %v", err)
	}
	defer wgClient.Close()

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	numConns := benchCmdArgs.numConnections
	if numConns < 1 {
		return fmt.Errorf("num-connections must be >= 1, got %d", numConns)
	}

	// Validate that interface names will fit in IFNAMSIZ (15 chars).
	longestIfname := fmt.Sprintf("%s%d", benchCmdArgs.ifprefix, numConns-1)
	if len(longestIfname) > 15 {
		return fmt.Errorf("interface name %q (%d chars) exceeds Linux 15-char limit; shorten --interface prefix",
			longestIfname, len(longestIfname))
	}

	log.Printf("Starting benchmark: %d parallel connection(s) to %v\n", numConns, serverIp)

	// Track all created clients so we can clean them up on signal or completion.
	var clientsMu sync.Mutex
	var clients []*lib.Client

	// Ensure cleanup always runs, even on ctrl-C.
	defer func() {
		clientsMu.Lock()
		defer clientsMu.Unlock()
		for _, c := range clients {
			c.DeleteInterface()
		}
		if len(clients) > 0 {
			log.Printf("Cleaned up %d interface(s)\n", len(clients))
		}
	}()

	registerClient := func(c *lib.Client) {
		clientsMu.Lock()
		clients = append(clients, c)
		clientsMu.Unlock()
	}

	var wg sync.WaitGroup
	results := make(chan ConnectionResult, numConns)
	startTime := time.Now()

	for i := range numConns {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			result := benchEstablishConnection(ctx, index, serverIp, password, wgClient, registerClient)
			results <- result
		}(i)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var (
		successCount int
		failedCount  int
		connectTimes []time.Duration
		verifyTimes  []time.Duration
	)

	for result := range results {
		if result.Error != nil {
			failedCount++
			log.Printf("[%d] FAILED: %v\n", result.Index, result.Error)
		} else {
			successCount++
			connectTimes = append(connectTimes, result.ConnectDuration)
			if result.VerifyDuration > 0 {
				verifyTimes = append(verifyTimes, result.VerifyDuration)
			}
			hc := "skipped"
			if result.HealthCheckPassed {
				hc = "passed"
			}
			verify := "skipped"
			if result.VerifyDuration > 0 {
				verify = result.VerifyDuration.Round(time.Microsecond).String()
			}
			log.Printf("[%d] OK  connect=%v  verify=%s  healthcheck=%s\n",
				result.Index, result.ConnectDuration, verify, hc)
		}
	}

	totalTime := time.Since(startTime)

	// Sort for percentile calculations.
	sort.Slice(connectTimes, func(i, j int) bool { return connectTimes[i] < connectTimes[j] })

	fmt.Println()
	fmt.Println("═══════════════════════════════════════")
	fmt.Println("           BENCHMARK SUMMARY")
	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("  Connections attempted : %d\n", numConns)
	fmt.Printf("  Successful            : %d\n", successCount)
	fmt.Printf("  Failed                : %d\n", failedCount)
	fmt.Printf("  Success rate          : %.1f%%\n", float64(successCount)/float64(numConns)*100)
	fmt.Println("───────────────────────────────────────")
	fmt.Printf("  Total wall-clock time : %v\n", totalTime.Round(time.Millisecond))

	if len(connectTimes) > 0 {
		var total time.Duration
		for _, d := range connectTimes {
			total += d
		}
		avg := total / time.Duration(len(connectTimes))
		p50 := benchPercentile(connectTimes, 50)
		p99 := benchPercentile(connectTimes, 99)

		fmt.Println("───────────────────────────────────────")
		fmt.Println("  Connect latency:")
		fmt.Printf("    avg                 : %v\n", avg.Round(time.Microsecond))
		fmt.Printf("    min                 : %v\n", connectTimes[0].Round(time.Microsecond))
		fmt.Printf("    p50                 : %v\n", p50.Round(time.Microsecond))
		fmt.Printf("    p99                 : %v\n", p99.Round(time.Microsecond))
		fmt.Printf("    max                 : %v\n", connectTimes[len(connectTimes)-1].Round(time.Microsecond))

		if len(verifyTimes) > 0 {
			sort.Slice(verifyTimes, func(i, j int) bool { return verifyTimes[i] < verifyTimes[j] })
			var vtotal time.Duration
			for _, d := range verifyTimes {
				vtotal += d
			}
			vavg := vtotal / time.Duration(len(verifyTimes))
			vp50 := benchPercentile(verifyTimes, 50)
			vp99 := benchPercentile(verifyTimes, 99)
			fmt.Println("───────────────────────────────────────")
			fmt.Println("  Verify latency (UP + handshake + ping):")
			fmt.Printf("    avg                 : %v\n", vavg.Round(time.Microsecond))
			fmt.Printf("    min                 : %v\n", verifyTimes[0].Round(time.Microsecond))
			fmt.Printf("    p50                 : %v\n", vp50.Round(time.Microsecond))
			fmt.Printf("    p99                 : %v\n", vp99.Round(time.Microsecond))
			fmt.Printf("    max                 : %v\n", verifyTimes[len(verifyTimes)-1].Round(time.Microsecond))
		}

		fmt.Println("───────────────────────────────────────")
		fmt.Printf("  Throughput            : %.1f conn/s\n", float64(successCount)/totalTime.Seconds())
	}
	fmt.Println("═══════════════════════════════════════")

	if failedCount > 0 {
		return fmt.Errorf("%d out of %d connections failed", failedCount, numConns)
	}
	return nil
}

// benchPercentile returns the p-th percentile from a sorted slice of durations.
func benchPercentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := len(sorted) * p / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func benchEstablishConnection(
	ctx context.Context,
	index int,
	serverIp netip.Addr,
	password string,
	wgClient *wgctrl.Client,
	registerClient func(*lib.Client),
) ConnectionResult {
	ifname := fmt.Sprintf("%s%d", benchCmdArgs.ifprefix, index)

	result := ConnectionResult{
		Index:  index,
		Ifname: ifname,
	}

	key, err := lib.GetClientKey(ifname)
	if err != nil {
		result.Error = fmt.Errorf("failed to load client key: %v", err)
		return result
	}

	client := &lib.Client{
		Key:      key,
		Ifname:   ifname,
		ServerIp: serverIp,
		Password: password,
		WgClient: wgClient,
		Http: &http.Client{
			Timeout: benchCmdArgs.timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	err = client.CreateInterface()
	if err != nil {
		result.Error = fmt.Errorf("failed to create interface: %v", err)
		return result
	}

	// Register immediately so cleanup runs even if we fail below.
	registerClient(client)

	// Check for cancellation before attempting the (potentially slow) connect.
	select {
	case <-ctx.Done():
		result.Error = fmt.Errorf("cancelled before connect")
		return result
	default:
	}

	connectStart := time.Now()
	err = client.Connect()
	result.ConnectDuration = time.Since(connectStart)

	if err != nil {
		result.Error = fmt.Errorf("failed to connect: %v", err)
		return result
	}

	// Run full interface verification (UP + handshake + ping) if requested.
	if benchCmdArgs.verify {
		verifyStart := time.Now()
		err = client.VerifyInterface(ctx)
		result.VerifyDuration = time.Since(verifyStart)
		if err != nil {
			result.Error = fmt.Errorf("verify failed: %v", err)
			return result
		}
	}

	if !benchCmdArgs.skipHealthCheck {
		result.HealthCheckPassed = client.CheckConnection(healthCheckTimeout, ctx)
		if !result.HealthCheckPassed {
			result.Error = fmt.Errorf("health check failed")
			return result
		}
	} else {
		result.HealthCheckPassed = true
	}

	return result
}
