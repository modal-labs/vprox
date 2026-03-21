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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/modal-labs/vprox/lib"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// ConnectionResult captures the outcome of a single connect attempt.
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
	Long: `Benchmark parallel VPN connections to a server.

Without --duration, runs a single burst of N parallel connections and reports
latency stats (the "burst" mode).

With --duration, runs N workers that continuously create, verify, and tear down
connections for the specified time (the "sustained" mode). Stats are printed
every 10 seconds and a final summary is shown at the end.`,
	Args: cobra.ExactArgs(1),
	RunE: runBench,
}

var benchCmdArgs struct {
	ifprefix        string
	numConnections  int
	skipHealthCheck bool
	verify          bool
	timeout         time.Duration
	duration        time.Duration
}

func init() {
	BenchCmd.Flags().StringVar(&benchCmdArgs.ifprefix, "interface",
		"vbench", "Interface name prefix (suffixed with connection index)")
	BenchCmd.Flags().IntVarP(&benchCmdArgs.numConnections, "num-connections", "n",
		1, "Number of parallel connections (burst) or workers (sustained)")
	BenchCmd.Flags().BoolVar(&benchCmdArgs.skipHealthCheck, "skip-healthcheck",
		false, "Skip the post-connect health check ping")
	BenchCmd.Flags().BoolVar(&benchCmdArgs.verify, "verify",
		false, "Run full interface verification (UP + handshake + ping) matching production checks")
	BenchCmd.Flags().DurationVar(&benchCmdArgs.timeout, "timeout",
		5*time.Second, "HTTP timeout for each /connect request")
	BenchCmd.Flags().DurationVar(&benchCmdArgs.duration, "duration",
		0, "Run sustained load for this long (e.g. 60s, 5m). 0 means burst mode.")
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

	if benchCmdArgs.duration > 0 {
		return runSustainedBench(ctx, serverIp, password, wgClient, numConns, benchCmdArgs.duration)
	}
	return runBurstBench(ctx, serverIp, password, wgClient, numConns)
}

// ---------------------------------------------------------------------------
// Burst mode (original behaviour)
// ---------------------------------------------------------------------------

func runBurstBench(ctx context.Context, serverIp netip.Addr, password string, wgClient *wgctrl.Client, numConns int) error {
	log.Printf("Starting burst benchmark: %d parallel connection(s) to %v\n", numConns, serverIp)

	var clientsMu sync.Mutex
	var clients []*lib.Client

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

	sort.Slice(connectTimes, func(i, j int) bool { return connectTimes[i] < connectTimes[j] })

	fmt.Println()
	printBurstSummary(numConns, successCount, failedCount, totalTime, connectTimes, verifyTimes)

	if failedCount > 0 {
		return fmt.Errorf("%d out of %d connections failed", failedCount, numConns)
	}
	return nil
}

func printBurstSummary(attempted, successes, failures int, totalTime time.Duration, connectTimes, verifyTimes []time.Duration) {
	fmt.Println("═══════════════════════════════════════")
	fmt.Println("        BURST BENCHMARK SUMMARY")
	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("  Connections attempted : %d\n", attempted)
	fmt.Printf("  Successful            : %d\n", successes)
	fmt.Printf("  Failed                : %d\n", failures)
	fmt.Printf("  Success rate          : %.1f%%\n", float64(successes)/float64(attempted)*100)
	fmt.Println("───────────────────────────────────────")
	fmt.Printf("  Total wall-clock time : %v\n", totalTime.Round(time.Millisecond))

	if len(connectTimes) > 0 {
		printLatencyBlock("Connect latency", connectTimes)

		if len(verifyTimes) > 0 {
			sort.Slice(verifyTimes, func(i, j int) bool { return verifyTimes[i] < verifyTimes[j] })
			printLatencyBlock("Verify latency (UP + handshake + ping)", verifyTimes)
		}

		fmt.Println("───────────────────────────────────────")
		fmt.Printf("  Throughput            : %.1f conn/s\n", float64(successes)/totalTime.Seconds())
	}
	fmt.Println("═══════════════════════════════════════")
}

func printLatencyBlock(label string, sorted []time.Duration) {
	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	avg := total / time.Duration(len(sorted))
	p50 := benchPercentile(sorted, 50)
	p99 := benchPercentile(sorted, 99)

	fmt.Println("───────────────────────────────────────")
	fmt.Printf("  %s:\n", label)
	fmt.Printf("    avg                 : %v\n", avg.Round(time.Microsecond))
	fmt.Printf("    min                 : %v\n", sorted[0].Round(time.Microsecond))
	fmt.Printf("    p50                 : %v\n", p50.Round(time.Microsecond))
	fmt.Printf("    p99                 : %v\n", p99.Round(time.Microsecond))
	fmt.Printf("    max                 : %v\n", sorted[len(sorted)-1].Round(time.Microsecond))
}

// ---------------------------------------------------------------------------
// Sustained mode
// ---------------------------------------------------------------------------

// cycleResult captures one create→verify→teardown cycle.
type cycleResult struct {
	WorkerID        int
	Iteration       int
	ConnectDuration time.Duration
	VerifyDuration  time.Duration
	TotalDuration   time.Duration
	Error           error
	Cancelled       bool // true only when the --duration context expired mid-cycle
}

// sustainedStats collects results from all workers for periodic and final
// reporting. All methods are safe for concurrent use.
type sustainedStats struct {
	mu            sync.Mutex
	connectTimes   []time.Duration
	verifyTimes    []time.Duration
	cycleTimes     []time.Duration
	successCount   int
	failureCount   int
	cancelledCount int
	totalAttempts  int

	// Rolling window for periodic reporting.
	windowStart    time.Time
	winConnect     []time.Duration
	winVerify      []time.Duration
	winCycle       []time.Duration
	winSuccesses   int
	winFailures    int
	winCancelled   int
}

func newSustainedStats() *sustainedStats {
	return &sustainedStats{windowStart: time.Now()}
}

func (s *sustainedStats) record(r cycleResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalAttempts++

	if r.Cancelled {
		s.cancelledCount++
		s.winCancelled++
	} else if r.Error != nil {
		s.failureCount++
		s.winFailures++
	} else {
		s.successCount++
		s.winSuccesses++
		s.connectTimes = append(s.connectTimes, r.ConnectDuration)
		s.cycleTimes = append(s.cycleTimes, r.TotalDuration)
		s.winConnect = append(s.winConnect, r.ConnectDuration)
		s.winCycle = append(s.winCycle, r.TotalDuration)
		if r.VerifyDuration > 0 {
			s.verifyTimes = append(s.verifyTimes, r.VerifyDuration)
			s.winVerify = append(s.winVerify, r.VerifyDuration)
		}
	}
}

func (s *sustainedStats) resetWindow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.windowStart = time.Now()
	s.winConnect = s.winConnect[:0]
	s.winVerify = s.winVerify[:0]
	s.winCycle = s.winCycle[:0]
	s.winSuccesses = 0
	s.winFailures = 0
	s.winCancelled = 0
}

func (s *sustainedStats) printWindow(elapsed time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := s.winSuccesses + s.winFailures + s.winCancelled
	if total == 0 {
		log.Printf("[T+%v] no cycles completed in window", elapsed.Round(time.Second))
		return
	}

	rate := float64(s.winSuccesses) / time.Since(s.windowStart).Seconds()

	var cp50, vp50, cyp50 string
	if len(s.winConnect) > 0 {
		sorted := sortedCopy(s.winConnect)
		cp50 = benchPercentile(sorted, 50).Round(time.Microsecond).String()
	} else {
		cp50 = "-"
	}
	if len(s.winVerify) > 0 {
		sorted := sortedCopy(s.winVerify)
		vp50 = benchPercentile(sorted, 50).Round(time.Microsecond).String()
	} else {
		vp50 = "-"
	}
	if len(s.winCycle) > 0 {
		sorted := sortedCopy(s.winCycle)
		cyp50 = benchPercentile(sorted, 50).Round(time.Microsecond).String()
	} else {
		cyp50 = "-"
	}

	log.Printf("[T+%v] cycles=%d ok=%d fail=%d cancelled=%d  connect_p50=%s verify_p50=%s cycle_p50=%s  rate=%.1f/s",
		elapsed.Round(time.Second), total, s.winSuccesses, s.winFailures, s.winCancelled, cp50, vp50, cyp50, rate)
}

func (s *sustainedStats) printFinal(totalTime time.Duration, numWorkers int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("        SUSTAINED BENCHMARK SUMMARY")
	fmt.Println("═══════════════════════════════════════════════")
	completed := s.successCount + s.failureCount
	fmt.Printf("  Workers               : %d\n", numWorkers)
	fmt.Printf("  Duration              : %v\n", totalTime.Round(time.Millisecond))
	fmt.Printf("  Total cycles          : %d\n", s.totalAttempts)
	fmt.Printf("  Successful            : %d\n", s.successCount)
	fmt.Printf("  Failed                : %d\n", s.failureCount)
	fmt.Printf("  Cancelled (duration)  : %d\n", s.cancelledCount)
	if completed > 0 {
		fmt.Printf("  Success rate          : %.1f%% (of %d completed)\n", float64(s.successCount)/float64(completed)*100, completed)
	}
	fmt.Println("───────────────────────────────────────────────")

	if len(s.connectTimes) > 0 {
		sorted := sortedCopy(s.connectTimes)
		printSustainedLatencyBlock("Connect latency", sorted)
	}
	if len(s.verifyTimes) > 0 {
		sorted := sortedCopy(s.verifyTimes)
		printSustainedLatencyBlock("Verify latency (UP + handshake + ping)", sorted)
	}
	if len(s.cycleTimes) > 0 {
		sorted := sortedCopy(s.cycleTimes)
		printSustainedLatencyBlock("Full cycle (create → verify → teardown)", sorted)
	}

	if s.successCount > 0 && totalTime > 0 {
		fmt.Println("───────────────────────────────────────────────")
		fmt.Printf("  Throughput            : %.1f cycles/s\n", float64(s.successCount)/totalTime.Seconds())
	}
	fmt.Println("═══════════════════════════════════════════════")
}

func printSustainedLatencyBlock(label string, sorted []time.Duration) {
	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	avg := total / time.Duration(len(sorted))
	p50 := benchPercentile(sorted, 50)
	p99 := benchPercentile(sorted, 99)

	fmt.Println("───────────────────────────────────────────────")
	fmt.Printf("  %s (%d samples):\n", label, len(sorted))
	fmt.Printf("    avg                 : %v\n", avg.Round(time.Microsecond))
	fmt.Printf("    min                 : %v\n", sorted[0].Round(time.Microsecond))
	fmt.Printf("    p50                 : %v\n", p50.Round(time.Microsecond))
	fmt.Printf("    p99                 : %v\n", p99.Round(time.Microsecond))
	fmt.Printf("    max                 : %v\n", sorted[len(sorted)-1].Round(time.Microsecond))
}

func runSustainedBench(ctx context.Context, serverIp netip.Addr, password string, wgClient *wgctrl.Client, numWorkers int, duration time.Duration) error {
	log.Printf("Starting sustained benchmark: %d workers for %v to %v\n", numWorkers, duration, serverIp)

	// Create a child context that expires after the requested duration.
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	stats := newSustainedStats()

	// Global iteration counter so each interface name is unique even across
	// workers and loop iterations, avoiding name collisions.
	var globalIter atomic.Int64

	var workersWg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		workersWg.Add(1)
		go func(workerID int) {
			defer workersWg.Done()
			sustainedWorker(ctx, workerID, serverIp, password, wgClient, stats, &globalIter)
		}(w)
	}

	// Periodic stats printer.
	const reportInterval = 10 * time.Second
	startTime := time.Now()
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()

	doneCh := make(chan struct{})
	go func() {
		workersWg.Wait()
		close(doneCh)
	}()

loop:
	for {
		select {
		case <-doneCh:
			break loop
		case <-ticker.C:
			stats.printWindow(time.Since(startTime))
			stats.resetWindow()
		}
	}

	totalTime := time.Since(startTime)
	stats.printFinal(totalTime, numWorkers)
	return nil
}

func sustainedWorker(
	ctx context.Context,
	workerID int,
	serverIp netip.Addr,
	password string,
	wgClient *wgctrl.Client,
	stats *sustainedStats,
	globalIter *atomic.Int64,
) {
	for iteration := 0; ; iteration++ {
		// Check if we should stop.
		select {
		case <-ctx.Done():
			return
		default:
		}

		iter := globalIter.Add(1)
		result := sustainedCycle(ctx, workerID, iteration, iter, serverIp, password, wgClient)
		// Mark as cancelled only if the parent --duration context expired,
		// NOT if a verify step timed out on its own.
		if result.Error != nil && ctx.Err() != nil {
			result.Cancelled = true
		}
		stats.record(result)

		if result.Cancelled {
			// Duration expired mid-cycle — not a real failure, don't spam logs.
		} else if result.Error != nil {
			log.Printf("[w%d #%d] FAIL cycle=%v err=%v",
				workerID, iteration, result.TotalDuration.Round(time.Millisecond), result.Error)
		} else {
			log.Printf("[w%d #%d] OK   cycle=%v connect=%v verify=%v",
				workerID, iteration,
				result.TotalDuration.Round(time.Millisecond),
				result.ConnectDuration.Round(time.Microsecond),
				result.VerifyDuration.Round(time.Microsecond))
		}
	}
}

// sustainedCycle runs one full create → connect → verify → teardown cycle.
// Each cycle creates its own wgctrl.Client so that verifyHandshake's Device()
// calls and Connect's ConfigureDevice calls don't all serialize on one netlink
// socket. With 1000 workers sharing a single client, the netlink mutex becomes
// the bottleneck — not the server.
func sustainedCycle(
	ctx context.Context,
	workerID int,
	iteration int,
	globalIter int64,
	serverIp netip.Addr,
	password string,
	_ *wgctrl.Client, // unused; each cycle creates its own
) cycleResult {
	cycleStart := time.Now()

	// Use the global iteration counter for a unique interface name.
	ifname := fmt.Sprintf("%s%d", benchCmdArgs.ifprefix, globalIter)

	result := cycleResult{
		WorkerID:  workerID,
		Iteration: iteration,
	}

	// Each cycle gets its own wgctrl.Client (its own netlink socket) so
	// concurrent workers don't serialize on a shared mutex.
	cycleWgClient, err := wgctrl.New()
	if err != nil {
		result.Error = fmt.Errorf("wgctrl: %w", err)
		result.TotalDuration = time.Since(cycleStart)
		return result
	}
	defer cycleWgClient.Close()

	key, err := lib.GetClientKey(ifname)
	if err != nil {
		result.Error = fmt.Errorf("key: %w", err)
		result.TotalDuration = time.Since(cycleStart)
		return result
	}

	client := &lib.Client{
		Key:      key,
		Ifname:   ifname,
		ServerIp: serverIp,
		Password: password,
		WgClient: cycleWgClient,
		Http: &http.Client{
			Timeout: benchCmdArgs.timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	// Create interface.
	if err := client.CreateInterface(); err != nil {
		result.Error = fmt.Errorf("create: %w", err)
		result.TotalDuration = time.Since(cycleStart)
		return result
	}
	// Always clean up the interface when the cycle ends.
	defer client.DeleteInterface()

	// Check for cancellation before the (potentially slow) connect.
	select {
	case <-ctx.Done():
		result.Error = ctx.Err()
		result.TotalDuration = time.Since(cycleStart)
		return result
	default:
	}

	// Connect.
	connectStart := time.Now()
	if err := client.Connect(); err != nil {
		result.Error = fmt.Errorf("connect: %w", err)
		result.ConnectDuration = time.Since(connectStart)
		result.TotalDuration = time.Since(cycleStart)
		return result
	}
	result.ConnectDuration = time.Since(connectStart)

	// Verify.
	if benchCmdArgs.verify {
		verifyStart := time.Now()
		if err := client.VerifyInterface(ctx); err != nil {
			result.Error = fmt.Errorf("verify: %w", err)
			result.VerifyDuration = time.Since(verifyStart)
			result.TotalDuration = time.Since(cycleStart)
			return result
		}
		result.VerifyDuration = time.Since(verifyStart)
	}

	// Healthcheck.
	if !benchCmdArgs.skipHealthCheck {
		if !client.CheckConnection(healthCheckTimeout, ctx) {
			result.Error = fmt.Errorf("healthcheck failed")
			result.TotalDuration = time.Since(cycleStart)
			return result
		}
	}

	result.TotalDuration = time.Since(cycleStart)
	return result
	// deferred DeleteInterface runs here — teardown is included in TotalDuration.
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

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

func sortedCopy(src []time.Duration) []time.Duration {
	dst := make([]time.Duration, len(src))
	copy(dst, src)
	sort.Slice(dst, func(i, j int) bool { return dst[i] < dst[j] })
	return dst
}

// benchEstablishConnection is used by burst mode to create one connection.
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
