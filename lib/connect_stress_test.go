//go:build linux

package lib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// skipUnlessRoot skips the test when not running as root, since creating
// WireGuard interfaces requires CAP_NET_ADMIN.
func skipUnlessRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: must run as root to create WireGuard interfaces")
	}
}

// testServerWithWg stands up a real WireGuard interface and returns a fully
// initialised Server plus a cleanup function.  The caller MUST defer cleanup().
func testServerWithWg(t *testing.T, cidr netip.Prefix, index uint16) (*Server, func()) {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	wgClient, err := wgctrl.New()
	require.NoError(t, err)

	srv := &Server{
		Key:      key,
		BindAddr: netip.MustParseAddr("127.0.0.1"),
		Password: "test-secret",
		Index:    index,
		WgCidr:   cidr,
		WgClient: wgClient,
		Ctx:      context.Background(),
	}

	// Initialise the IP allocator and peer map the same way InitState does,
	// but without calling getDefaultInterface (we don't need BindIface for
	// the connect handler).
	srv.ipAllocator = NewIpAllocator(cidr)
	_ = srv.ipAllocator.Allocate() // reserve the network address
	srv.peers = make(map[wgtypes.Key]peerState)
	srv.pendingPeers = make(chan wgtypes.PeerConfig, 4096)
	srv.flushDone = make(chan struct{})

	// Create the WireGuard interface.
	ifname := srv.Ifname()
	link := &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}}
	// Remove any leftover from a previous failed run.
	_ = netlink.LinkDel(link)

	err = netlink.LinkAdd(link)
	require.NoError(t, err, "failed to create WireGuard interface (are you root?)")

	ipnet := prefixToIPNet(cidr)
	err = netlink.AddrAdd(link, &netlink.Addr{IPNet: &ipnet})
	require.NoError(t, err)

	err = netlink.LinkSetUp(link)
	require.NoError(t, err)

	listenPort := WireguardListenPortBase + int(index)
	err = wgClient.ConfigureDevice(ifname, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &listenPort,
	})
	require.NoError(t, err)

	// Start the flush loop so enqueued peers actually get registered.
	go srv.flushPeersLoop()

	cleanup := func() {
		close(srv.pendingPeers)
		<-srv.flushDone
		_ = netlink.LinkDel(link)
		_ = wgClient.Close()
	}

	return srv, cleanup
}

// doConnectRequest fires a single POST /connect and returns the status code,
// the parsed response (if 200), and any transport-level error.
func doConnectRequest(ts *httptest.Server, pubKey, password string, timeout time.Duration) (int, *connectResponse, error) {
	body, _ := json.Marshal(connectRequest{PeerPublicKey: pubKey})
	req, err := http.NewRequest("POST", ts.URL+"/connect", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+password)

	// Build a fresh client per request so concurrent goroutines don't race
	// on the shared Timeout field of the httptest default client.
	client := &http.Client{
		Transport: ts.Client().Transport,
		Timeout:   timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err // includes timeouts
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var cr connectResponse
		if jsonErr := json.Unmarshal(respBody, &cr); jsonErr == nil {
			return resp.StatusCode, &cr, nil
		}
	}
	return resp.StatusCode, nil, nil
}

// measureConcurrentP50 fires `n` concurrent GET requests against `url` and
// returns the median (p50) latency.  This is used to measure the inherent
// httptest + TCP overhead at a given concurrency level so that the connect
// handler latency can be compared against a fair baseline.
func measureConcurrentP50(ts *httptest.Server, url string, n int) time.Duration {
	latencies := make([]time.Duration, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			start := time.Now()
			client := &http.Client{
				Transport: ts.Client().Transport,
				Timeout:   5 * time.Second,
			}
			resp, err := client.Get(url)
			if err == nil {
				resp.Body.Close()
			}
			latencies[idx] = time.Since(start)
		}(i)
	}
	wg.Wait()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return latencies[len(latencies)*50/100]
}

// TestConnectConcurrentDistinctKeys sends many requests with unique peer keys
// in parallel against a real WireGuard-backed server.
//
// To isolate handler-level serialisation from httptest/TCP overhead, it first
// measures the p50 latency of the same number of concurrent requests against a
// trivial no-op handler on the same server.  Then it fires the real /connect
// batch and compares.  If the handler serialises on the netlink socket, the
// /connect p50 will be many multiples of the no-op p50.
//
// Run:
//
//	sudo go test -race -run TestConnectConcurrentDistinctKeys -count=1 -v ./lib/
func TestConnectConcurrentDistinctKeys(t *testing.T) {
	skipUnlessRoot(t)

	cidr := netip.MustParsePrefix("10.99.0.0/24") // 254 usable IPs
	srv, cleanup := testServerWithWg(t, cidr, 50)  // high index to avoid clashing
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/connect", srv.connectHandler)
	mux.HandleFunc("/noop", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	const concurrency = 50
	const perRequestTimeout = 5 * time.Second

	// ---- Baseline: concurrent no-op requests to measure httptest overhead ----
	noopP50 := measureConcurrentP50(ts, ts.URL+"/noop", concurrency)
	t.Logf("no-op baseline (concurrent p50 at %d): %v", concurrency, noopP50)

	// Pre-generate distinct keys.
	keys := make([]wgtypes.Key, concurrency)
	for i := range keys {
		k, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		keys[i] = k
	}

	// ---- Concurrent /connect batch ----
	type result struct {
		idx     int
		status  int
		cr      *connectResponse
		err     error
		latency time.Duration
	}

	results := make([]result, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)

	start := time.Now()

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			pubKey := keys[idx].PublicKey().String()
			reqStart := time.Now()
			status, cr, err := doConnectRequest(ts, pubKey, "test-secret", perRequestTimeout)
			results[idx] = result{idx: idx, status: status, cr: cr, err: err, latency: time.Since(reqStart)}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Tally outcomes and collect latencies.
	var timeouts, errors, successes int
	assignedIPs := make(map[string]int)
	latencies := make([]time.Duration, 0, concurrency)
	for _, r := range results {
		switch {
		case r.err != nil:
			timeouts++
			t.Logf("  request %2d: TIMEOUT/ERROR after %v: %v", r.idx, r.latency, r.err)
		case r.status == http.StatusOK && r.cr != nil:
			successes++
			assignedIPs[r.cr.AssignedAddr]++
			latencies = append(latencies, r.latency)
		default:
			errors++
			t.Logf("  request %2d: unexpected status %d after %v", r.idx, r.status, r.latency)
		}
	}

	// Sort latencies to compute percentiles.
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	var p50, p99 time.Duration
	if len(latencies) > 0 {
		p50 = latencies[len(latencies)*50/100]
		p99 = latencies[len(latencies)*99/100]
	}

	t.Logf("elapsed=%v  successes=%d  errors=%d  timeouts=%d  unique_ips=%d",
		elapsed, successes, errors, timeouts, len(assignedIPs))
	t.Logf("latency  p50=%v  p99=%v  noop_p50=%v", p50, p99, noopP50)
	if noopP50 > 0 {
		t.Logf("p50/noop=%.1fx  p99/noop=%.1fx",
			float64(p50)/float64(noopP50), float64(p99)/float64(noopP50))
	}

	// ---- Assertions ----

	// No request should have hit the client timeout.
	assert.Zerof(t, timeouts,
		"%d/%d requests timed out (>%v) – the handler serialises under concurrency",
		timeouts, concurrency, perRequestTimeout)

	// Serialisation check: compare /connect p50 against the no-op baseline
	// measured at the same concurrency.  The no-op baseline captures httptest
	// TCP overhead and goroutine scheduling cost.  A concurrent handler
	// should add only modest overhead on top.  We allow up to 5× the no-op
	// p50 — serialised netlink calls would push this to 10×+ easily.
	if noopP50 > 0 && p50 > noopP50*5 {
		t.Errorf("p50 under concurrency (%v) is %.1fx the no-op baseline (%v) "+
			"– handler appears serialised",
			p50, float64(p50)/float64(noopP50), noopP50)
	}

	// Every successful response must have a unique IP.
	for addr, count := range assignedIPs {
		if count > 1 {
			t.Errorf("IP %s was assigned to %d different keys (expected unique)", addr, count)
		}
	}

	// Sanity: at least some requests should have succeeded.
	assert.Greater(t, successes, 0, "no requests succeeded at all")
}

// TestConnectConcurrentSameKey sends many requests for the *same* peer key at
// once.  The handler should behave idempotently: every response should contain
// the same assigned IP.  A TOCTOU race in the duplicate-check path (Device()
// is called outside any lock) can cause multiple IPs to be allocated for one
// key, leaking addresses.
//
// Run:
//
//	sudo go test -race -run TestConnectConcurrentSameKey -count=1 -v ./lib/
func TestConnectConcurrentSameKey(t *testing.T) {
	skipUnlessRoot(t)

	cidr := netip.MustParsePrefix("10.98.0.0/24")
	srv, cleanup := testServerWithWg(t, cidr, 51)
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/connect", srv.connectHandler)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	pubKeyStr := peerKey.PublicKey().String()

	const concurrency = 30
	const perRequestTimeout = 5 * time.Second

	type result struct {
		status int
		cr     *connectResponse
		err    error
	}
	results := make([]result, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)

	start := time.Now()

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			status, cr, err := doConnectRequest(ts, pubKeyStr, "test-secret", perRequestTimeout)
			results[idx] = result{status: status, cr: cr, err: err}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	var timeouts int
	assignedAddrs := make(map[string]int)
	for i, r := range results {
		if r.err != nil {
			timeouts++
			t.Logf("  request %2d: TIMEOUT/ERROR: %v", i, r.err)
			continue
		}
		if r.status == http.StatusOK && r.cr != nil {
			assignedAddrs[r.cr.AssignedAddr]++
		}
	}

	t.Logf("elapsed=%v  timeouts=%d  unique_assigned_addrs=%d  distribution=%v",
		elapsed, timeouts, len(assignedAddrs), assignedAddrs)

	assert.Zerof(t, timeouts,
		"%d/%d same-key requests timed out under concurrency", timeouts, concurrency)

	// An idempotent handler should return exactly one distinct IP for a single key.
	if len(assignedAddrs) > 1 {
		t.Errorf("same peer key received %d distinct IPs (race in duplicate-peer check): %v",
			len(assignedAddrs), assignedAddrs)
	}
}

// TestConnectConcurrentIPExhaustion uses a tiny /28 CIDR (14 usable addresses)
// and sends more concurrent requests than there are IPs.  Excess requests must
// receive a clean 503; no request should deadlock or time out.
//
// Run:
//
//	sudo go test -race -run TestConnectConcurrentIPExhaustion -count=1 -v ./lib/
func TestConnectConcurrentIPExhaustion(t *testing.T) {
	skipUnlessRoot(t)

	cidr := netip.MustParsePrefix("10.97.0.0/28") // 14 usable IPs
	srv, cleanup := testServerWithWg(t, cidr, 52)
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/connect", srv.connectHandler)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	const total = 30 // intentionally more than 14
	const perRequestTimeout = 5 * time.Second

	keys := make([]wgtypes.Key, total)
	for i := range keys {
		k, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		keys[i] = k
	}

	type result struct {
		status int
		err    error
	}
	results := make([]result, total)
	var wg sync.WaitGroup
	wg.Add(total)

	start := time.Now()

	for i := 0; i < total; i++ {
		go func(idx int) {
			defer wg.Done()
			pubKey := keys[idx].PublicKey().String()
			status, _, err := doConnectRequest(ts, pubKey, "test-secret", perRequestTimeout)
			results[idx] = result{status: status, err: err}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	var timeouts, unavailable, successes, other int
	for _, r := range results {
		switch {
		case r.err != nil:
			timeouts++
		case r.status == http.StatusServiceUnavailable:
			unavailable++
		case r.status == http.StatusOK:
			successes++
		default:
			other++
		}
	}

	t.Logf("elapsed=%v  200s=%d  503s=%d  other=%d  timeouts=%d",
		elapsed, successes, unavailable, other, timeouts)

	assert.Zerof(t, timeouts,
		"%d/%d requests deadlocked or timed out during IP exhaustion", timeouts, total)
	assert.Greater(t, unavailable, 0,
		fmt.Sprintf("expected some 503s from IP exhaustion (sent %d requests into a /28)", total))
	assert.Greater(t, successes, 0,
		"expected at least some successful allocations before exhaustion")
}
