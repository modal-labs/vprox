package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const DefaultControlPort = 9123

// ControlServer runs a plain HTTP server on localhost for upgrade orchestration.
// It provides endpoints for the new binary to query state and trigger graceful shutdown.
// It binds to 127.0.0.1 only and does not require authentication.
type ControlServer struct {
	sm       *ServerManager
	port     int
	cloud    string
	server   *http.Server
	cancelFn context.CancelFunc // cancels the top-level server context
}

// NewControlServer creates a control server bound to the given port on localhost.
// cancelFn should cancel the top-level context that governs the ServerManager lifecycle.
func NewControlServer(sm *ServerManager, port int, cancelFn context.CancelFunc) *ControlServer {
	return &ControlServer{
		sm:       sm,
		port:     port,
		cancelFn: cancelFn,
	}
}

// controlInfoResponse is returned by GET /info.
type controlInfoResponse struct {
	GitCommit    string   `json:"git_commit"`
	GitTag       string   `json:"git_tag"`
	WgBlock      string   `json:"wg_block"`
	WgBlockPerIp uint     `json:"wg_block_per_ip"`
	ActiveIPs    []string `json:"active_ips"`
	Cloud        string   `json:"cloud"`
	Takeover     bool     `json:"takeover"`
}

// controlShutdownResponse is returned by POST /shutdown.
type controlShutdownResponse struct {
	Status          string         `json:"status"`
	RelinquishedIPs []string       `json:"relinquished_ips"`
	FDSocket        string         `json:"fd_socket"`
	Listeners       []ListenerMeta `json:"listeners"`
}

// SetCloud stores the cloud provider string so it can be reported in /info.
func (cs *ControlServer) SetCloud(cloud string) {
	cs.cloud = cloud
}

// Start begins listening for control requests on localhost. It blocks until the
// context is done or an error occurs.
//
// During an upgrade the old control server may still hold the port for a few
// seconds while it drains. Start retries binding with a backoff for up to 10
// seconds so the new process can take over cleanly.
func (cs *ControlServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/info", cs.infoHandler)
	mux.HandleFunc("/shutdown", cs.shutdownHandler)

	cs.server = &http.Server{
		Handler: mux,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cs.port)

	var listener net.Listener
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		listener, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		// If the context is already done, bail out immediately.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(500 * time.Millisecond):
		}
	}
	if err != nil {
		return fmt.Errorf("control server: failed to listen on %s after retries: %v", addr, err)
	}

	log.Printf("control server listening on %s", addr)

	errCh := make(chan error, 1)
	go func() {
		if err := cs.server.Serve(listener); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("control server failed: %v", err)
		} else {
			errCh <- nil
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cs.server.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// infoHandler returns information about the running server configuration.
func (cs *ControlServer) infoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeIPs := make([]string, 0, len(cs.sm.activeServers))
	for ip := range cs.sm.activeServers {
		activeIPs = append(activeIPs, ip.String())
	}

	resp := &controlInfoResponse{
		GitCommit:    GitCommit,
		GitTag:       GitTag,
		WgBlock:      cs.sm.wgBlock.String(),
		WgBlockPerIp: cs.sm.wgBlockPerIp,
		ActiveIPs:    activeIPs,
		Cloud:        cs.cloud,
		Takeover:     cs.sm.takeover,
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)
}

// shutdownHandler performs a two-phase graceful shutdown for zero-downtime upgrades:
//
//  1. Mark every active server as relinquished so that /connect and /disconnect
//     start returning 503, and WireGuard + iptables state will be preserved on exit.
//  2. Collect a dup'd file descriptor for every active HTTPS listener.
//  3. Create a Unix domain socket and return its path in the HTTP response so the
//     new process knows where to connect.
//  4. In a background goroutine, wait for the new process to connect and receive
//     the FDs via SCM_RIGHTS, then cancel all server contexts and the top-level
//     context so the old process exits.
//
// If anything goes wrong before the FD handoff (e.g. the new process never
// connects), the background goroutine still cancels everything so the old
// process doesn't hang forever.
func (cs *ControlServer) shutdownHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Phase 1: mark all servers as relinquished (503 for new client requests,
	// skip WireGuard/iptables cleanup on exit). We deliberately do NOT cancel
	// their contexts yet — the HTTPS listeners must stay alive so the kernel
	// socket remains open while we dup the FD and hand it off.
	relinquishedIPs := make([]string, 0, len(cs.sm.activeServers))
	for ip := range cs.sm.activeServers {
		cs.sm.MarkRelinquished(ip)
		relinquishedIPs = append(relinquishedIPs, ip.String())
	}

	// Phase 2: collect a dup'd FD for every active listener.
	files, meta, err := cs.sm.CollectListenerFiles()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to collect listener FDs: %v", err), http.StatusInternalServerError)
		return
	}

	// Phase 3: create the Unix socket that the new process will connect to.
	unixListener, err := CreateUpgradeSocket()
	if err != nil {
		for _, f := range files {
			f.Close()
		}
		http.Error(w, fmt.Sprintf("failed to create upgrade socket: %v", err), http.StatusInternalServerError)
		return
	}

	msg := &handoffMessage{Listeners: meta}

	// Build and send the HTTP response before we block on the FD handoff.
	resp := &controlShutdownResponse{
		Status:          "awaiting_handoff",
		RelinquishedIPs: relinquishedIPs,
		FDSocket:        UpgradeSocketPath,
		Listeners:       meta,
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		unixListener.Close()
		for _, f := range files {
			f.Close()
		}
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)

	// Flush so the upgrade command receives the response immediately.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Phase 4: hand off the FDs to the new process in the background, then
	// tear down the old process.
	go func() {
		defer func() {
			for _, f := range files {
				f.Close()
			}
		}()

		if err := ServeListenerFDs(unixListener, msg, files); err != nil {
			log.Printf("control server: FD handoff failed: %v", err)
			log.Printf("control server: shutting down without successful handoff")
		} else {
			log.Printf("control server: FD handoff complete — new process has the listeners")
		}

		// Give the HTTP response a moment to finish writing, then bring
		// everything down. CancelAll stops each server's HTTPS accept
		// loop and cleanup routines; cancelFn stops the top-level context
		// (which also stops this control server, the AWS poll loop, etc).
		time.Sleep(100 * time.Millisecond)
		cs.sm.CancelAll()

		// Small grace period so the per-server goroutines notice their
		// cancelled contexts before we yank the top-level context.
		time.Sleep(100 * time.Millisecond)
		log.Printf("control server: triggering process exit")
		cs.cancelFn()
	}()

	// Log a summary for operators tailing the journal.
	fmt.Fprintf(os.Stderr, "control server: upgrade initiated — %d listener(s) queued for handoff\n", len(files))
}
