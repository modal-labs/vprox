package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
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
	Status          string   `json:"status"`
	RelinquishedIPs []string `json:"relinquished_ips"`
}

// SetCloud stores the cloud provider string so it can be reported in /info.
func (cs *ControlServer) SetCloud(cloud string) {
	cs.cloud = cloud
}

// Start begins listening for control requests on localhost. It blocks until the
// context is done or an error occurs.
func (cs *ControlServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/info", cs.infoHandler)
	mux.HandleFunc("/shutdown", cs.shutdownHandler)

	cs.server = &http.Server{
		Handler: mux,
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cs.port))
	if err != nil {
		return fmt.Errorf("control server: failed to listen on 127.0.0.1:%d: %v", cs.port, err)
	}

	log.Printf("control server listening on 127.0.0.1:%d", cs.port)

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

// shutdownHandler triggers a graceful shutdown of the running server.
// It relinquishes all active servers (preserving WireGuard state) and then
// cancels the server context so the process exits.
func (cs *ControlServer) shutdownHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Relinquish all active servers so WireGuard state is preserved.
	relinquishedIPs := make([]string, 0)
	for ip := range cs.sm.activeServers {
		cs.sm.RelinquishServer(ip)
		relinquishedIPs = append(relinquishedIPs, ip.String())
	}

	resp := &controlShutdownResponse{
		Status:          "shutting_down",
		RelinquishedIPs: relinquishedIPs,
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)

	// Flush the response before shutting down.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Cancel the top-level context to trigger graceful shutdown.
	// Do this in a goroutine so the HTTP response completes first.
	go func() {
		time.Sleep(100 * time.Millisecond)
		log.Printf("control server: triggering shutdown after upgrade request")
		cs.cancelFn()
	}()
}
