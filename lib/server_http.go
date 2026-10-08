package lib

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type connectRequest struct {
	PeerPublicKey string
}

type connectResponse struct {
	AssignedAddr     string
	ServerPublicKey  string
	ServerListenPort int
}

type disconnectRequest struct {
	PeerPublicKey string
}

type disconnectResponse struct {
	Status string
}

type relinquishResponse struct {
	Status string
}

type versionResponse struct {
	GitCommit string `json:"git_commit"`
	GitTag    string `json:"git_tag"`
}

// listenForHttps serves the server's control API over TLS on port 443 of the
// bind address until the server's context is done, keeping the bind address
// present on the host interface and idle peers pruned while it runs.
func listenForHttps(server *Server) error {
	if !server.BindAddr.Is4() {
		return fmt.Errorf("invalid IPv4 bind address: %v", server.BindAddr)
	}

	go runIdlePeerRemovalLoop(server)

	// Add the bind address in case the host has not already configured it on the interface.
	_ = addBindAddr(server)
	go runBindAddrRefreshLoop(server)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { handleIndexRequest(server, w, r) })
	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) { handleConnectRequest(server, w, r) })
	mux.HandleFunc("/disconnect", func(w http.ResponseWriter, r *http.Request) { handleDisconnectRequest(server, w, r) })
	mux.HandleFunc("/relinquish", func(w http.ResponseWriter, r *http.Request) { handleRelinquishRequest(server, w, r) })
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) { handleVersionRequest(server, w, r) })

	cert, err := loadServerTls()
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%v:443", server.BindAddr))
	if err != nil {
		return fmt.Errorf("failed to listen on :443: %v", err)
	}

	serveErrors := make(chan error, 1)
	go func() {
		log.Printf("server listening on %v:443\n", server.BindAddr)
		err := httpServer.ServeTLS(listener, "", "")
		if err != http.ErrServerClosed {
			serveErrors <- fmt.Errorf("https server failed to serve %v: %v", server.BindAddr, err)
		} else {
			serveErrors <- nil
		}
	}()

	select {
	case <-server.Ctx.Done():
		log.Printf("server no longer listening on %v:443\n", server.BindAddr)
		return httpServer.Shutdown(server.Ctx)
	case err := <-serveErrors:
		return err
	}
}

func handleIndexRequest(server *Server, w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fmt.Fprintf(w, "vprox ok. received %v -> %v:443\n", r.RemoteAddr, server.BindAddr)
}

// handleConnectRequest adds the requesting peer to the server and responds with
// its assigned tunnel address and the server's WireGuard endpoint details.
func handleConnectRequest(server *Server, w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	recordConnectRequest()
	defer func() { recordConnectLatency(time.Since(requestStart)) }()

	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !authenticateRequest(server, w, r) {
		return
	}

	var request connectRequest
	if !readJsonRequest(w, r, &request) {
		return
	}

	peerKey, err := wgtypes.ParseKey(request.PeerPublicKey)
	if err != nil {
		http.Error(w, "invalid peer public key", http.StatusBadRequest)
		return
	}

	log.Printf("[%v] connect request from %v: %v", server.BindAddr, remoteIp(r), peerKey)
	peerIp, err := addPeer(server, peerKey)
	if errors.Is(err, errNoAddressesAvailable) {
		log.Printf("no more ip addresses available in %v", server.WgCidr)
		http.Error(w, "no more IP addresses available", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		log.Printf("%v", err)
		http.Error(w, "failed to configure WireGuard peer", http.StatusInternalServerError)
		return
	}
	log.Printf("[%v] new peer %v at %v: %v", server.BindAddr, remoteIp(r), peerIp, peerKey)

	writeJsonResponse(w, &connectResponse{
		AssignedAddr:     fmt.Sprintf("%v/%d", peerIp, server.WgCidr.Bits()),
		ServerPublicKey:  server.Key.PublicKey().String(),
		ServerListenPort: wireguardListenPort(server),
	})
}

// handleDisconnectRequest removes the requesting peer from the server.
func handleDisconnectRequest(server *Server, w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	recordDisconnectRequest()
	defer func() { recordDisconnectLatency(time.Since(requestStart)) }()

	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !authenticateRequest(server, w, r) {
		return
	}

	var request disconnectRequest
	if !readJsonRequest(w, r, &request) {
		return
	}

	peerKey, err := wgtypes.ParseKey(request.PeerPublicKey)
	if err != nil {
		http.Error(w, "invalid peer public key", http.StatusBadRequest)
		return
	}

	log.Printf("[%v] disconnect request from %v: %v", server.BindAddr, remoteIp(r), peerKey)
	if err := removePeer(server, peerKey); err != nil {
		log.Printf("failed to cleanup peer %v: %v", peerKey, err)
		http.Error(w, "failed to cleanup peer", http.StatusInternalServerError)
		return
	}

	writeJsonResponse(w, &disconnectResponse{Status: "success"})
}

// handleRelinquishRequest marks the server to leave its WireGuard state in
// place on exit so that a replacement server instance can take it over.
func handleRelinquishRequest(server *Server, w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !authenticateRequest(server, w, r) {
		return
	}

	server.mu.Lock()
	server.relinquished = true
	server.mu.Unlock()

	log.Printf("[%v] server relinquished - WireGuard state will be preserved on exit", server.BindAddr)
	writeJsonResponse(w, &relinquishResponse{Status: "relinquished"})
}

func handleVersionRequest(server *Server, w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !authenticateRequest(server, w, r) {
		return
	}

	writeJsonResponse(w, &versionResponse{
		GitCommit: GitCommit,
		GitTag:    GitTag,
	})
}

// authenticateRequest reports whether the request carries valid credentials,
// writing a 401 response if it does not.
func authenticateRequest(server *Server, w http.ResponseWriter, r *http.Request) bool {
	if err := server.Auth.Authenticate(r); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// readJsonRequest decodes the request body into request and reports whether
// it succeeded, writing a 400 response if it did not.
func readJsonRequest(w http.ResponseWriter, r *http.Request, request any) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return false
	}
	if err := json.Unmarshal(body, request); err != nil {
		http.Error(w, "failed to parse request body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJsonResponse(w http.ResponseWriter, response any) {
	body, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func remoteIp(r *http.Request) string {
	return strings.Split(r.RemoteAddr, ":")[0]
}

//go:embed certs/cert.pem certs/key.pem
var defaultCerts embed.FS

// loadServerTls returns the embedded TLS certificate used for control connections.
func loadServerTls() (tls.Certificate, error) {
	certData, _ := defaultCerts.ReadFile("certs/cert.pem")
	keyData, _ := defaultCerts.ReadFile("certs/key.pem")

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load server certificate: %v", err)
	}
	return cert, nil
}
