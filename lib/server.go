package lib

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FwmarkBase is the base value for firewall marks used by vprox.
const FwmarkBase = 0x54437D00

// UDP listen port for WireGuard connections.
const WireguardListenPort = 50227

// Server handles state for one WireGuard network.
//
// The `vprox server` command should create one Server instance for each
// private IP that the server should bind to.
type Server struct {
	// Key is the private key of the server.
	Key wgtypes.Key

	// BindAddr is the private IPv4 address that the server binds to.
	BindAddr net.IP

	/// Password is needed to authenticate connection requests.
	Password string

	/// Index is a unique server index for firewall marks and other uses. It starts at 0.
	Index uint16

	/// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	/// WgCidr is the CIDR block of IPs that the server assigns to WireGuard peers.
	WgCidr *net.IPNet

	/// Ctx is the shutdown context for the server.
	Ctx context.Context
}

func (srv *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fmt.Fprintf(w, "vprox ok. received %v -> %v:443\n", r.RemoteAddr, srv.BindAddr)
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// Handle a new connection.
func (srv *Server) connectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+srv.Password {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	type ConnectRequest struct {
		PeerPublicKey string
	}
	type ConnectResponse struct {
		AssignedAddr    string
		ServerPublicKey string
	}

	req := &ConnectRequest{}
	if err = json.Unmarshal(buf, req); err != nil {
		http.Error(w, "failed to parse request body", http.StatusBadRequest)
		return
	}

	peerKey, err := wgtypes.ParseKey(req.PeerPublicKey)
	if err != nil {
		http.Error(w, "invalid peer public key", http.StatusBadRequest)
	}

	// Add a WireGuard peer for the new connection.
	srv.WgClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         peerKey,
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{{
					// TODO: allocate an IP address from the WgCidr
					IP:   net.IPv4(240, 0, 0, 3),
					Mask: srv.WgCidr.Mask,
				}},
			},
		},
	})

	// Return the assigned IP address and the server's public key.
	resp := &ConnectResponse{
		AssignedAddr:    "10.0.0.24/8",
		ServerPublicKey: srv.Key.PublicKey().String(),
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)
}

func (srv *Server) Ifname() string {
	return fmt.Sprintf("vprox%d", srv.Index)
}

func (srv *Server) StartWireguard() error {
	ifname := srv.Ifname()
	link := &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}}
	_ = netlink.LinkDel(link) // remove if it already exists
	err := netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("failed to create WireGuard device: %v", err)
	}

	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: srv.WgCidr,
	})
	if err != nil {
		return fmt.Errorf("failed to add address to WireGuard device: %v", err)
	}

	listenPort := WireguardListenPort
	firewallMark := FwmarkBase + int(srv.Index)
	err = srv.WgClient.ConfigureDevice(ifname, wgtypes.Config{
		PrivateKey:   &srv.Key,
		ListenPort:   &listenPort,
		FirewallMark: &firewallMark,
	})
	if err != nil {
		return err
	}

	return nil
}

func (srv *Server) CleanupWireguard() {
	ifname := srv.Ifname()
	_ = netlink.LinkDel(&linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}})
}

func (srv *Server) StartIptables() error {
	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(5))
	if err != nil {
		return fmt.Errorf("failed to initialize iptables: %v", err)
	}

	firewallMark := FwmarkBase + int(srv.Index)
	err = ipt.AppendUnique("nat", "POSTROUTING",
		"-m", "mark", "--mark", strconv.Itoa(firewallMark),
		"-j", "SNAT", "--to-source", srv.BindAddr.String(),
		"--comment", fmt.Sprintf("snat rule for %s", srv.Ifname()))
	if err != nil {
		return fmt.Errorf("failed to add SNAT rule: %v", err)
	}

	return nil
}

func (srv *Server) CleanupIptables() {
	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(5))
	if err != nil {
		log.Printf("failed to initialize iptables: %v", err)
		return
	}

	firewallMark := FwmarkBase + int(srv.Index)
	ipt.Delete("nat", "POSTROUTING",
		"-m", "mark", "--mark", strconv.Itoa(firewallMark),
		"-j", "SNAT", "--to-source", srv.BindAddr.String(),
		"--comment", fmt.Sprintf("snat rule for %s", srv.Ifname()))
}

func (srv *Server) ListenForHttps() error {
	if len(srv.BindAddr) != net.IPv4len {
		return fmt.Errorf("invalid IPv4 bind address: %v", srv.BindAddr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.indexHandler)
	mux.HandleFunc("/connect", srv.connectHandler)

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

	listener, err := net.Listen("tcp", fmt.Sprintf("%v:443", srv.BindAddr))
	if err != nil {
		return fmt.Errorf("failed to listen on :443: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("server listening on %v:443\n", srv.BindAddr)
		err = httpServer.ServeTLS(listener, "", "")
		if err != http.ErrServerClosed {
			errCh <- fmt.Errorf("https server failed to serve %v: %v", srv.BindAddr, err)
		} else {
			errCh <- nil
		}
	}()

	select {
	case <-srv.Ctx.Done():
		return httpServer.Shutdown(srv.Ctx)
	case err = <-errCh:
		return err
	}
}

//go:embed certs/cert.pem certs/key.pem
var defaultCerts embed.FS

// loadServerTls loads the server's TLS certificate for control connections.
func loadServerTls() (tls.Certificate, error) {
	certData, _ := defaultCerts.ReadFile("certs/cert.pem")
	keyData, _ := defaultCerts.ReadFile("certs/key.pem")

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load server certificate: %v", err)
	}
	return cert, nil
}