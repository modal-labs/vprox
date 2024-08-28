package cmd

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/fatih/color"
	"github.com/modal-labs/vprox/lib"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RunDir is the path for runtime data that should be kept across restarts.
const RunDir string = "/run/vprox"

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
					// TODO: Use correct subnet and return value
					IP:   net.IPv4(10, 0, 0, 0),
					Mask: net.CIDRMask(32, 32),
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

func (srv *Server) startWireguard() error {
	ifname := srv.Ifname()
	link := &lib.LinkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}}
	_ = netlink.LinkDel(link) // remove if it already exists
	err := netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("failed to create WireGuard device: %v", err)
	}

	gatewayIP := net.IPv4(1, 2, 3, 4) // TODO
	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   gatewayIP,
			Mask: net.CIDRMask(24, 32), // TODO
		},
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

func (srv *Server) cleanupWireguard() {
	ifname := srv.Ifname()
	_ = netlink.LinkDel(&lib.LinkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}})
}

func (srv *Server) startIptables() error {
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

func (srv *Server) cleanupIptables() {
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

func (srv *Server) listenForHttps() error {
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

func createRunDir() error {
	return os.MkdirAll(RunDir, 0700)
}

func getServerKey() (key wgtypes.Key, err error) {
	if err = createRunDir(); err != nil {
		return
	}
	keyFile := path.Join(RunDir, "server-key")
	contents, err := os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		// Generate a private key for the server. This private key will be reused in
		// event of a server restart, so we save it in `/run/vprox/key`.
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return
		}
		if err = os.WriteFile(keyFile, []byte(key.String()), 0600); err != nil {
			return
		}
		return
	} else if err != nil {
		return
	}
	return wgtypes.ParseKey(strings.TrimSpace(string(contents)))
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

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start a VPN server, listening for new WireGuard peers",
	RunE:  runServer,
}

var serverCmdArgs struct {
	ip []string
}

func init() {
	ServerCmd.Flags().StringArrayVar(&serverCmdArgs.ip, "ip",
		[]string{}, "IPv4 address to bind to")
}

func runServer(cmd *cobra.Command, args []string) error {
	if len(serverCmdArgs.ip) == 0 {
		return errors.New("missing required flag: --ip")
	}
	if len(serverCmdArgs.ip) > 1024 {
		return errors.New("too many --ip flags")
	}

	key, err := getServerKey()
	if err != nil {
		return fmt.Errorf("failed to load server key: %v", err)
	}

	password := os.Getenv("VPROX_PASSWORD")
	if password == "" {
		return errors.New("VPROX_PASSWORD environment variable is not set")
	}

	// Make a shared WireGuard client.
	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to initialize wgctrl: %v", err)
	}

	// Display the public key, just for information.
	fmt.Printf("%s %s\n",
		color.New(color.Bold).Sprint("server public key:"),
		key.PublicKey().String())

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()
	g, ctx := errgroup.WithContext(ctx)

	for i, ipStr := range serverCmdArgs.ip {
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			return fmt.Errorf("invalid IPv4 address: %v", ipStr)
		}

		srv := new(Server)
		srv.Key = key
		srv.BindAddr = ip
		srv.Password = password
		srv.Index = uint16(i)
		srv.WgClient = wgClient
		srv.Ctx = ctx

		g.Go(func() error {
			if err := srv.startWireguard(); err != nil {
				return fmt.Errorf("failed to start WireGuard: %v", err)
			}
			defer srv.cleanupWireguard()

			if err := srv.startIptables(); err != nil {
				return fmt.Errorf("failed to start iptables: %v", err)
			}
			defer srv.cleanupIptables()

			if err := srv.listenForHttps(); err != nil {
				return fmt.Errorf("https server failed: %v", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}
