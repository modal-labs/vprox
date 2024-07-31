package cmd

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RunDir is the path for runtime data that should be kept across restarts.
const RunDir string = "/run/vprox"

// Server handles state for one WireGuard network.
//
// The `vprox server` command should create one Server instance for each
// private IP that the server should bind to.
type Server struct {
	// Key is the private key of the server.
	Key wgtypes.Key

	// BindAddr is the private IPv4 address that the server binds to.
	BindAddr net.IP
}

// NewServer creates a new VPN server with the given private key and bind address.
func NewServer(key wgtypes.Key, bindAddr net.IP) (*Server, error) {
	if len(bindAddr) != net.IPv4len {
		return nil, fmt.Errorf("invalid IPv4 bind address: %v", bindAddr)
	}
	srv := new(Server)
	srv.Key = key
	srv.BindAddr = bindAddr
	return srv, nil
}

func (srv *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "vprox ok. received %v -> %v:443\n", r.RemoteAddr, srv.BindAddr)
}

func (srv *Server) listenForHttps(ctx context.Context, bindAddr net.IP) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.indexHandler)

	cert, err := loadServerTls()
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%v:443", bindAddr))
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
	case <-ctx.Done():
		return httpServer.Shutdown(ctx)
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

	key, err := getServerKey()
	if err != nil {
		return fmt.Errorf("failed to load server key: %v", err)
	}

	// Display the public key, just for information.
	fmt.Printf("%s %s\n",
		color.New(color.Bold).Sprint("server public key:"),
		key.PublicKey().String())

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()
	g, ctx := errgroup.WithContext(ctx)

	for _, ipStr := range serverCmdArgs.ip {
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			return fmt.Errorf("invalid IPv4 address: %v", ipStr)
		}

		srv, err := NewServer(key, ip)
		if err != nil {
			return err
		}

		g.Go(func() error {
			if err := srv.listenForHttps(ctx, ip); err != nil {
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
