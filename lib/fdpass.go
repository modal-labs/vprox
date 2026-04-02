package lib

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"
)

// UpgradeSocketPath is the Unix socket used for listener FD handoff during upgrades.
var UpgradeSocketPath = RunDir + "/upgrade.sock"

const handoffTimeout = 30 * time.Second

// ListenerMeta describes a listener being passed during an upgrade handoff.
type ListenerMeta struct {
	BindAddr string `json:"bind_addr"`
	Index    uint16 `json:"index"`
}

// handoffMessage is the metadata sent over the Unix socket alongside the FDs.
type handoffMessage struct {
	Listeners []ListenerMeta `json:"listeners"`
}

// handoffAck is sent back by the receiver to confirm FDs were received.
type handoffAck struct {
	Status string `json:"status"`
}

// ReceivedListener pairs handoff metadata with the reconstructed net.Listener.
type ReceivedListener struct {
	Meta     ListenerMeta
	Listener net.Listener
}

// HandoffConn holds the received listeners and the still-open Unix connection
// to the old process. The caller must call Ack() after it has started serving
// on the inherited listeners so the old process knows it is safe to shut down.
type HandoffConn struct {
	conn      *net.UnixConn
	listeners []ReceivedListener
}

// Listeners returns the inherited listeners received from the old process.
func (h *HandoffConn) Listeners() []ReceivedListener {
	return h.listeners
}

// Ack tells the old process that the new server is accepting connections and
// it is safe to tear down. This must be called exactly once, after the caller
// has started serving on every inherited listener.
func (h *HandoffConn) Ack() {
	ackBytes, _ := json.Marshal(&handoffAck{Status: "ok"})
	if _, err := h.conn.Write(ackBytes); err != nil {
		log.Printf("warning: failed to send handoff ack: %v", err)
	}
	h.conn.Close()
}

// CreateUpgradeSocket creates a Unix domain socket for listener FD handoff.
// The caller is responsible for closing the returned listener (typically via
// ServeListenerFDs which closes it internally).
func CreateUpgradeSocket() (net.Listener, error) {
	if err := createRunDir(); err != nil {
		return nil, fmt.Errorf("failed to create run dir: %v", err)
	}
	// Remove stale socket from a previous upgrade attempt.
	os.Remove(UpgradeSocketPath)
	l, err := net.Listen("unix", UpgradeSocketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create upgrade socket at %s: %v", UpgradeSocketPath, err)
	}
	return l, nil
}

// ServeListenerFDs accepts a single connection on the Unix socket listener,
// sends the listener file descriptors with their metadata using SCM_RIGHTS,
// and waits for an acknowledgment from the receiver.
//
// This function blocks until the handoff completes or times out. It closes
// unixListener and removes the socket file before returning.
func ServeListenerFDs(unixListener net.Listener, msg *handoffMessage, files []*os.File) error {
	defer unixListener.Close()
	defer os.Remove(UpgradeSocketPath)

	// Set a deadline on the accept so we don't block forever if no new
	// process connects (e.g. the new binary failed to start).
	if ul, ok := unixListener.(*net.UnixListener); ok {
		ul.SetDeadline(time.Now().Add(handoffTimeout))
	}

	conn, err := unixListener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept handoff connection: %v", err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}
	unixConn.SetDeadline(time.Now().Add(handoffTimeout))

	// Marshal the metadata header.
	headerBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal handoff message: %v", err)
	}

	// Collect raw file descriptor integers for SCM_RIGHTS.
	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd())
	}
	rights := syscall.UnixRights(fds...)

	// Send the JSON metadata as the data payload and the FDs as the
	// out-of-band control message, all in a single sendmsg(2) call.
	_, _, err = unixConn.WriteMsgUnix(headerBytes, rights, nil)
	if err != nil {
		return fmt.Errorf("failed to send listener FDs: %v", err)
	}

	// Wait for the receiver to acknowledge.
	buf := make([]byte, 512)
	n, err := unixConn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read handoff ack: %v", err)
	}

	var ack handoffAck
	if err := json.Unmarshal(buf[:n], &ack); err != nil {
		return fmt.Errorf("failed to parse handoff ack: %v", err)
	}
	if ack.Status != "ok" {
		return fmt.Errorf("handoff rejected by receiver: %s", ack.Status)
	}

	return nil
}

// ReceiveListenerFDs connects to the upgrade Unix socket and receives listener
// file descriptors from the old server process. It returns a *HandoffConn that
// holds the reconstructed listeners and the still-open Unix connection.
//
// The caller must:
//  1. Start serving on every listener returned by HandoffConn.Listeners().
//  2. Call HandoffConn.Ack() to tell the old process it is safe to shut down.
//
// This two-step design ensures there is no window where neither process is
// accepting connections on :443.
func ReceiveListenerFDs(socketPath string) (*HandoffConn, error) {
	conn, err := net.DialTimeout("unix", socketPath, handoffTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upgrade socket at %s: %v", socketPath, err)
	}

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}
	unixConn.SetDeadline(time.Now().Add(handoffTimeout))

	// Read both the JSON data payload and the SCM_RIGHTS control message.
	// 64 KiB for data is generous for the JSON header; 8 KiB for OOB
	// supports hundreds of file descriptors (each takes ~4 bytes in the
	// control message plus a fixed header).
	buf := make([]byte, 65536)
	oob := make([]byte, 8192)
	n, oobn, _, _, err := unixConn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, fmt.Errorf("failed to receive handoff message: %v", err)
	}

	// Parse the JSON metadata.
	var msg handoffMessage
	if err := json.Unmarshal(buf[:n], &msg); err != nil {
		return nil, fmt.Errorf("failed to parse handoff message: %v", err)
	}

	// Extract file descriptors from the control message.
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("failed to parse socket control message: %v", err)
	}

	var fds []int
	for _, scm := range scms {
		gotFds, err := syscall.ParseUnixRights(&scm)
		if err != nil {
			return nil, fmt.Errorf("failed to parse unix rights: %v", err)
		}
		fds = append(fds, gotFds...)
	}

	if len(fds) != len(msg.Listeners) {
		// Clean up any received FDs before returning the error.
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return nil, fmt.Errorf("FD count mismatch: received %d FDs for %d listeners", len(fds), len(msg.Listeners))
	}

	// Reconstruct net.Listener values from the raw file descriptors.
	result := make([]ReceivedListener, len(fds))
	for i, fd := range fds {
		name := fmt.Sprintf("inherited-%s", msg.Listeners[i].BindAddr)
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			// Clean up.
			for j := i; j < len(fds); j++ {
				syscall.Close(fds[j])
			}
			for j := 0; j < i; j++ {
				result[j].Listener.Close()
			}
			return nil, fmt.Errorf("os.NewFile returned nil for FD %d", fd)
		}

		listener, err := net.FileListener(file)
		file.Close() // FileListener dup's the FD, so close our copy.
		if err != nil {
			// Clean up remaining FDs and already-created listeners.
			for j := i + 1; j < len(fds); j++ {
				syscall.Close(fds[j])
			}
			for j := 0; j < i; j++ {
				result[j].Listener.Close()
			}
			return nil, fmt.Errorf("failed to create listener from FD %d (%s): %v", fd, name, err)
		}

		result[i] = ReceivedListener{
			Meta:     msg.Listeners[i],
			Listener: listener,
		}
	}

	return &HandoffConn{conn: unixConn, listeners: result}, nil
}
