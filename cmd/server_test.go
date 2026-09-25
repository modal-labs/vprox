package cmd

import (
	"net/netip"
	"testing"

	"github.com/modal-labs/vprox/lib"
)

type fixedAwsAddresses []lib.AwsInterface

func (a fixedAwsAddresses) GetAddresses() ([]lib.AwsInterface, error) { return a, nil }

type retryManager struct {
	finished []netip.Addr
	started  []netip.Addr
}

func (m *retryManager) ReapFinished() []netip.Addr {
	finished := m.finished
	m.finished = nil
	return finished
}
func (m *retryManager) Start(ip netip.Addr) error {
	m.started = append(m.started, ip)
	return nil
}
func (*retryManager) Stop(netip.Addr) {}

func TestPollAwsRetriesReapedStartupFailure(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	manager := &retryManager{finished: []netip.Addr{ip}}
	currentIps := ipSet{ip: struct{}{}}

	got, err := pollAws(fixedAwsAddresses{{PrivateIps: []string{ip.String()}}}, currentIps, manager)
	if err != nil {
		t.Fatalf("pollAws() error = %v", err)
	}
	if len(manager.started) != 1 || manager.started[0] != ip {
		t.Fatalf("Start() calls = %v, want [%v]", manager.started, ip)
	}
	if _, ok := got[ip]; !ok {
		t.Fatalf("current IP set = %v, want %v retained after retry", got, ip)
	}
}
