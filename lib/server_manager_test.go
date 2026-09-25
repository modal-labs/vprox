package lib

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
)

func TestStartFailureCanBeReapedBeforeRetry(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	serveCalls := 0
	var serverCtx context.Context
	sm := &ServerManager{
		ctx:           context.Background(),
		waitGroup:     new(sync.WaitGroup),
		wgBlock:       netip.MustParsePrefix("10.0.0.0/24"),
		wgBlockPerIp:  30,
		activeServers: make(map[netip.Addr]ServerInfo),
		initializeServer: func(*Server) error {
			return nil
		},
		serveServer: func(srv *Server) error {
			serveCalls++
			serverCtx = srv.Ctx
			if serveCalls == 1 {
				return errors.New("simulated startup failure")
			}
			return nil
		},
	}

	if err := sm.Start(ip); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	sm.Wait()
	if serverCtx.Err() == nil {
		t.Fatal("server context remains active after its goroutine exits")
	}
	if _, ok := sm.activeServers[ip]; !ok {
		t.Fatal("completed registration was removed before serialized reaping")
	}

	finished := sm.ReapFinished()
	if len(finished) != 1 || finished[0] != ip {
		t.Fatalf("ReapFinished() = %v, want [%v]", finished, ip)
	}
	if _, ok := sm.activeServers[ip]; ok {
		t.Fatal("failed server remains active after reaping")
	}
	if len(sm.freeIndices) != 1 || sm.freeIndices[0] != 0 {
		t.Fatalf("free indices = %v, want [0]", sm.freeIndices)
	}

	if err := sm.Start(ip); err != nil {
		t.Fatalf("retry Start() error = %v", err)
	}
	sm.Wait()
	if serveCalls != 2 {
		t.Fatalf("serve calls = %d, want 2", serveCalls)
	}
	if got := sm.activeServers[ip].i; got != 0 {
		t.Fatalf("retry index = %d, want reaped index 0", got)
	}
}

func TestStartRejectsReplacementUntilPreviousServerFinishes(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	started := make(chan struct{})
	finish := make(chan struct{})
	sm := &ServerManager{
		ctx:           context.Background(),
		waitGroup:     new(sync.WaitGroup),
		wgBlock:       netip.MustParsePrefix("10.0.0.0/24"),
		wgBlockPerIp:  30,
		activeServers: make(map[netip.Addr]ServerInfo),
		initializeServer: func(*Server) error {
			return nil
		},
		serveServer: func(*Server) error {
			close(started)
			<-finish
			return nil
		},
	}

	if err := sm.Start(ip); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	<-started
	first := sm.activeServers[ip]
	if err := sm.Start(ip); err == nil {
		t.Fatal("second Start() succeeded while previous server was still active")
	}
	if got := sm.activeServers[ip].i; got != first.i {
		t.Fatalf("active index changed from %d to %d", first.i, got)
	}
	if len(sm.freeIndices) != 0 {
		t.Fatalf("free indices before previous server finished = %v, want none", sm.freeIndices)
	}

	close(finish)
	sm.Wait()
	if got := sm.ReapFinished(); len(got) != 1 || got[0] != ip {
		t.Fatalf("ReapFinished() = %v, want [%v]", got, ip)
	}
}
