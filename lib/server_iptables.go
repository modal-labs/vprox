package lib

import (
	"fmt"
	"log"
	"strconv"
)

// fwmarkRuleSpec returns the mangle PREROUTING rule that marks traffic arriving
// from the server's WireGuard interface with the server's firewall mark.
func fwmarkRuleSpec(server *Server) []string {
	return []string{
		"-i", wireguardIfname(server),
		"-j", "MARK", "--set-mark", strconv.Itoa(firewallMark(server)),
		"-m", "comment", "--comment", fmt.Sprintf("vprox fwmark rule for %s", wireguardIfname(server)),
	}
}

// snatRuleSpec returns the nat POSTROUTING rule that rewrites the source of
// marked outbound traffic to the server's bind address.
func snatRuleSpec(server *Server) []string {
	return []string{
		"-m", "mark", "--mark", strconv.Itoa(firewallMark(server)),
		"-j", "SNAT", "--to-source", server.BindAddr.String(),
		"-m", "comment", "--comment", fmt.Sprintf("vprox snat rule for %s", wireguardIfname(server)),
	}
}

// mssRuleSpec returns the filter FORWARD rule that clamps the TCP MSS of
// forwarded SYN packets so they fit inside the WireGuard tunnel MTU.
func mssRuleSpec(server *Server) []string {
	return []string{
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--set-mss", "1160",
		"-m", "comment", "--comment", fmt.Sprintf("vprox mss rule for %s", wireguardIfname(server)),
	}
}

func firewallMark(server *Server) int {
	return FwmarkBase + int(server.Index)
}

// addIptablesRules installs the fwmark, SNAT, and MSS rules for the server.
// Rules installed before a failure are removed again before returning the error.
func addIptablesRules(server *Server) error {
	if err := server.Ipt.AppendUnique("mangle", "PREROUTING", fwmarkRuleSpec(server)...); err != nil {
		return fmt.Errorf("failed to add fwmark rule: %v", err)
	}

	if err := server.Ipt.AppendUnique("nat", "POSTROUTING", snatRuleSpec(server)...); err != nil {
		_ = server.Ipt.Delete("mangle", "PREROUTING", fwmarkRuleSpec(server)...)
		return fmt.Errorf("failed to add SNAT rule: %v", err)
	}

	if err := server.Ipt.AppendUnique("filter", "FORWARD", mssRuleSpec(server)...); err != nil {
		_ = server.Ipt.Delete("nat", "POSTROUTING", snatRuleSpec(server)...)
		_ = server.Ipt.Delete("mangle", "PREROUTING", fwmarkRuleSpec(server)...)
		return fmt.Errorf("failed to add MSS rule: %v", err)
	}

	return nil
}

// removeIptablesRules removes the fwmark, SNAT, and MSS rules for the server,
// logging rather than returning any failures.
func removeIptablesRules(server *Server) {
	if err := server.Ipt.Delete("mangle", "PREROUTING", fwmarkRuleSpec(server)...); err != nil {
		log.Printf("warning: error cleaning up iptables: failed to remove fwmark rule: %v\n", err)
	}
	if err := server.Ipt.Delete("nat", "POSTROUTING", snatRuleSpec(server)...); err != nil {
		log.Printf("warning: error cleaning up iptables: failed to remove SNAT rule: %v\n", err)
	}
	if err := server.Ipt.Delete("filter", "FORWARD", mssRuleSpec(server)...); err != nil {
		log.Printf("warning: error cleaning up iptables: failed to remove MSS rule: %v\n", err)
	}
}
