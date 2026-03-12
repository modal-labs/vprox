# vprox

vprox is a high-performance network proxy acting as a split tunnel VPN, powered by WireGuard. The server accepts peering requests from clients, which then establish WireGuard tunnels that direct all traffic on the client's network interface through the server, with IP masquerading.

Both the client and server commands need root access. The server can have multiple public IP addresses attached, and on cloud providers, it automatically uses the instance metadata endpoint to discover its public IP addresses and start one proxy for each.

This property allows the server to be high-availability. In the event of a restart or network partition, the tunnels remain open. If the server's IP address is attached to a new host, clients will automatically re-establish connections. This means that IP addresses can be moved to different hosts in event of an outage.

## Architecture

In single-tunnel mode, vprox creates one WireGuard interface per connection:

```
Client                                Server
┌──────────┐     UDP :50227     ┌──────────┐
│  vprox0  │◄──────────────────►│  vprox0  │──► Internet
│ (wg)     │                    │ (wg)     │    (SNAT)
└──────────┘                    └──────────┘
```

In multi-tunnel mode (`--tunnels N`), vprox creates N parallel WireGuard interfaces, each on a different UDP port. On the client, a dummy interface with policy routing presents a single `vprox0` device to applications while distributing traffic across all tunnels:

```
Client                                              Server
┌──────────┐  policy routing    ┌──────────┐
│  vprox0  │  (dummy, user-     │  vprox0  │◄─── UDP :50227 ───► vprox0t0 (wg)
│          │   facing)          │  vprox0t1│◄─── UDP :50228 ───► vprox0t1 (wg)
│          │                    │  vprox0t2│◄─── UDP :50229 ───► vprox0t2 (wg) ──► Internet
│          │  ip rule: to wg    │  vprox0t3│◄─── UDP :50230 ───► vprox0t3 (wg)     (SNAT)
│          │  subnet → table    └──────────┘
│          │  with multipath
│ vprox0t0 │◄──────────────────►
│ vprox0t1 │◄──────────────────►
│ vprox0t2 │◄──────────────────►
│ vprox0t3 │◄──────────────────►
└──────────┘
```

Each tunnel uses a different UDP port, so the NIC's RSS (Receive Side Scaling) hashes them to different hardware RX queues. The kernel's multipath routing distributes flows across tunnels using L4 hashing. Applications bind to the single `vprox0` interface and are unaware of the underlying tunnels.

## Usage

### Prerequisites

On the Linux VPN server and client, install system requirements (`iptables` and `wireguard`).

```bash
# On Ubuntu
sudo apt install iptables wireguard

# On Fedora / Amazon Linux
sudo dnf install iptables wireguard-tools
```

Set the required kernel parameters. Enable IPv4 forwarding, and make sure that [`rp_filter`](https://sysctl-explorer.net/net/ipv4/rp_filter/) is set to 2, or masqueraded packets may be filtered out.

```bash
# Applies until next reboot
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=2
```

### Basic setup

You'll need the private IPv4 address of the server connected to an Internet gateway (use the `ip addr` command), as well as a block of IPs to allocate to the WireGuard subnet between server and client. This can be arbitrarily chosen to not overlap with other subnets.

```bash
# [Machine A: public IP 1.2.3.4, private IP 172.31.64.125]
VPROX_PASSWORD=my-password vprox server --ip 172.31.64.125 --wg-block 240.1.0.0/16

# [Machine B: public IP 5.6.7.8]
VPROX_PASSWORD=my-password vprox connect 1.2.3.4 --interface vprox0
curl ifconfig.me                     # => 5.6.7.8
curl --interface vprox0 ifconfig.me  # => 1.2.3.4
```

Note that Machine B must be able to send UDP packets to port 50227 on Machine A, and TCP to port 443.

All outbound network traffic seen by `vprox0` will automatically be forwarded through the WireGuard tunnel. The VPN server masquerades the source IP address.

### Multi-tunnel mode (high throughput)

A single WireGuard tunnel is encapsulated in one UDP flow (fixed 4-tuple). On cloud providers like AWS, NIC hardware hashes flows to RX queues by this 4-tuple, so a single tunnel is limited to the throughput of one hardware queue — typically ~2-2.5 Gbps on AWS ENA.

Multi-tunnel mode creates N parallel WireGuard tunnels on different UDP ports, spreading traffic across multiple NIC queues:

```bash
# Server: 4 parallel tunnels per IP
VPROX_PASSWORD=my-password vprox server --ip 172.31.64.125 --wg-block 240.1.0.0/16 --tunnels 4

# Client: 4 parallel tunnels (must be <= server's --tunnels value)
VPROX_PASSWORD=my-password vprox connect 1.2.3.4 --interface vprox0 --tunnels 4
```

Both server and client must use `--tunnels`. The `dummy` kernel module must be available on the client (`sudo modprobe dummy`).

**Required sysctl on both server and client** for multipath flow distribution:

```bash
sudo sysctl -w net.ipv4.fib_multipath_hash_policy=1
```

Applications bind to the single `vprox0` interface as before — the multi-tunnel routing is transparent.

**Choosing the number of tunnels:** Start with `--tunnels 4`. The optimal value depends on the number of CPU cores and NIC queues. On a 4-core server, 4 tunnels will typically saturate the CPU. Adding more tunnels than CPU cores provides diminishing returns since WireGuard encryption becomes the bottleneck.

### Performance tuning

For maximum throughput, apply these additional sysctl settings on both server and client:

```bash
# UDP/Socket buffer sizes (WireGuard uses UDP)
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
sudo sysctl -w net.core.rmem_default=1048576
sudo sysctl -w net.core.wmem_default=1048576

# Network device backlog (for high packet rates)
sudo sysctl -w net.core.netdev_max_backlog=50000

# TCP tuning (for traffic inside the tunnel)
sudo sysctl -w net.ipv4.tcp_rmem="4096 1048576 26214400"
sudo sysctl -w net.ipv4.tcp_wmem="4096 1048576 26214400"
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

# Multipath flow hashing (required for multi-tunnel)
sudo sysctl -w net.ipv4.fib_multipath_hash_policy=1

# Connection tracking limits (for NAT with many peers)
sudo sysctl -w net.netfilter.nf_conntrack_max=1048576
```

To make these settings persistent across reboots, add them to `/etc/sysctl.d/99-vprox.conf` without the `sudo sysctl -w` prefix, then apply with `sudo sysctl --system`.


### Building

To build `vprox`, run the following command with Go 1.22+ installed:

```bash
CGO_ENABLED=0 go build
```

This produces a static binary in `./vprox`.

### Multiple private IPs

On cloud providers like AWS, you can attach [secondary private IP addresses](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/MultipleIP.html) to an interface and associate each of them with a global IPv4 unicast address.

A `vprox` server listening on multiple IP addresses needs to provide `--ip` option once for every IP, and each IP requires its own WireGuard VPN subnet with a non-overlapping address range. You can pass `--wg-block-per-ip /22` to split the `--wg-block` into smaller blocks for each IP.

On AWS in particular, the `--cloud aws` option allows you to automatically discover the private IP addresses of the server by periodically querying the instance metadata endpoint.

## Features

- Works on Linux 5.15+ with WireGuard installed
- Supports forwarding IPv4 packets
- Works if the server has multiple IPs, specified with `--wg-block-per-ip`
- Automatic discovery of IPs using instance metadata endpoints (AWS)
- Multi-tunnel mode for throughput beyond the single NIC queue limit (`--tunnels N`)
- WireGuard interfaces tuned with GSO/GRO offload, multi-queue, and optimized MTU/MSS
- Connection tracking bypass (NOTRACK) for reduced CPU overhead on WireGuard UDP flows
- TCP MSS clamping to prevent fragmentation inside the tunnel
- Control traffic is encrypted with TLS (Warning: does not verify server certificate)
- Only one vprox server may be running on a host

## How it works

### Control plane

The server listens on port 443 (HTTPS) for control traffic. Clients send a `/connect` request with their WireGuard public key. The server allocates a peer IP from the WireGuard subnet, adds the client as a peer on all tunnel interfaces, and returns the assigned address along with a list of tunnel endpoints (listen ports).

### Data plane

WireGuard handles the data plane. Each tunnel interface encrypts/decrypts traffic independently. The server applies iptables rules for:

- **SNAT (masquerade)**: Outbound traffic from WireGuard peers is source-NAT'd to the server's bind address.
- **Firewall marks**: Traffic from WireGuard interfaces is marked for routing policy.
- **MSS clamping**: TCP SYN packets are clamped to fit within the WireGuard MTU (1380 bytes).
- **NOTRACK**: WireGuard UDP flows bypass connection tracking to reduce per-packet CPU overhead.

### Multi-tunnel routing

In multi-tunnel mode, both server and client use Linux policy routing to distribute traffic:

- A custom routing table (51820) contains multipath routes across all tunnel interfaces.
- An `ip rule` directs matching traffic to this table.
- On the client, the rule matches traffic sourced from the WireGuard IP (set by the dummy `vprox0` device).
- On the server, the rule matches traffic destined for the WireGuard subnet (forwarded download traffic).
- The kernel's L4 multipath hash (`fib_multipath_hash_policy=1`) distributes different flows to different tunnels.

### Interface tuning

WireGuard interfaces are created with performance-optimized settings:

- **MTU 1420**: Prevents fragmentation on standard 1500 MTU networks (WireGuard adds ~60 bytes overhead).
- **GSO/GRO 65536**: Enables Generic Segmentation/Receive Offload, allowing the kernel to batch packets into 64 KB super-packets before encryption (Linux 5.19+).
- **4 TX/RX queues**: Enables parallel packet processing across multiple CPU cores.
- **TxQLen 1000**: Reduces packet drops during traffic bursts.

## Authors

This library is created by the team behind [Modal](https://modal.com/).

- Eric Zhang ([@ekzhang1](https://twitter.com/ekzhang1)) – [Modal](https://modal.com/)
- Luis Capelo ([@luiscape](https://twitter.com/luiscape)) – [Modal](https://modal.com/)
- Jeffrey Meng – [Modal](https://modal.com/)
