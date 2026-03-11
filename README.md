# vprox

vprox is a high-performance network proxy acting as a split tunnel VPN. The server accepts peering requests from clients, which then establish WireGuard tunnels that direct all traffic on the client's network interface through the server, with IP masquerading.

Both the client and server commands need root access. The server can have multiple public IP addresses attached, and on cloud providers, it automatically uses the instance metadata endpoint to discover its public IP addresses and start one proxy for each.

This property allows the server to be high-availability. In the event of a restart or network partition, the tunnels remain open. If the server's IP address is attached to a new host, clients will automatically re-establish connections. This means that IP addresses can be moved to different hosts in event of an outage.

## Usage

On the Linux VPN server and client, install system requirements (`iptables` and `wireguard`).

```bash
# On Ubuntu
sudo apt install iptables wireguard

# On Fedora
sudo dnf install iptables wireguard-tools
```

Also, you need to set some kernel settings with Sysctl. Enable IPv4 forwarding, and make sure that [`rp_filter`](https://sysctl-explorer.net/net/ipv4/rp_filter/) is set to 2, or masqueraded packets may be filtered out. You can edit your OS configuration file to set this persistently, or set it once below.

```bash
# Applies until next reboot
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=2
```

### Performance Tuning (Optional)

For maximum throughput, especially on high-bandwidth servers with many peers, apply these additional sysctl settings. Create a file `/etc/sysctl.d/99-vprox-performance.conf` or apply them temporarily:

```bash
# UDP/Socket Buffer Sizes (WireGuard uses UDP)
# Increase max buffer sizes to 25MB for high-throughput scenarios
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
sudo sysctl -w net.core.rmem_default=1048576
sudo sysctl -w net.core.wmem_default=1048576

# Network device backlog (for high packet rates)
# Increase backlog to handle traffic bursts
sudo sysctl -w net.core.netdev_max_backlog=50000
sudo sysctl -w net.core.netdev_budget=600

# TCP tuning (for traffic inside the tunnel)
# Format: min default max
sudo sysctl -w net.ipv4.tcp_rmem="4096 1048576 26214400"
sudo sysctl -w net.ipv4.tcp_wmem="4096 1048576 26214400"

# Use BBR congestion control (better than cubic for most scenarios)
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

# Enable TCP Fast Open for reduced latency on reconnects
sudo sysctl -w net.ipv4.tcp_fastopen=3

# Connection tracking limits (critical for NAT with many peers)
# Increase max tracked connections to 1M
sudo sysctl -w net.netfilter.nf_conntrack_max=1048576

# Optional: Busy polling for lower latency (increases CPU usage)
# sudo sysctl -w net.core.busy_poll=50
# sudo sysctl -w net.core.busy_read=50
```

To make these settings persistent across reboots, add them to `/etc/sysctl.d/99-vprox-performance.conf` without the `sudo sysctl -w` prefix:

```
# /etc/sysctl.d/99-vprox-performance.conf
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.core.rmem_default=1048576
net.core.wmem_default=1048576
net.core.netdev_max_backlog=50000
net.core.netdev_budget=600
net.ipv4.tcp_rmem=4096 1048576 26214400
net.ipv4.tcp_wmem=4096 1048576 26214400
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.netfilter.nf_conntrack_max=1048576
```

Then apply with `sudo sysctl --system`.

To set up `vprox`, you'll need the private IPv4 address of the server connected to an Internet gateway (use the `ip addr` command), as well as a block of IPs to allocate to the WireGuard subnet between server and client. This has no particular meaning and can be arbitrarily chosen to not overlap with other subnets.

#### Password Authentication (default)

The default authentication mode uses a shared password via the `VPROX_PASSWORD` environment variable:

```bash
# [Machine A: public IP 1.2.3.4, private IP 172.31.64.125]
VPROX_PASSWORD=my-password vprox server --ip 172.31.64.125 --wg-block 240.1.0.0/16

# [Machine B: public IP 5.6.7.8]
VPROX_PASSWORD=my-password vprox connect 1.2.3.4 --interface vprox0
curl ifconfig.me                     # => 5.6.7.8
curl --interface vprox0 ifconfig.me  # => 1.2.3.4
```

#### OIDC Authentication (Modal)

vprox supports OIDC token-based authentication, designed for use with [Modal's OIDC integration](https://modal.com/docs/guide/oidc-integration). In this mode, the server verifies JWT identity tokens signed by Modal (or any OIDC-compliant issuer) instead of using a shared password.

Modal automatically injects a short-lived OIDC identity token into every container via the `MODAL_IDENTITY_TOKEN` environment variable. The vprox server fetches the issuer's JWKS (JSON Web Key Set) to cryptographically verify token signatures and validate claims like workspace ID, environment, and expiration.

**Server setup:**

```bash
# Start the server in OIDC mode, restricting access to a specific Modal workspace
VPROX_AUTH_MODE=oidc \
VPROX_OIDC_ISSUER=https://oidc.modal.com \
VPROX_OIDC_ALLOWED_WORKSPACE_IDS=ws-abc123 \
  vprox server --ip 172.31.64.125 --wg-block 240.1.0.0/16
```

**Client setup (inside a Modal container):**

```bash
# The MODAL_IDENTITY_TOKEN env var is set automatically by Modal
VPROX_AUTH_MODE=oidc vprox connect 1.2.3.4 --interface vprox0
```

**OIDC environment variables:**

| Variable | Description | Default |
|---|---|---|
| `VPROX_AUTH_MODE` | Auth mode: `password` or `oidc` | `password` |
| `VPROX_OIDC_ISSUER` | OIDC issuer URL | `https://oidc.modal.com` |
| `VPROX_OIDC_AUDIENCE` | Expected `aud` claim (skip check if empty) | _(empty)_ |
| `VPROX_OIDC_ALLOWED_WORKSPACE_IDS` | Comma-separated list of allowed Modal workspace IDs | _(any)_ |
| `VPROX_OIDC_ALLOWED_ENVIRONMENTS` | Comma-separated list of allowed Modal environment names | _(any)_ |
| `MODAL_IDENTITY_TOKEN` | OIDC token (set automatically by Modal in containers) | — |

Note that Machine B must be able to send UDP packets to port 50227 on Machine A, and TCP to port 443.

All outbound network traffic seen by `vprox0` will automatically be forwarded through the WireGuard tunnel. The VPN server masquerades the source IP address.

### Building

To build `vprox`, run the following command with Go 1.22+ installed:

```bash
CGO_ENABLED=0 go build
```

This produces a static binary in `./vprox`.

### Multiple private IPs

On cloud providers like AWS, you can attach [secondary private IP addresses](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/MultipleIP.html) to an interface and associate each of them with a global IPv4 unicast address.

A `vprox` server listening on multiple IP addresses needs to provide `--ip` option once for every IP, and each IP requires its its own WireGuard VPN subnet with a non-overlapping address range. You can pass `--wg-block-per-ip /22` to split the `--wg-block` into smaller blocks for each IP.

On AWS in particular, the `--cloud aws` option allows you to automatically discover the private IP addresses of the server by periodically querying the instance metadata endpoint.

## Features

- Works on Linux 5.15+ with WireGuard installed
- Supports forwarding IPv4 packets
- Works if the server has multiple IPs, specified with `--wg-block-per-ip`
- Automatic discovery of IPs using instance metadata endpoints (AWS)
- Only one vprox server may be running on a host
- Control traffic is encrypted with TLS (Warning: does not verify server certificate)
- Optimized for throughput with automatic MTU, MSS, GSO/GRO, and multi-queue configuration
- Connection tracking bypass (NOTRACK) for reduced CPU overhead on WireGuard UDP flows
- OIDC authentication for passwordless auth from Modal containers (or any OIDC provider)

## Authors

This library is created by the team behind [Modal](https://modal.com/).

- Eric Zhang ([@ekzhang1](https://twitter.com/ekzhang1)) – [Modal](https://modal.com/)
- Luis Capelo ([@luiscape](https://twitter.com/luiscape)) – [Modal](https://modal.com/)
- Jeffrey Meng – [Modal](https://modal.com/)
