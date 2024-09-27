# vprox

**WARNING:** This is unfinished.

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

To set up `vprox`, you'll need the private IPv4 address of the server connected to an Internet gateway (use the `ip addr` command), as well as a block of IPs to allocate to the WireGuard subnet between server and client. This has no particular meaning and can be arbitrarily chosen to not overlap with other subnets.

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

## Authors

This library is created by the team behind [Modal](https://modal.com/).

- Eric Zhang ([@ekzhang1](https://twitter.com/ekzhang1)) – [Modal](https://modal.com/)
- Jeffrey Meng – [Modal](https://modal.com/)
