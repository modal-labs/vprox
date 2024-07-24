# vprox

**WARNING:** This is unfinished.

vprox is a high-performance network proxy acting as a VPN server. The server accepts peering requests from clients, which then establish WireGuard tunnels that direct all traffic on the client's network interface through the server, with IP masquerading.

Both the client and server commands need root access. The server can have multiple public IP addresses attached, and on cloud providers, it automatically uses the instance metadata endpoint to discover its public IP addresses and start one proxy for each.

This property allows the server to be high-availability. In the event of a restart or network partition, the tunnels remain open. If the server's IP address is attached to a new host, clients will automatically re-establish connections. This means that IP addresses can be moved to different hosts in event of an outage.

## Usage

By default, `vprox` uses the `fd30:efe7:e682:cf06::/64` subnet for WireGuard tunnels. This subnet has no particular meaning and was randomly chosen. Each network interface and peer gets a random IP address from this subnet, and the risk of collision is low.

```bash
# [Machine A: 1.2.3.4]
# Note: Make sure you're running as root
VPROX_PASSWORD=my-password vprox server

# [Machine B: 5.6.7.8]
VPROX_PASSWORD=my-password vprox connect 1.2.3.4 --interface vprox0
curl ifconfig.me                     # => 5.6.7.8
curl --interface vprox0 ifconfig.me  # => 1.2.3.4
```

Note that Machine B must have UDP connectivity to port 51820 on Machine A.

All outbound network traffic seen by `vprox0` will automatically be forwarded through the WireGuard tunnel. The VPN server masquerades the source IP address.

## Features

- Works on Linux 5.15+ with WireGuard installed
- Supports forwarding both IPv4 and IPv6 packets

## Authors

This library is created by the team behind [Modal](https://modal.com/).

- Eric Zhang ([@ekzhang1](https://twitter.com/ekzhang1)) – [Modal](https://modal.com/)
