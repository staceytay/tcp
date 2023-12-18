# A simple TCP implementation in Rust

An attempt to learn Rust and TCP while at the Recurse Center. I also wrote about
the experience of working on this [here](https://stace.dev/rc-05-tcp-in-rust/).


## Design overview

API modeled after Rust's `TcpStream` with `read` and `write` functions exposed
to clients. I also used the [typestate
pattern](https://stace.dev/rc-04-typechecking-tcp-states-in-rust/) to model the
different TCP states.

## Things implemented

- Three-way handshake, sending and reading of packets, closing of TCP connection.
- Verification of received packet's checksum and sequence numbers.
- Waiting for ACK from remote host for packets sent.

## Things not implemented (yet?)

TODO

## Setup

### Dependencies

This implementation was tested on a Linux VM and requires Linux to run.

```bash
# set up `tun0`
sudo ip link del tun0
sudo ip tuntap add name tun0 mode tun user $USER
sudo ip link set tun0 up
sudo ip addr add 192.0.2.1 peer 192.0.2.2 dev tun0

# set up NAT
sudo iptables -t nat -A POSTROUTING -s 192.0.2.2 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -s 192.0.2.2 -j ACCEPT
sudo iptables -A FORWARD -o tun0 -d 192.0.2.2 -j ACCEPT
sudo sysctl -w net.ipv4.ip_forward=1
```

Taken from [How to send raw network packets in Python with
tun/tap](https://jvns.ca/blog/2022/09/06/send-network-packets-python-tun-tap/).

## Examples

```bash
$ cargo run --example http-get http://example.com
```

## Credits and resources

- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/html/)
- [How to send raw network packets in Python with tun/tap](https://jvns.ca/blog/2022/09/06/send-network-packets-python-tun-tap/)
- Julia Evans' Implementing TCP in a Weekend (beta)
- [RFC1122: Requirements for Internet Hosts -- Communication Layers](https://datatracker.ietf.org/doc/html/rfc1122#autoid-4)
- [RFC2581: TCP Congestion Control](https://datatracker.ietf.org/doc/html/rfc2581)
- [RFC6056: Recommendations for Transport-Protocol Port Randomization](https://datatracker.ietf.org/doc/html/rfc6056)
- [RFC6335: Internet Assigned Numbers Authority (IANA) Procedures for the Management of the Service Name and Transport Protocol Port Number Registry](https://datatracker.ietf.org/doc/html/rfc6335#autoid-8) 
- [Rust for Rustaceans](https://rust-for-rustaceans.com/), specifically Chapter 3 for introducing the typestate pattern.
- https://crates.io/crates/smoltcp
- https://github.com/WireGuard/wireguard-rs
- https://github.com/cloudflare/boringtun
- https://github.com/meh/rust-tun
