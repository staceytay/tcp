extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::ipv4_checksum;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpOption;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use std::net::Ipv4Addr;

use std::env;
use std::net::IpAddr;

// use tcp::get_tcp_packet;

// Invoke as echo <interface name>
fn main() {
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    println!("Interfaces: {:?}", interfaces);
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));

    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, _) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 32;
    const TEST_DATA_LEN: usize = 4;

    let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TEST_DATA_LEN];

    // let ipv4_source = Ipv4Addr::new(127, 0, 0, 1);
    let ipv4_source = Ipv4Addr::new(192, 168, 0, 84);
    // Supposed to be example.com
    let ipv4_destination = Ipv4Addr::new(93, 184, 216, 34);

    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
    }

    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN] = 't' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 1] = 'e' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 2] = 's' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 3] = 't' as u8;

    let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
    // tcp_header.set_source(rx.socket.clone());
    tcp_header.set_source(60001);

    tcp_header.set_destination(80);

    // TODO: What is sequence?
    tcp_header.set_sequence(0x0);

    tcp_header.set_acknowledgement(0x0);

    tcp_header.set_flags(TcpFlags::SYN);

    tcp_header.set_window(65535);

    tcp_header.set_data_offset(8);

    let ts = TcpOption::timestamp(743951781, 44056978);
    tcp_header.set_options(&vec![TcpOption::nop(), TcpOption::nop(), ts]);

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &ipv4_source, &ipv4_destination);
    tcp_header.set_checksum(checksum);

    let _ = tx.send_to(tcp_header, std::net::IpAddr::V4(ipv4_destination));

    loop {
        match rx.next() {
            Ok(packet) => {
                // let ethernet_packet = EthernetPacket::new(packet).unwrap();

                // println!(
                //     "ethernet_packet: len = {}, {} -> {}",
                //     packet.len(),
                //     ethernet_packet.get_source(),
                //     ethernet_packet.get_destination()
                // );

                // let interface_name = &interface.name[..];
                // match ethernet_packet.get_ethertype() {
                //     EtherTypes::Ipv4 => {
                //         let header = Ipv4Packet::new(ethernet_packet.payload());
                //         if let Some(header) = header {
                //             match header.get_next_level_protocol() {
                //                 IpNextHeaderProtocols::Tcp => {
                //                     let tcp = TcpPacket::new(packet);
                //                     if let Some(tcp) = tcp {
                //                         println!(
                //                             "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                //                             interface_name,
                //                             IpAddr::V4(header.get_source()),
                //                             tcp.get_source(),
                //                             IpAddr::V4(header.get_destination()),
                //                             tcp.get_destination(),
                //                             packet.len()
                //                         );
                //                         println!(
                //                             "[{}]: TCP Packet: {}",
                //                             interface_name,
                //                             show(tcp.payload())
                //                         );
                //                     } else {
                //                         println!("[{}]: Malformed TCP Packet", interface_name);
                //                     }
                //                 }
                //                 _ => println!(
                //                     "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                //                     interface_name,
                //                     match IpAddr::V4(header.get_source()) {
                //                         IpAddr::V4(..) => "IPv4",
                //                         _ => "IPv6",
                //                     },
                //                     IpAddr::V4(header.get_source()),
                //                     IpAddr::V4(header.get_destination()),
                //                     header.get_next_level_protocol(),
                //                     packet.len()
                //                 ),
                //             }
                //         } else {
                //             println!("[{}]: Malformed IPv4 Packet", interface_name);
                //         }
                //     }
                //     _ => println!(
                //         "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                //         interface_name,
                //         ethernet_packet.get_source(),
                //         ethernet_packet.get_destination(),
                //         ethernet_packet.get_ethertype(),
                //         ethernet_packet.packet().len()
                //     ),
                // }

                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                match ethernet_packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let header = Ipv4Packet::new(ethernet_packet.payload());
                        if let Some(header) = header {
                            match header.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp) = TcpPacket::new(header.payload()) {
                                        if tcp.get_source() == 80 || tcp.get_destination() == 80 {
                                            println!(
                                                "[{}]: Ethernet: {} > {}",
                                                interface_name,
                                                ethernet_packet.get_source(),
                                                ethernet_packet.get_destination(),
                                            );
                                            println!(
                                                "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                                                interface_name,
                                                header.get_source(),
                                                tcp.get_source(),
                                                header.get_destination(),
                                                tcp.get_destination(),
                                                packet.len()
                                            );
                                            println!("FLAGS: {:#010b}", tcp.get_flags());
                                            println!("CONTENTS: {}", show(tcp.payload()));
                                            println!("-----");
                                        }
                                    }
                                }
                                _ => (),
                            }
                        } else {
                            panic!("Malformed IPv4 packet");
                        }
                    }
                    _ => (),
                }

                // Constructs a single packet, the same length as the the one received,
                // using the provided closure. This allows the packet to be constructed
                // directly in the write buffer, without copying. If copying is not a
                // problem, you could also use send_to.
                //
                // The packet is sent once the closure has finished executing.
                // tx.build_and_send(1, packet.packet().len(), &mut |mut new_packet| {
                //     let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

                //     // Create a clone of the original packet
                //     new_packet.clone_from(&packet);

                //     // Switch the source and destination
                //     new_packet.set_source(packet.get_destination());
                //     new_packet.set_destination(packet.get_source());
                // });
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

use std::ascii::escape_default;
use std::str;

fn show(bs: &[u8]) -> String {
    let mut visible = String::new();
    for &b in bs {
        let part: Vec<u8> = escape_default(b).collect();
        visible.push_str(str::from_utf8(&part).unwrap());
    }
    visible
}
