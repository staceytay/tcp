use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::{MutablePacket, Packet};

use std::net::IpAddr;

// pub fn get_tcp_packet(packet: &EthernetPacket) -> Option<TcpPacket> {
// pub fn get_tcp_packet<'a>(packet: &'a EthernetPacket<'a>) -> Option<TcpPacket<'a>> {
//     match packet.get_ethertype() {
//         EtherTypes::Ipv4 => {
//             let header = Ipv4Packet::new(packet.payload());
//             if let Some(header) = header {
//                 match header.get_next_level_protocol() {
//                     IpNextHeaderProtocols::Tcp => {
//                         return TcpPacket::new(header.payload());
//                     }
//                     _ => None,
//                 }
//             } else {
//                 panic!("Malformed IPv4 packet");
//             }
//         }
//         _ => None,
//     }
// }

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
