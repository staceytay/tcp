use libc::{
    c_short, c_uchar, close, ioctl, open, read, write, IFF_NO_PI, IFF_TUN, IFNAMSIZ, O_RDWR,
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::packet::Packet;
use rand::{thread_rng, Rng};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    num::Wrapping,
    os::unix::io::RawFd,
    rc::Rc,
};

const IPV4_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const MTU: usize = 1500;

#[derive(Debug)]
struct ReceiveSequence {
    next: Wrapping<u32>,
    window: u16,
    // irs: u32,
}

#[derive(Debug)]
struct SendSequence {
    unacknowledged: Wrapping<u32>,
    next: Wrapping<u32>,
    window: u16,
    // iss: u32,
}

pub struct Closed;
pub struct Established {
    receive: ReceiveSequence,
    send: SendSequence,
    source: u16,
}

pub struct TcpStream<State = Closed> {
    socket_addr_v4: SocketAddrV4,
    state: State,
    tun: Rc<TunSocket>,
}

impl<T> TcpStream<T> {
    pub fn peer_addr(&self) -> io::Result<SocketAddrV4> {
        Ok(self.socket_addr_v4)
    }

    // We assume that the `packet` slice here is the entire ipv4 packet, i.e.
    // `packet.len()` is the ipv4 packet's total length.
    fn prepare_ipv4_packet(&self, packet: &mut [u8]) -> () {
        // TODO: Check buf size here
        let packet_length = packet.len();
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(IPV4_SOURCE);
        ip_header.set_destination(*self.socket_addr_v4.ip());
        ip_header.set_identification(1);
        ip_header.set_header_length(5);
        ip_header.set_version(4);
        ip_header.set_ttl(64);

        ip_header.set_total_length(packet_length as u16);
        ip_header.set_checksum(checksum(&ip_header.to_immutable()));
    }
}

impl TcpStream<Closed> {
    pub fn connect<T: ToSocketAddrs>(addr: T) -> io::Result<TcpStream<Established>> {
        let socket_addr = addr.to_socket_addrs().unwrap().collect::<Vec<_>>()[0];

        match socket_addr {
            SocketAddr::V4(socket_addr_v4) => {
                let tun = Rc::new(TunSocket::new("tun0")?);

                let mut tcp_stream = TcpStream {
                    socket_addr_v4,
                    state: Closed,
                    tun,
                }
                .open_tcp_connection()
                .unwrap();

                Ok(tcp_stream)
            }
            _ => panic!("TcpStream::connect: Ipv6 unsupported"),
        }
    }

    fn open_tcp_connection(&self) -> Result<TcpStream<Established>, &'static str> {
        const IPV4_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;
        const TCP_MSS_OPTION_LEN: usize = 4;

        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_MSS_OPTION_LEN];

        let ipv4_destination = self.socket_addr_v4.ip();
        let tcp_destination = self.socket_addr_v4.port();
        let mut rng = thread_rng();
        let initial_seq = Wrapping(rng.gen());
        let tcp_source = rng.gen_range(49152..=65535);

        // TODO: Use builder pattern to reduce duplication of set methods
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_source(tcp_source);
        tcp_header.set_destination(tcp_destination);
        tcp_header.set_window(65535);

        tcp_header.set_sequence(initial_seq.0);
        tcp_header.set_acknowledgement(0);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_data_offset(((TCP_HEADER_LEN + TCP_MSS_OPTION_LEN) / 4) as u8);
        tcp_header.set_options(&vec![TcpOption::mss(1460)]);
        tcp_header.set_checksum(ipv4_checksum(
            &tcp_header.to_immutable(),
            &IPV4_SOURCE,
            ipv4_destination,
        ));

        self.prepare_ipv4_packet(&mut packet[..]);

        let size = self.tun.write(&packet).unwrap();

        println!("");
        // Technically we're in the SYN-SENT state here.

        let mut buf = [0; MTU];

        let packet = self.tun.read(&mut buf).unwrap();
        println!("response: packet len = {}", packet.len());
        // println!("packet: {:?}", packet);
        let response = Ipv4Packet::new(&packet).unwrap();
        // println!("IP RESPONSE: {:?}", response);
        let tcp_response = TcpPacket::new(response.payload()).unwrap();
        println!("SYN ACK TCP RESPONSE: {:?}", tcp_response);

        // TODO: Verify checksum and check if response packet is a SYN ACK.
        // Send ACK back to server.

        let mut send = SendSequence {
            unacknowledged: Wrapping(0u32),
            next: initial_seq + Wrapping(1u32),
            window: 65535,
        };

        let receive = ReceiveSequence {
            next: Wrapping(tcp_response.get_sequence()) + Wrapping(1u32),
            window: tcp_response.get_window(),
        };

        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_source(tcp_source);
        tcp_header.set_destination(tcp_destination);
        tcp_header.set_sequence(send.next.0);
        tcp_header.set_acknowledgement(receive.next.0);
        tcp_header.set_flags(TcpFlags::ACK);
        tcp_header.set_window(65535);
        tcp_header.set_data_offset((TCP_HEADER_LEN / 4) as u8);

        println!("ACK TCP ACK REPLY FROM US: {:?}", tcp_header);

        let checksum_val =
            ipv4_checksum(&tcp_header.to_immutable(), &IPV4_SOURCE, &ipv4_destination);
        tcp_header.set_checksum(checksum_val);

        self.prepare_ipv4_packet(&mut packet[..]);

        let size = self.tun.write(&packet).unwrap();
        println!("Size: {size}");

        Ok(TcpStream {
            socket_addr_v4: self.socket_addr_v4,
            state: Established {
                receive,
                send,
                source: tcp_source,
            },
            tun: Rc::clone(&self.tun),
        })
    }
}

impl TcpStream<Established> {
    fn close(&mut self) -> Result<(), &'static str> {
        println!("TcpStream<Established>: close");

        const IPV4_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;

        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];

        let ipv4_destination = self.socket_addr_v4.ip();
        let tcp_destination = self.socket_addr_v4.port();

        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_source(self.state.source);
        tcp_header.set_destination(tcp_destination);
        tcp_header.set_sequence(self.state.send.next.0);
        self.state.send.next = self.state.send.next + Wrapping(1u32);
        tcp_header.set_acknowledgement(self.state.receive.next.0);
        tcp_header.set_flags(TcpFlags::FIN | TcpFlags::ACK);
        tcp_header.set_window(65535);
        tcp_header.set_data_offset((TCP_HEADER_LEN / 4) as u8);

        let checksum_val =
            ipv4_checksum(&tcp_header.to_immutable(), &IPV4_SOURCE, ipv4_destination);
        tcp_header.set_checksum(checksum_val);

        self.prepare_ipv4_packet(&mut packet[..]);

        let size = self.tun.write(&packet).unwrap();

        // Technically we're in the LAST-ACK state here.
        // Expecting an ACK from the remote server.

        let mut buf = [0; MTU];

        let packet = self.tun.read(&mut buf).unwrap();
        println!("response: packet len = {}", packet.len());
        // println!("packet: {:?}", packet);
        let response = Ipv4Packet::new(&packet).unwrap();
        // println!("IP RESPONSE: {:?}", response);
        let tcp_response = TcpPacket::new(response.payload()).unwrap();
        println!(
            "TcpStream<Established>: close: TCP RESPONSE 1: {:?}",
            tcp_response
        );

        Ok(())
    }

    fn reset(&mut self) -> Result<(), &'static str> {
        const IPV4_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;

        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];

        let ipv4_destination = self.socket_addr_v4.ip();
        let tcp_destination = self.socket_addr_v4.port();

        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_source(self.state.source);
        tcp_header.set_destination(tcp_destination);
        tcp_header.set_sequence(self.state.send.next.0);
        self.state.send.next = self.state.send.next + Wrapping(1u32);
        tcp_header.set_acknowledgement(self.state.receive.next.0);
        tcp_header.set_flags(TcpFlags::RST);
        tcp_header.set_window(65535);
        tcp_header.set_data_offset((TCP_HEADER_LEN / 4) as u8);

        let checksum_val =
            ipv4_checksum(&tcp_header.to_immutable(), &IPV4_SOURCE, ipv4_destination);
        tcp_header.set_checksum(checksum_val);

        self.prepare_ipv4_packet(&mut packet[..]);

        println!("reset: TunSocket = {:?}", self.tun);

        let size = self.tun.write(&packet).unwrap();

        Ok(())
    }
}

impl io::Read for TcpStream<Established> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        println!("TcpStream: read: start");

        // TODO: check and break once tcp_data_read >= buf.len()
        let mut tcp_data_read = 0;

        loop {
            let mut read_buf = [0u8; MTU];
            // TODO: use something like epoll to see if it's worth reading,
            // otherwise skip, and can assume no more data to pass in after a
            // certain time and return. We shouldn't close the connection here
            // though, will probably need to use Drop for that?
            let packet = self.tun.read(&mut read_buf).unwrap();
            let response = Ipv4Packet::new(&packet).unwrap();
            let tcp_response = TcpPacket::new(response.payload()).unwrap();

            // TODO: Verify checksum of packets above ^

            if tcp_response.get_flags() & TcpFlags::FIN == TcpFlags::FIN {
                // We're in the CLOSE-WAIT state here.
                // Increment for FIN packet received.
                self.state.receive.next += 1;
                self.close();
                break;
            }

            // TODO: Check that received packet is within receive window
            // TODO: Check order of received packet
            // TODO: Implement delayed ACK? See "4.2.3.2  When to Send an ACK Segment" in rfc1122
            let tcp_data = tcp_response.payload();
            if tcp_data.len() > 0 {
                println!("tcp_data_read = {}", tcp_data_read);
                println!(
                    "TCP DATA RECEIVED: LEN = {}, {}...",
                    tcp_data.len(),
                    &(std::str::from_utf8(tcp_data).unwrap())[..std::cmp::min(tcp_data.len(), 24)]
                );
                // TODO: check that end is still within buf.len()
                buf[tcp_data_read..tcp_data_read + tcp_data.len()].clone_from_slice(tcp_data);
                tcp_data_read += tcp_data.len();

                //  send ack packet
                const IPV4_HEADER_LEN: usize = 20;
                const TCP_HEADER_LEN: usize = 20;

                let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];

                let ipv4_destination = self.socket_addr_v4.ip();
                let tcp_destination = self.socket_addr_v4.port();

                let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
                tcp_header.set_source(self.state.source);
                tcp_header.set_destination(tcp_destination);
                tcp_header.set_sequence(self.state.send.next.0);
                self.state.receive.next += Wrapping(tcp_data.len() as u32);
                tcp_header.set_acknowledgement(self.state.receive.next.0);
                tcp_header.set_flags(TcpFlags::ACK);
                tcp_header.set_window(65535);
                tcp_header.set_data_offset((TCP_HEADER_LEN / 4) as u8);

                let checksum_val =
                    ipv4_checksum(&tcp_header.to_immutable(), &IPV4_SOURCE, ipv4_destination);
                tcp_header.set_checksum(checksum_val);

                self.prepare_ipv4_packet(&mut packet[..]);

                let size = self.tun.write(&packet).unwrap();
            }
        }

        Ok(42)
    }
}

impl io::Write for TcpStream<Established> {
    fn flush(&mut self) -> io::Result<()> {
        println!("TcpStream: flush: start");
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        println!("TcpStream: write: start");

        const IPV4_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;
        for segment in buf.chunks(MTU - TCP_HEADER_LEN - IPV4_HEADER_LEN) {
            println!("TcpStream: write: segment length = {}", segment.len());
            println!(
                "TcpStream: write: segment contents = {}",
                std::str::from_utf8(segment).unwrap()
            );

            let mut packet = [0u8; MTU];
            let packet_length = IPV4_HEADER_LEN + TCP_HEADER_LEN + segment.len();

            let ipv4_destination = self.socket_addr_v4.ip();
            let tcp_destination = self.socket_addr_v4.port();

            let mut tcp_header =
                MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..packet_length]).unwrap();
            tcp_header.set_source(self.state.source);
            tcp_header.set_destination(tcp_destination);
            tcp_header.set_sequence(self.state.send.next.0);
            self.state.send.next = self.state.send.next + Wrapping(segment.len() as u32);
            tcp_header.set_acknowledgement(self.state.receive.next.0);
            tcp_header.set_flags(TcpFlags::PSH | TcpFlags::ACK);
            tcp_header.set_window(65535);
            tcp_header.set_data_offset((TCP_HEADER_LEN / 4) as u8);

            tcp_header.set_payload(segment);

            let checksum_val =
                ipv4_checksum(&tcp_header.to_immutable(), &IPV4_SOURCE, ipv4_destination);
            tcp_header.set_checksum(checksum_val);

            self.prepare_ipv4_packet(&mut packet[..packet_length]);

            let size = self.tun.write(&packet[..packet_length]).unwrap();
        }

        Ok(42)
    }
}

// impl<T> Drop for TcpStream<T> {
//     fn drop(&mut self) {}
// }
// impl Drop for TcpStream<Established> {
//     fn drop(&mut self) {
//         // Implementation here.
//     }
// }

#[derive(Clone, Debug)]
struct TunSocket {
    fd: RawFd,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

#[repr(C)]
union IfrIfru {
    ifru_flags: c_short,
}

#[repr(C)]
pub struct ifreq {
    ifr_name: [c_uchar; IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

impl TunSocket {
    const TUNSETIFF: u64 = 0x400454CA;

    fn new(name: &str) -> Result<TunSocket, io::Error> {
        let fd = match unsafe { open(b"/dev/net/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => return Err(io::Error::last_os_error()),
            fd => fd,
        };

        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru {
                ifru_flags: (IFF_TUN | IFF_NO_PI) as _,
            },
        };

        let iface_name = name.as_bytes();
        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, Self::TUNSETIFF as _, &ifr) } < 0 {
            println!("ioctl error");
            return Err(io::Error::last_os_error());
        }

        Ok(TunSocket { fd })
    }

    fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], io::Error> {
        match unsafe { read(self.fd, dst.as_mut_ptr() as *mut _, dst.len()) } {
            -1 => Err(io::Error::last_os_error()),
            n => Ok(&mut dst[..n as usize]),
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, io::Error> {
        match unsafe { write(self.fd, buf.as_ptr() as *const _, buf.len()) } {
            -1 => Err(io::Error::last_os_error()),
            n => Ok(n as usize),
        }
    }
}
