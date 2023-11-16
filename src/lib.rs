use libc::{
    c_short, c_uchar, close, ioctl, open, read, write, IFF_NO_PI, IFF_TUN, IFNAMSIZ, O_RDWR,
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::packet::Packet;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    os::unix::io::RawFd,
    rc::Rc,
};

const IPV4_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const MTU: usize = 1500;

#[derive(Debug)]
struct ReceiveSequence {
    next: u32,
    window: u16,
    // irs: u32,
}

#[derive(Debug)]
struct SendSequence {
    unacknowledged: u32,
    next: u32,
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
    // state: std::marker::PhantomData<State>,
    state: State,
    tun: Rc<TunSocket>,
}

impl<T> TcpStream<T> {
    pub fn peer_addr(&self) -> io::Result<SocketAddrV4> {
        Ok(self.socket_addr_v4)
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

                tcp_stream.reset();

                Ok(tcp_stream)
            }
            _ => panic!("TcpStream::connect: Ipv6 unsupported"),
        }
    }

    fn open_tcp_connection(&self) -> Result<TcpStream<Established>, &'static str> {
        const IPV4_HEADER_LEN: usize = 20;
        const TCP_SYN_HEADER_LEN: usize = 24;

        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_SYN_HEADER_LEN];

        let ipv4_destination = self.socket_addr_v4.ip();
        let initial_seq = 30; // TODO: Randomize sequence number generation

        // TODO: Use builder pattern to reduce duplication of set methods
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        // TODO: use a random source port?
        tcp_header.set_source(12345);
        tcp_header.set_destination(80);
        // TODO: What is sequence?
        tcp_header.set_sequence(initial_seq);
        tcp_header.set_acknowledgement(0);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(65535);
        tcp_header.set_data_offset((TCP_SYN_HEADER_LEN / 4) as u8);

        tcp_header.set_options(&vec![TcpOption::mss(1460)]);

        println!("SYN TCP HEADER: {:?}", tcp_header);

        let checksum_val =
            ipv4_checksum(&tcp_header.to_immutable(), &IPV4_SOURCE, ipv4_destination);
        tcp_header.set_checksum(checksum_val);

        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(IPV4_SOURCE);
        ip_header.set_destination(*ipv4_destination);
        ip_header.set_identification(1);
        ip_header.set_header_length(5);
        ip_header.set_version(4);
        ip_header.set_ttl(64);
        ip_header.set_total_length((IPV4_HEADER_LEN + TCP_SYN_HEADER_LEN) as u16);

        ip_header.set_checksum(checksum(&ip_header.to_immutable()));

        let size = self.tun.write(&packet).unwrap();

        println!("");
        // Technically we're in the SYN-SENT state here.

        let mut buf = [0; MTU];

        let packet = self.tun.read(&mut buf).unwrap();
        println!("response: packet len = {}", packet.len(),);
        // println!("packet: {:?}", packet);
        let response = Ipv4Packet::new(&packet).unwrap();
        // println!("IP RESPONSE: {:?}", response);
        let tcp_response = TcpPacket::new(response.payload()).unwrap();
        println!("SYN ACK TCP RESPONSE: {:?}", tcp_response);

        // TODO: Check if response packet is a SYN ACK.
        // Send ACK back to server.

        let mut send = SendSequence {
            unacknowledged: 0,
            next: initial_seq + 1,
            window: 65535,
        };

        let receive = ReceiveSequence {
            next: tcp_response.get_sequence() + 1,
            window: tcp_response.get_window(),
        };

        const TCP_HEADER_LEN: usize = 20;
        let mut packet = [0u8; 1500];
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_source(12345);
        tcp_header.set_destination(80);
        // TODO: What is sequence?
        tcp_header.set_sequence(send.next);
        send.next = send.next + 1;
        tcp_header.set_acknowledgement(receive.next);
        tcp_header.set_flags(TcpFlags::ACK);
        tcp_header.set_window(65535);
        tcp_header.set_data_offset((TCP_HEADER_LEN / 4) as u8);

        println!("ACK TCP ACK REPLY FROM US: {:?}", tcp_header);

        let checksum_val =
            ipv4_checksum(&tcp_header.to_immutable(), &IPV4_SOURCE, &ipv4_destination);
        tcp_header.set_checksum(checksum_val);

        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(IPV4_SOURCE);
        ip_header.set_destination(*ipv4_destination);
        ip_header.set_identification(1);
        ip_header.set_header_length(5);
        ip_header.set_version(4);
        ip_header.set_ttl(64);
        ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);

        ip_header.set_checksum(checksum(&ip_header.to_immutable()));

        let size = self.tun.write(&packet).unwrap();
        println!("Size: {size}");

        Ok(TcpStream {
            socket_addr_v4: self.socket_addr_v4,
            state: Established {
                receive,
                send,
                source: 12345,
            },
            tun: Rc::clone(&self.tun),
        })
    }
}

impl TcpStream<Established> {
    fn reset(&mut self) -> Result<(), &'static str> {
        const IPV4_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;

        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];

        let ipv4_destination = self.socket_addr_v4.ip();

        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_source(12345);
        tcp_header.set_destination(80);
        tcp_header.set_sequence(self.state.send.next);
        self.state.send.next = self.state.send.next + 1;
        tcp_header.set_acknowledgement(self.state.receive.next);
        tcp_header.set_flags(TcpFlags::RST);
        tcp_header.set_window(65535);
        tcp_header.set_data_offset((TCP_HEADER_LEN / 4) as u8);

        let checksum_val =
            ipv4_checksum(&tcp_header.to_immutable(), &IPV4_SOURCE, ipv4_destination);
        tcp_header.set_checksum(checksum_val);

        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(IPV4_SOURCE);
        ip_header.set_destination(*ipv4_destination);
        ip_header.set_identification(1);
        ip_header.set_header_length(5);
        ip_header.set_version(4);
        ip_header.set_ttl(64);
        ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);

        ip_header.set_checksum(checksum(&ip_header.to_immutable()));

        println!("reset: TunSocket = {:?}", self.tun);

        let size = self.tun.write(&packet).unwrap();

        Ok(())
    }
}

impl io::Read for TcpStream<Established> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        println!("TcpStream: read: start");
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
        Ok(42)
    }
}

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
