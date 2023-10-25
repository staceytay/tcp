use libc::{
    c_short, c_uchar, close, ioctl, open, read, write, IFF_NO_PI, IFF_TUN, IFNAMSIZ, O_RDWR,
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::packet::Packet;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
    os::unix::io::RawFd,
};

pub struct TcpStream {
    socket_addr: SocketAddr,
    tun: TunSocket,
}

impl TcpStream {
    pub fn connect<T: ToSocketAddrs>(addr: T) -> io::Result<TcpStream> {
        let socket_addr = addr.to_socket_addrs().unwrap().collect::<Vec<_>>()[0];

        match socket_addr {
            SocketAddrV4 @ socket_addr_v4 => {
                let tun = TunSocket::new("tun0")?;
                println!("TUN: {:?}", tun);

                let tcp_stream = TcpStream { socket_addr, tun };
                tcp_stream.open_tcp_connection();

                Ok(tcp_stream)
            }
            _ => panic!("TcpStream::connect: Ipv6 unsupported"),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.socket_addr)
    }

    fn open_tcp_connection(&self) -> Result<(), &'static str> {
        const IPV4_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 24;

        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];

        let ipv4_source = Ipv4Addr::new(192, 0, 2, 2);
        // let ipv4_destination = self.socket_addr.ip();
        // let ipv4_destination = Ipv4Addr::new(93, 184, 216, 34);
        let ipv4_destination = Ipv4Addr::new(192, 0, 2, 1);

        // TCP(src_port=12345, dst_port=8080, seq=0, ack=0, offset=96, flags=2, window=65535, checksum=50265, urgent=0, options=b'\x02\x04\x05\xb4', data=b'')
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        // TODO: use a random source port?
        tcp_header.set_source(12345);
        tcp_header.set_destination(8080);

        // TODO: What is sequence?
        tcp_header.set_sequence(0x0);

        tcp_header.set_acknowledgement(0x0);

        tcp_header.set_flags(TcpFlags::SYN);

        tcp_header.set_window(65535);

        tcp_header.set_data_offset((TCP_HEADER_LEN / 4) as u8);

        // let ts = TcpOption::timestamp(743951781, 44056978);
        tcp_header.set_options(&vec![TcpOption::mss(1460)]);

        let checksum_val =
            ipv4_checksum(&tcp_header.to_immutable(), &ipv4_source, &ipv4_destination);
        println!("checksum: {}", checksum_val);
        tcp_header.set_checksum(checksum_val);

        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
        ip_header.set_identification(1);
        ip_header.set_header_length(5);
        ip_header.set_version(4);
        ip_header.set_ttl(64);
        ip_header.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);

        ip_header.set_checksum(checksum(&ip_header.to_immutable()));

        println!("IP PACKET: {:?}", Ipv4Packet::new(&packet));
        let syn = b"E\x00\x00,\x00\x01\x00\x00@\x06\xf6\xc7\xc0\x00\x02\x02\xc0\x00\x02\x0109\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00`\x02\xff\xff\xc4Y\x00\x00\x02\x04\x05\xb4";
        println!("LENGTHS: Packet = {}, SYN = {}", packet.len(), syn.len());
        assert_eq!(&packet[..IPV4_HEADER_LEN], &syn[..IPV4_HEADER_LEN]);
        assert_eq!(&packet[IPV4_HEADER_LEN..], &syn[IPV4_HEADER_LEN..]);
        let size = self.tun.write(&packet).unwrap();

        println!("Size: {size}");

        let mut buf = [0; 1024];

        let packet = self.tun.read(&mut buf).unwrap();
        println!("packet: {:?}", packet);
        let response = Ipv4Packet::new(&packet).unwrap();
        println!("IP RESPONSE: {:?}", response);
        println!("TCP RESPONSE: {:?}", TcpPacket::new(response.payload()));

        Ok(())
    }
}

impl io::Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(42)
    }
}

impl io::Write for TcpStream {
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(42)
    }
}

#[derive(Debug)]
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
