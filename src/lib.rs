use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
};

pub struct TcpStream {
    socket_addr: SocketAddr,
}

impl TcpStream {
    pub fn connect<T: ToSocketAddrs>(addr: T) -> io::Result<TcpStream> {
        let socket_addr = addr.to_socket_addrs().unwrap().collect::<Vec<_>>()[0];
        Ok(TcpStream { socket_addr })
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.socket_addr)
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
