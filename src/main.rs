use libc::{close, ioctl, open, read, write, O_RDWR};
use std::io;

const TUNSETIFF: u64 = 0x400454CA;

fn main() -> std::io::Result<()> {
    println!("main: TUNSETIFF: {}", TUNSETIFF);

    let fd = match unsafe { open(b"/dev/net/tun\0".as_ptr() as _, O_RDWR) } {
        -1 => return Err(io::Error::last_os_error()),
        fd => fd,
    };
    println!("main: fd = {fd}");

    // ifs here taken from printing the `ifs` value in
    // https://jvns.ca/blog/2022/09/06/send-network-packets-python-tun-tap/
    let ifs = b"tun0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    println!("ifs = {:?}", &ifs);

    if unsafe { ioctl(fd, TUNSETIFF as _, &ifs) } < 0 {
        unsafe { close(fd) };
        return Err(io::Error::last_os_error());
    }

    // buf here contains the SYN packet from same link above.
    let buf = b"E\x00\x00,\x00\x01\x00\x00@\x06\xf6\xc7\xc0\x00\x02\x02\xc0\x00\x02\x0109\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00`\x02\xff\xff\xc4Y\x00\x00\x02\x04\x05\xb4";
    println!("main: writing to fd = {}, buf = {:?}", fd, &buf);

    // Code for writing to tun device referenced from
    // https://github.com/meh/rust-tun/blob/a35761b2f49e6b26434a3d5273b7bfb4d9eb18ca/src/platform/posix/fd.rs#L71
    if unsafe { write(fd, buf.as_ptr() as *const _, buf.len()) } < 0 {
        unsafe { close(fd) };
        return Err(io::Error::last_os_error());
    }

    // Code for reading from tun device referenced from
    // https://github.com/meh/rust-tun/blob/a35761b2f49e6b26434a3d5273b7bfb4d9eb18ca/src/platform/posix/fd.rs#L43
    let mut dst = [0; 4096];
    println!("TunSocket::new reading, dst = {:?}", &dst);
    if unsafe { read(fd, dst.as_mut_ptr() as *mut _, dst.len()) } < 0 {
        unsafe { close(fd) };
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
