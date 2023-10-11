use std::{
    io::{Read, Write},
    str,
};

use tcp::TcpStream;

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("example.com:80")?;

    println!("* Connected to {}", stream.peer_addr().unwrap());

    let mut response = [0; 2048];

    let _ = stream.write(b"GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n");
    let _ = stream.read(&mut response);

    if let [headers, content] = &(str::from_utf8(&response)
        .unwrap()
        .split("\r\n\r\n")
        .take(2)
        .collect::<Vec<&str>>())[..]
    {
        for h in headers.split("\r\n") {
            println!("< {}", h);
        }
        println!("<");
        println!("{} ", content);
    }

    Ok(())
}
