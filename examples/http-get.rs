use std::{
    env,
    io::{Read, Write},
    process, str,
};

use url::Url;

use tcp::TcpStream;

struct Config {
    pub url: String,
}

impl Config {
    pub fn build(mut args: impl Iterator<Item = String>) -> Result<Config, &'static str> {
        args.next();

        let url = match args.next() {
            Some(arg) => arg,
            None => return Err("Usage: http-get url"),
        };

        Ok(Config { url })
    }
}

fn main() {
    let config = Config::build(env::args()).unwrap_or_else(|err| {
        eprintln!("Error parsing argument: {err}");
        process::exit(1);
    });

    let url = Url::parse(&config.url).expect("Invalid url given");

    if url.scheme() == "https" {
        eprintln!("https unsupported for now, try http instead");
        process::exit(1);
    }

    let mut stream = TcpStream::connect(format!("{}:80", url.host().unwrap())).unwrap();

    println!("* Connected to {}", stream.peer_addr().unwrap());

    let mut response = [0; 4096];

    let _ = stream.write(
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            url.path(),
            url.host().unwrap()
        )
        .as_bytes(),
    );
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
}
