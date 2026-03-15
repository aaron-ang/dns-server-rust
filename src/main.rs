use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use clap::Parser;

mod dns;

const DNS_PORT: u16 = 2053;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    resolver: SocketAddr,
}

fn main() {
    let args = Args::parse();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, DNS_PORT));
    let udp_socket = UdpSocket::bind(addr).expect(&format!("failed to bind to {addr}"));
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                if let Some(response) = dns::forward_request(&buf[..size], args.resolver) {
                    udp_socket
                        .send_to(&response, source)
                        .expect("failed to send DNS response");
                } else {
                    eprintln!("failed to handle DNS request from {source}");
                }
            }
            Err(err) => {
                eprintln!("error receiving UDP data: {err}");
                break;
            }
        }
    }
}
