use std::net::UdpSocket;

mod msg;
use msg::*;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let packet = DnsPacket::builder()
                    .add_question(DnsQuestion {
                        name: "codecrafters.io".to_string(),
                        record_class: DnsRecordClass::IN,
                        record_type: DnsRecordType::A,
                    })
                    .build();
                let response = packet.to_bytes();
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

#[cfg(test)]
mod test;
