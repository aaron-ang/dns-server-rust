use super::*;

#[test]
fn test_dns_message() {
    let message = DnsQuestion {
        name: "google.com".to_string(),
        record_type: DnsRecordType::A,
        record_class: DnsRecordClass::IN,
    };
    assert_eq!(
        message.to_bytes(),
        vec![
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // name
            0x00, 0x1, // record_type
            0x0, 0x1 // record_class
        ]
    )
}

#[test]
fn test_dns_packet() {
    let packet = super::DnsPacket::builder()
        .add_question(DnsQuestion {
            name: "codecrafters.io".to_string(),
            record_class: DnsRecordClass::IN,
            record_type: DnsRecordType::A,
        })
        .build();
    assert_eq!(
        packet.to_bytes(),
        vec![
            0x04, 0xd2, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
            0x0c, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x72, 0x61, 0x66, 0x74, 0x65, 0x72, 0x73, 0x02,
            0x69, 0x6f, 0x00, // name
            0x00, 0x01, // record_type
            0x00, 0x01 // record_class
        ]
    )
}
