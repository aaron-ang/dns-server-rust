use super::*;

#[test]
fn test_dns_question_encoding() {
    let question = DnsQuestion {
        name: "google.com".to_string(),
        record_type: DnsRecordType::A,
        record_class: DnsRecordClass::IN,
    };

    let expected = question_section_bytes("google.com", DnsRecordType::A, DnsRecordClass::IN);
    assert_eq!(
        question.to_bytes(),
        expected,
        "question section wire format"
    );
}

#[test]
fn test_dns_packet_query_only() {
    let packet = DnsPacket::builder()
        .add_question(DnsQuestion {
            name: "codecrafters.io".to_string(),
            record_class: DnsRecordClass::IN,
            record_type: DnsRecordType::A,
        })
        .build();

    let expected: Vec<u8> = [
        DnsHeader::response(1234, 1, 0).to_bytes(),
        question_section_bytes("codecrafters.io", DnsRecordType::A, DnsRecordClass::IN),
    ]
    .concat();
    assert_eq!(packet.to_bytes(), expected, "packet with question only");
}

#[test]
fn test_dns_packet_with_answer() {
    let packet = DnsPacket::builder()
        .add_question(DnsQuestion {
            name: "codecrafters.io".to_string(),
            record_class: DnsRecordClass::IN,
            record_type: DnsRecordType::A,
        })
        .add_answer(codecrafters_io_a_record(60, vec![8, 8, 8, 8]))
        .build();

    let expected: Vec<u8> = [
        DnsHeader::response(1234, 1, 1).to_bytes(),
        question_section_bytes("codecrafters.io", DnsRecordType::A, DnsRecordClass::IN),
        codecrafters_io_a_record(60, vec![8, 8, 8, 8]).to_bytes(),
    ]
    .concat();
    assert_eq!(
        packet.to_bytes(),
        expected,
        "packet with question and one A answer"
    );
}

fn question_section_bytes(
    name: &str,
    record_type: DnsRecordType,
    record_class: DnsRecordClass,
) -> Vec<u8> {
    [
        encode_domain_name(name),
        (record_type as u16).to_be_bytes().to_vec(),
        (record_class as u16).to_be_bytes().to_vec(),
    ]
    .concat()
}

fn codecrafters_io_a_record(ttl: u32, ip: Vec<u8>) -> DnsRecord {
    DnsRecord {
        name: "codecrafters.io".to_string(),
        record_type: DnsRecordType::A,
        record_class: DnsRecordClass::IN,
        ttl,
        rdata: ip,
    }
}
