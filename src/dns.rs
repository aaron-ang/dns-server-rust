use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use bytes::{BufMut, BytesMut};
use num_enum::{IntoPrimitive, TryFromPrimitive};

const DNS_HEADER_LEN: usize = 12;
const MAX_DNS_PACKET_SIZE: usize = 512;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const PORT_ANY: u16 = 0;

pub(crate) fn forward_request(request_bytes: &[u8], resolver: SocketAddr) -> Option<Vec<u8>> {
    let request = DnsPacket::parse(request_bytes)?;
    if request.header.operation_code != 0 {
        return Some(DnsPacket::invalid_opcode_response(&request).to_bytes());
    }

    let upstream_socket =
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT_ANY))).ok()?;
    upstream_socket
        .set_read_timeout(Some(UPSTREAM_TIMEOUT))
        .ok()?;

    let mut answers = Vec::new();
    let mut buf = [0; MAX_DNS_PACKET_SIZE];

    for question in &request.questions {
        let query = DnsPacket::single_question_query(&request.header, question.clone());
        if upstream_socket
            .send_to(&query.to_bytes(), resolver)
            .is_err()
        {
            eprintln!("failed to send forwarded DNS query to resolver {resolver}");
            continue;
        }

        let response = match upstream_socket.recv_from(&mut buf) {
            Ok((size, _)) => DnsPacket::parse(&buf[..size]),
            Err(err) => {
                eprintln!("failed to receive DNS response from resolver {resolver}: {err}");
                None
            }
        };

        if let Some(response) = response {
            answers.extend(response.answers);
        } else {
            eprintln!("failed to parse DNS response from resolver {resolver}");
        }
    }

    Some(DnsPacket::merged_response(&request, answers).to_bytes())
}

#[derive(Debug)]
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
}

impl DnsPacket {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let header = DnsHeader::parse(bytes)?;
        let mut parser = DnsReader::new(bytes).with_offset(DNS_HEADER_LEN);

        let questions = parser.read_questions(header.question_count)?;
        let answers = parser.read_records(header.answer_record_count)?;
        parser.skip_records(header.authority_record_count)?;
        parser.skip_records(header.additional_record_count)?;

        Some(Self {
            header,
            questions,
            answers,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&self.header.to_bytes());
        for question in &self.questions {
            buf.extend_from_slice(&question.to_bytes());
        }
        for answer in &self.answers {
            buf.extend_from_slice(&answer.to_bytes());
        }
        buf.to_vec()
    }

    fn single_question_query(request_header: &DnsHeader, question: DnsQuestion) -> Self {
        Self {
            header: DnsHeader::query(
                request_header.packet_id,
                request_header.operation_code,
                request_header.recursion_desired,
                1,
            ),
            questions: vec![question],
            answers: Vec::new(),
        }
    }

    fn merged_response(request: &DnsPacket, answers: Vec<DnsRecord>) -> Self {
        Self {
            header: DnsHeader::response_from_request(
                &request.header,
                request.questions.len() as u16,
                answers.len() as u16,
                0,
            ),
            questions: request.questions.clone(),
            answers,
        }
    }

    fn invalid_opcode_response(request: &DnsPacket) -> Self {
        Self {
            header: DnsHeader::response_from_request(
                &request.header,
                request.questions.len() as u16,
                0,
                4,
            ),
            questions: request.questions.clone(),
            answers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
enum QueryResponse {
    Query = 0,
    Reply = 1,
}

#[derive(Debug)]
struct DnsHeader {
    packet_id: u16,
    query_response_indicator: QueryResponse,
    operation_code: u8,
    authoritative_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    reserved: u8,
    response_code: u8,
    question_count: u16,
    answer_record_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,
}

impl DnsHeader {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < DNS_HEADER_LEN {
            return None;
        }

        let flags1 = bytes[2];
        let flags2 = bytes[3];

        Some(Self {
            packet_id: u16::from_be_bytes([bytes[0], bytes[1]]),
            query_response_indicator: QueryResponse::try_from((flags1 >> 7) & 1).ok()?,
            operation_code: (flags1 >> 3) & 0x0f,
            authoritative_answer: ((flags1 >> 2) & 1) != 0,
            truncation: ((flags1 >> 1) & 1) != 0,
            recursion_desired: (flags1 & 1) != 0,
            recursion_available: ((flags2 >> 7) & 1) != 0,
            reserved: (flags2 >> 4) & 0x07,
            response_code: flags2 & 0x0f,
            question_count: u16::from_be_bytes([bytes[4], bytes[5]]),
            answer_record_count: u16::from_be_bytes([bytes[6], bytes[7]]),
            authority_record_count: u16::from_be_bytes([bytes[8], bytes[9]]),
            additional_record_count: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }

    fn query(
        packet_id: u16,
        operation_code: u8,
        recursion_desired: bool,
        question_count: u16,
    ) -> Self {
        Self {
            packet_id,
            query_response_indicator: QueryResponse::Query,
            operation_code,
            authoritative_answer: false,
            truncation: false,
            recursion_desired,
            recursion_available: false,
            reserved: 0,
            response_code: 0,
            question_count,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
        }
    }

    fn response_from_request(
        request: &DnsHeader,
        question_count: u16,
        answer_count: u16,
        response_code: u8,
    ) -> Self {
        Self {
            packet_id: request.packet_id,
            query_response_indicator: QueryResponse::Reply,
            operation_code: request.operation_code,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: request.recursion_desired,
            recursion_available: false,
            reserved: 0,
            response_code,
            question_count,
            answer_record_count: answer_count,
            authority_record_count: 0,
            additional_record_count: 0,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(DNS_HEADER_LEN);
        buf.put_u16(self.packet_id);

        let query_response_indicator: u8 = self.query_response_indicator.into();
        let flags1 = (query_response_indicator << 7)
            | (self.operation_code << 3)
            | ((self.authoritative_answer as u8) << 2)
            | ((self.truncation as u8) << 1)
            | (self.recursion_desired as u8);
        buf.put_u8(flags1);

        let flags2 = ((self.recursion_available as u8) << 7)
            | ((self.reserved & 0x07) << 4)
            | (self.response_code & 0x0f);
        buf.put_u8(flags2);

        buf.put_u16(self.question_count);
        buf.put_u16(self.answer_record_count);
        buf.put_u16(self.authority_record_count);
        buf.put_u16(self.additional_record_count);
        buf.to_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, TryFromPrimitive)]
#[repr(u16)]
enum DnsRecordType {
    A = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, TryFromPrimitive)]
#[repr(u16)]
enum DnsRecordClass {
    IN = 1,
}

#[derive(Debug, Clone, PartialEq)]
struct DnsQuestion {
    name: String,
    record_type: DnsRecordType,
    record_class: DnsRecordClass,
}

impl DnsQuestion {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_domain_name(&self.name));
        buf.put_u16(self.record_type as u16);
        buf.put_u16(self.record_class as u16);
        buf.to_vec()
    }
}

#[derive(Debug, Clone, PartialEq)]
struct DnsRecord {
    name: String,
    record_type: DnsRecordType,
    record_class: DnsRecordClass,
    ttl: u32,
    rdata: Vec<u8>,
}

impl DnsRecord {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_domain_name(&self.name));
        buf.put_u16(self.record_type as u16);
        buf.put_u16(self.record_class as u16);
        buf.put_u32(self.ttl);
        buf.put_u16(self.rdata.len() as u16);
        buf.extend_from_slice(&self.rdata);
        buf.to_vec()
    }
}

pub(crate) fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    for part in name.split('.') {
        buf.put_u8(part.len() as u8);
        buf.extend_from_slice(part.as_bytes());
    }
    buf.put_u8(0);
    buf.to_vec()
}

struct DnsReader<'a> {
    msg: &'a [u8],
    cursor: usize,
}

impl<'a> DnsReader<'a> {
    fn new(msg: &'a [u8]) -> Self {
        Self { msg, cursor: 0 }
    }

    fn with_offset(mut self, offset: usize) -> Self {
        self.cursor = offset;
        self
    }

    fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.read_slice(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let bytes = self.read_slice(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_bytes(&mut self, len: usize) -> Option<Vec<u8>> {
        Some(self.read_slice(len)?.to_vec())
    }

    fn skip_bytes(&mut self, len: usize) -> Option<()> {
        self.read_slice(len)?;
        Some(())
    }

    fn read_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let bytes = self.msg.get(self.cursor..self.cursor + len)?;
        self.cursor += len;
        Some(bytes)
    }

    fn read_domain_name_at(&self, offset: usize) -> Option<(String, usize)> {
        let mut labels = Vec::new();
        let mut visited = vec![false; self.msg.len()];
        let mut pos = offset;
        let mut next_offset = offset;
        let mut jumped = false;

        loop {
            if pos >= self.msg.len() || visited[pos] {
                return None;
            }
            visited[pos] = true;

            let len = self.msg[pos];
            match len & 0b1100_0000 {
                0b0000_0000 => {
                    pos += 1;
                    if len == 0 {
                        if !jumped {
                            next_offset = pos;
                        }
                        break;
                    }

                    let len = len as usize;
                    if pos + len > self.msg.len() {
                        return None;
                    }

                    let label = std::str::from_utf8(&self.msg[pos..pos + len]).ok()?;
                    labels.push(label.to_string());
                    pos += len;
                }
                0b1100_0000 => {
                    if pos + 1 >= self.msg.len() {
                        return None;
                    }

                    let ptr_offset =
                        (((len as usize) & 0b0011_1111) << 8) | self.msg[pos + 1] as usize;
                    if ptr_offset >= self.msg.len() {
                        return None;
                    }

                    if !jumped {
                        next_offset = pos + 2;
                        jumped = true;
                    }
                    pos = ptr_offset;
                }
                _ => return None,
            }
        }

        Some((labels.join("."), next_offset))
    }

    fn read_domain_name(&mut self) -> Option<String> {
        let (name, next_offset) = self.read_domain_name_at(self.cursor)?;
        self.cursor = next_offset;
        Some(name)
    }

    fn read_question(&mut self) -> Option<DnsQuestion> {
        let name = self.read_domain_name()?;
        let record_type = DnsRecordType::try_from(self.read_u16()?).ok()?;
        let record_class = DnsRecordClass::try_from(self.read_u16()?).ok()?;
        Some(DnsQuestion {
            name,
            record_type,
            record_class,
        })
    }

    fn read_questions(&mut self, count: u16) -> Option<Vec<DnsQuestion>> {
        let mut questions = Vec::with_capacity(count as usize);
        for _ in 0..count {
            questions.push(self.read_question()?);
        }
        Some(questions)
    }

    fn read_record(&mut self) -> Option<DnsRecord> {
        let name = self.read_domain_name()?;
        let record_type = DnsRecordType::try_from(self.read_u16()?).ok()?;
        let record_class = DnsRecordClass::try_from(self.read_u16()?).ok()?;
        let ttl = self.read_u32()?;
        let rdata_len = self.read_u16()? as usize;
        let rdata = self.read_bytes(rdata_len)?;

        Some(DnsRecord {
            name,
            record_type,
            record_class,
            ttl,
            rdata,
        })
    }

    fn read_records(&mut self, count: u16) -> Option<Vec<DnsRecord>> {
        let mut records = Vec::with_capacity(count as usize);
        for _ in 0..count {
            records.push(self.read_record()?);
        }
        Some(records)
    }

    fn skip_record(&mut self) -> Option<()> {
        self.read_domain_name()?;
        self.read_u16()?;
        self.read_u16()?;
        self.read_u32()?;
        let rdata_len = self.read_u16()? as usize;
        self.skip_bytes(rdata_len)
    }

    fn skip_records(&mut self, count: u16) -> Option<()> {
        for _ in 0..count {
            self.skip_record()?;
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread, time::Instant};

    use super::*;

    fn question(name: &str) -> DnsQuestion {
        DnsQuestion {
            name: name.to_string(),
            record_type: DnsRecordType::A,
            record_class: DnsRecordClass::IN,
        }
    }

    fn a_record(name: &str, ttl: u32, rdata: [u8; 4]) -> DnsRecord {
        DnsRecord {
            name: name.to_string(),
            record_type: DnsRecordType::A,
            record_class: DnsRecordClass::IN,
            ttl,
            rdata: rdata.to_vec(),
        }
    }

    fn query_packet(id: u16, opcode: u8, rd: bool, questions: Vec<DnsQuestion>) -> DnsPacket {
        DnsPacket {
            header: DnsHeader::query(id, opcode, rd, questions.len() as u16),
            questions,
            answers: Vec::new(),
        }
    }

    fn response_packet(
        id: u16,
        rd: bool,
        questions: Vec<DnsQuestion>,
        answers: Vec<DnsRecord>,
    ) -> DnsPacket {
        let request_header = DnsHeader::query(id, 0, rd, questions.len() as u16);
        DnsPacket {
            header: DnsHeader::response_from_request(
                &request_header,
                questions.len() as u16,
                answers.len() as u16,
                0,
            ),
            questions,
            answers,
        }
    }

    #[test]
    fn test_dns_question_roundtrip() {
        let q = question("google.com");
        let wire = q.to_bytes();
        let mut parser = DnsReader::new(&wire);
        let parsed = parser.read_question().expect("question roundtrip");
        assert_eq!(parsed, q);
        let remaining = parser.msg.len().saturating_sub(parser.cursor);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_single_question_upstream_query_has_one_question() {
        let request_header = DnsHeader::query(0x1234, 0, true, 2);
        let packet = DnsPacket::single_question_query(&request_header, question("codecrafters.io"));
        let bytes = packet.to_bytes();
        let parsed = DnsPacket::parse(&bytes).expect("parse upstream query");

        assert_eq!(parsed.header.packet_id, 0x1234);
        assert_eq!(parsed.header.question_count, 1);
        assert_eq!(parsed.header.answer_record_count, 0);
        assert_eq!(parsed.questions, vec![question("codecrafters.io")]);
    }

    #[test]
    fn test_parse_response_with_compressed_answer_name() {
        let mut buf = BytesMut::new();
        buf.put_u16(0x1234);
        buf.put_u8(0x81);
        buf.put_u8(0x00);
        buf.put_u16(1);
        buf.put_u16(1);
        buf.put_u16(0);
        buf.put_u16(0);

        let qname_offset = buf.len();
        let question = question("example.com");
        buf.extend_from_slice(&question.to_bytes());

        buf.put_u16(0xC000 | qname_offset as u16);
        buf.put_u16(1);
        buf.put_u16(1);
        buf.put_u32(60);
        buf.put_u16(4);
        buf.extend_from_slice(&[1, 2, 3, 4]);

        let packet = DnsPacket::parse(&buf).expect("parse response");
        assert_eq!(packet.questions, vec![question]);
        assert_eq!(
            packet.answers,
            vec![a_record("example.com", 60, [1, 2, 3, 4])]
        );
    }

    #[test]
    fn test_merged_response_preserves_question_order_and_counts() {
        let request = query_packet(
            0x4321,
            0,
            true,
            vec![question("first.example"), question("second.example")],
        );
        let answers = vec![
            a_record("first.example", 30, [1, 1, 1, 1]),
            a_record("second.example", 45, [2, 2, 2, 2]),
        ];

        let response = DnsPacket::merged_response(&request, answers.clone());
        let parsed = DnsPacket::parse(&response.to_bytes()).expect("parse merged response");

        assert_eq!(parsed.header.packet_id, 0x4321);
        assert_eq!(parsed.header.question_count, 2);
        assert_eq!(parsed.header.answer_record_count, 2);
        assert_eq!(parsed.questions, request.questions);
        assert_eq!(parsed.answers, answers);
    }

    #[test]
    fn test_invalid_opcode_response_sets_rcode_four() {
        let request = query_packet(0x1000, 2, true, vec![question("codecrafters.io")]);
        let response = DnsPacket::invalid_opcode_response(&request);
        let bytes = response.to_bytes();
        let parsed = DnsPacket::parse(&bytes).expect("parse invalid opcode response");

        assert_eq!(parsed.header.packet_id, 0x1000);
        assert_eq!(parsed.header.response_code, 4);
        assert_eq!(parsed.questions, request.questions);
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn test_forward_request_merges_fake_resolver_answers() {
        let upstream = UdpSocket::bind("127.0.0.1:0").expect("bind fake resolver");
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let resolver_addr = upstream.local_addr().expect("resolver addr");

        let (done_tx, done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut buf = [0; MAX_DNS_PACKET_SIZE];
            let mut seen_questions = Vec::new();

            for ip in [[10, 0, 0, 1], [10, 0, 0, 2]] {
                let (size, source) = upstream
                    .recv_from(&mut buf)
                    .expect("receive forwarded query");
                let packet = DnsPacket::parse(&buf[..size]).expect("parse forwarded query");
                assert_eq!(packet.questions.len(), 1);

                let question = packet.questions[0].clone();
                seen_questions.push(question.clone());

                let response = response_packet(
                    packet.header.packet_id,
                    packet.header.recursion_desired,
                    vec![question.clone()],
                    vec![a_record(&question.name, 60, ip)],
                );
                upstream
                    .send_to(&response.to_bytes(), source)
                    .expect("send fake resolver response");
            }

            done_tx.send(seen_questions).expect("send seen questions");
        });

        let request = query_packet(
            0x2200,
            0,
            true,
            vec![question("first.test"), question("second.test")],
        );
        let response_bytes =
            forward_request(&request.to_bytes(), resolver_addr).expect("forward request");
        let response = DnsPacket::parse(&response_bytes).expect("parse merged response");

        assert_eq!(response.header.packet_id, 0x2200);
        assert_eq!(response.questions, request.questions);
        assert_eq!(response.answers.len(), 2);
        assert_eq!(
            response.answers[0],
            a_record("first.test", 60, [10, 0, 0, 1])
        );
        assert_eq!(
            response.answers[1],
            a_record("second.test", 60, [10, 0, 0, 2])
        );

        let seen_questions = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("resolver saw packets");
        assert_eq!(seen_questions, request.questions);
        server.join().expect("join fake resolver");
    }

    #[test]
    fn test_forward_request_splits_multi_question_queries() {
        let upstream = UdpSocket::bind("127.0.0.1:0").expect("bind fake resolver");
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let resolver_addr = upstream.local_addr().expect("resolver addr");

        let (done_tx, done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut buf = [0; MAX_DNS_PACKET_SIZE];
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut counts = Vec::new();

            while counts.len() < 2 && Instant::now() < deadline {
                let (size, source) = upstream
                    .recv_from(&mut buf)
                    .expect("receive forwarded query");
                let packet = DnsPacket::parse(&buf[..size]).expect("parse forwarded query");
                counts.push(packet.questions.len());

                let question = packet.questions[0].clone();
                let response = response_packet(
                    packet.header.packet_id,
                    packet.header.recursion_desired,
                    vec![question.clone()],
                    vec![a_record(
                        &question.name,
                        60,
                        [127, 0, 0, counts.len() as u8],
                    )],
                );
                upstream
                    .send_to(&response.to_bytes(), source)
                    .expect("send fake resolver response");
            }

            done_tx.send(counts).expect("send counts");
        });

        let request = query_packet(
            0x3300,
            0,
            false,
            vec![question("one.test"), question("two.test")],
        );

        let response =
            forward_request(&request.to_bytes(), resolver_addr).expect("forward request");
        let parsed = DnsPacket::parse(&response).expect("parse response");
        assert_eq!(parsed.answers.len(), 2);

        let counts = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("counts");
        assert_eq!(counts, vec![1, 1]);
        server.join().expect("join fake resolver");
    }
}
