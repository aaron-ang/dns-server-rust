use bytes::{Buf, BufMut, Bytes, BytesMut};

pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}
impl DnsPacket {
    pub fn response_bytes(request_bytes: &[u8]) -> Vec<u8> {
        if let Some(request) = DnsRequest::parse(request_bytes) {
            return DnsPacket::from_request(request).to_bytes();
        }
        DnsPacketBuilder::default()
            .with_request(RequestHeader::default())
            .add_question(DnsQuestion {
                name: "codecrafters.io".to_string(),
                record_type: DnsRecordType::A,
                record_class: DnsRecordClass::IN,
            })
            .add_answer(DnsRecord {
                name: "codecrafters.io".to_string(),
                record_type: DnsRecordType::A,
                record_class: DnsRecordClass::IN,
                ttl: 60,
                rdata: vec![8, 8, 8, 8], // 8.8.8.8
            })
            .build()
            .to_bytes()
    }

    pub fn from_request(request: DnsRequest) -> Self {
        let mut builder = DnsPacketBuilder::default().with_request(request.header);

        for q in &request.questions {
            builder = builder.add_question(q.clone());
            builder = builder.add_answer(DnsRecord {
                name: q.name.clone(),
                record_type: DnsRecordType::A,
                record_class: DnsRecordClass::IN,
                ttl: 60,
                rdata: vec![8, 8, 8, 8], // 8.8.8.8
            });
        }

        builder.build()
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
}

#[derive(Default)]
pub struct DnsPacketBuilder {
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    request_header: Option<RequestHeader>,
}
impl DnsPacketBuilder {
    pub fn add_question(mut self, question: DnsQuestion) -> Self {
        self.questions.push(question);
        self
    }

    pub fn add_answer(mut self, answer: DnsRecord) -> Self {
        self.answers.push(answer);
        self
    }

    pub fn with_request(mut self, req: RequestHeader) -> Self {
        self.request_header = Some(req);
        self
    }

    pub fn build(self) -> DnsPacket {
        let qcount = self.questions.len() as u16;
        let acount = self.answers.len() as u16;
        let header = match self.request_header {
            Some(req) => DnsHeader::response_from_request(req, qcount, acount),
            None => DnsHeader {
                question_count: qcount,
                answer_record_count: acount,
                ..DnsHeader::new()
            },
        };
        DnsPacket {
            header,
            questions: self.questions,
            answers: self.answers,
        }
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum QueryResponse {
    QuestionPacket, // 0 = query
    ReplyPacket,    // 1 = response
}

pub struct DnsHeader {
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
impl Default for DnsHeader {
    fn default() -> Self {
        Self {
            packet_id: 1234,
            query_response_indicator: QueryResponse::ReplyPacket,
            operation_code: 0,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            reserved: 0,
            response_code: 0,
            question_count: 0,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
        }
    }
}
impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader::default()
    }

    pub fn response_from_request(
        req: RequestHeader,
        question_count: u16,
        answer_count: u16,
    ) -> Self {
        let response_code = if req.opcode == 0 { 0 } else { 4 };
        DnsHeader {
            packet_id: req.id,
            query_response_indicator: QueryResponse::ReplyPacket,
            operation_code: req.opcode,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: req.rd,
            recursion_available: false,
            reserved: 0,
            response_code,
            question_count,
            answer_record_count: answer_count,
            authority_record_count: 0,
            additional_record_count: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(12);
        buf.put_u16(self.packet_id);

        let flags1 = (self.query_response_indicator as u8) << 7
            | (self.operation_code << 3)
            | ((self.authoritative_answer as u8) << 2)
            | ((self.truncation as u8) << 1)
            | (self.recursion_desired as u8);
        buf.put_u8(flags1);

        let flags2 = ((self.recursion_available as u8) << 7)
            | (self.reserved << 4)
            | (self.response_code & 0x0F);
        buf.put_u8(flags2);

        buf.put_u16(self.question_count);
        buf.put_u16(self.answer_record_count);
        buf.put_u16(self.authority_record_count);
        buf.put_u16(self.additional_record_count);

        buf.to_vec()
    }
}

#[derive(Clone, Copy)]
pub enum DnsRecordType {
    A = 1,
}
#[derive(Clone, Copy)]
pub enum DnsRecordClass {
    IN = 1,
}
#[derive(Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: DnsRecordType,
    pub record_class: DnsRecordClass,
}
impl DnsQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_domain_name(&self.name));
        buf.put_u16(self.record_type as u16);
        buf.put_u16(self.record_class as u16);
        buf.to_vec()
    }
}

pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub record_class: DnsRecordClass,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}
impl DnsRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
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

pub struct RequestHeader {
    pub id: u16,
    pub opcode: u8,
    pub rd: bool,
    pub qdcount: u16,
}
impl Default for RequestHeader {
    fn default() -> Self {
        Self {
            id: 1234,
            opcode: 0,
            rd: false,
            qdcount: 1,
        }
    }
}
impl RequestHeader {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let opcode = (bytes[2] >> 3) & 0x0F;
        let rd = (bytes[2] & 1) != 0;
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        Some(Self {
            id,
            opcode,
            rd,
            qdcount,
        })
    }
}

/// A parsed DNS request: header + questions.
pub struct DnsRequest {
    pub header: RequestHeader,
    pub questions: Vec<DnsQuestion>,
}
impl DnsRequest {
    /// Parses a DNS request (header + question section) from raw bytes.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header = RequestHeader::parse(bytes)?;
        let mut parser = DnsParser::new(bytes).with_offset(12);
        let questions = parser.read_questions(header.qdcount)?;
        Some(Self { header, questions })
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

struct DnsParser {
    msg: Bytes,
    pos: usize,
}

impl DnsParser {
    fn new(msg: &[u8]) -> Self {
        Self {
            msg: Bytes::copy_from_slice(msg),
            pos: 0,
        }
    }

    fn with_offset(mut self, pos: usize) -> Self {
        self.pos = pos;
        self
    }

    fn remaining(&self) -> usize {
        self.msg.len().saturating_sub(self.pos)
    }

    fn read_u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let mut buf = self.msg.slice(self.pos..self.pos + 2);
        let value = buf.get_u16();
        self.pos += 2;
        Some(value)
    }

    /// Decode a (potentially compressed) domain name from a DNS message.
    /// `offset` is the index from the start of the message (per RFC 1035 section 4.1.4).
    /// Returns the decoded name and the offset immediately after the original name
    /// (past the last label or pointer).
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
        let (name, next_offset) = self.read_domain_name_at(self.pos)?;
        self.pos = next_offset;
        Some(name)
    }

    fn read_question(&mut self) -> Option<DnsQuestion> {
        let name = self.read_domain_name()?;
        let record_type = self.read_u16()?;
        let record_class = self.read_u16()?;
        Some(DnsQuestion {
            name,
            record_type: (record_type == 1).then_some(DnsRecordType::A)?,
            record_class: (record_class == 1).then_some(DnsRecordClass::IN)?,
        })
    }

    fn read_questions(&mut self, qdcount: u16) -> Option<Vec<DnsQuestion>> {
        let mut questions = Vec::with_capacity(qdcount as usize);
        for _ in 0..qdcount {
            questions.push(self.read_question()?);
        }
        Some(questions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(name: &str) -> DnsQuestion {
        DnsQuestion {
            name: name.to_string(),
            record_type: DnsRecordType::A,
            record_class: DnsRecordClass::IN,
        }
    }

    fn a_record(name: &str, ttl: u32, rdata: Vec<u8>) -> DnsRecord {
        DnsRecord {
            name: name.to_string(),
            record_type: DnsRecordType::A,
            record_class: DnsRecordClass::IN,
            ttl,
            rdata,
        }
    }

    #[test]
    fn test_dns_question_encoding() {
        let q = question("google.com");
        let wire = q.to_bytes();
        let parsed = DnsParser::new(&wire).read_question().expect("roundtrip");
        assert_eq!(parsed.name, q.name);
        assert!(matches!(parsed.record_type, DnsRecordType::A));
        assert!(matches!(parsed.record_class, DnsRecordClass::IN));
    }

    #[test]
    fn test_dns_packet_query_only() {
        let q = question("codecrafters.io");
        let packet = DnsPacketBuilder::default().add_question(q.clone()).build();
        let bytes = packet.to_bytes();

        // Header: id=1234, QR=1, QDCOUNT=1, ANCOUNT=0
        let header = RequestHeader::parse(&bytes[..12]).expect("header parse");
        assert_eq!(header.id, 1234);
        assert_eq!(header.opcode, 0);
        assert_eq!(header.qdcount, 1);

        // Question section matches encoded question bytes
        assert_eq!(&bytes[12..], q.to_bytes().as_slice());
    }

    #[test]
    fn test_dns_packet_with_answer() {
        let q = question("codecrafters.io");
        let answer = a_record("codecrafters.io", 60, vec![8, 8, 8, 8]);
        let packet = DnsPacketBuilder::default()
            .add_question(q.clone())
            .add_answer(answer)
            .build();
        let bytes = packet.to_bytes();

        // Header: id=1234, QDCOUNT=1, ANCOUNT=1
        let header = RequestHeader::parse(&bytes[..12]).expect("header parse");
        assert_eq!(header.id, 1234);
        assert_eq!(header.qdcount, 1);
        // ANCOUNT is bytes[6..8]
        assert_eq!(&bytes[6..8], &[0x00, 0x01]);

        // Question + answer section
        let expected_body: Vec<u8> = [
            q.to_bytes(),
            a_record("codecrafters.io", 60, vec![8, 8, 8, 8]).to_bytes(),
        ]
        .concat();
        assert_eq!(&bytes[12..], expected_body.as_slice());
    }

    #[test]
    fn test_decode_domain_name() {
        for domain in ["google.com", "codecrafters.io"] {
            let wire = encode_domain_name(domain);
            let parser = DnsParser::new(&wire);
            let (name, rest) = parser.read_domain_name_at(0).expect("valid name");
            assert_eq!(name, domain);
            assert_eq!(rest, wire.len(), "no remainder after full name");
        }
    }

    #[test]
    fn test_decode_domain_name_roundtrip() {
        for domain in ["google.com", "codecrafters.io", "a.co", "example.org"] {
            let encoded = encode_domain_name(domain);
            let parser = DnsParser::new(&encoded);
            let (decoded, _) = parser.read_domain_name_at(0).expect("roundtrip");
            assert_eq!(decoded, domain, "roundtrip for {domain}");
        }
    }

    #[test]
    fn test_decode_domain_name_invalid() {
        let mut wire = encode_domain_name("google");
        wire.pop();
        assert!(DnsParser::new(&wire).read_domain_name_at(0).is_none());

        let wire = [10u8, b'a', b'b', 0];
        assert!(DnsParser::new(&wire).read_domain_name_at(0).is_none());
    }

    #[test]
    fn test_parse_question() {
        let q = question("google.com");
        let wire = q.to_bytes();
        let mut parser = DnsParser::new(&wire);
        let parsed = parser.read_question().expect("valid question");
        assert_eq!(parsed.name, "google.com");
        assert!(matches!(parsed.record_type, DnsRecordType::A));
        assert!(matches!(parsed.record_class, DnsRecordClass::IN));
        assert!(parser.remaining() == 0, "no remainder after one question");
    }

    #[test]
    fn test_parse_question_rejects_non_a_type() {
        let wire: Vec<u8> = encode_domain_name("google.com")
            .into_iter()
            .chain(5u16.to_be_bytes())
            .chain(1u16.to_be_bytes())
            .collect();
        assert!(DnsParser::new(&wire).read_question().is_none());
    }

    #[test]
    fn test_request_header_parse() {
        let wire = [
            0x04, 0xd2, // id
            0x01, 0x00, // flags (RD=1)
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        let parsed = RequestHeader::parse(&wire).expect("valid header");
        assert_eq!(parsed.id, 1234);
        assert_eq!(parsed.opcode, 0);
        assert!(parsed.rd);
        assert_eq!(parsed.qdcount, 1);
    }

    #[test]
    fn test_parse_questions_full_packet() {
        let q = question("google.com");
        let header_bytes = [
            0x04, 0xd2, // id
            0x00, 0x00, // flags
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        let mut packet = header_bytes.to_vec();
        packet.extend(q.to_bytes());
        let mut parser = DnsParser::new(&packet).with_offset(12);
        let questions = parser.read_questions(1).expect("one question");
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].name, "google.com");
        assert!(matches!(questions[0].record_type, DnsRecordType::A));
        assert!(matches!(questions[0].record_class, DnsRecordClass::IN));
    }

    #[test]
    fn test_dns_request_roundtrip_bytes() {
        // Manually construct a DNS request as Bytes using BufMut.
        // Header: id=0x1234, RD=1, QDCOUNT=1, no answers.
        let mut buf = BytesMut::new();
        buf.put_u16(0x1234); // id
        buf.put_u8(0x01); // flags: RD=1
        buf.put_u8(0x00); // flags2
        buf.put_u16(0x0001); // QDCOUNT = 1
        buf.put_u16(0x0000); // ANCOUNT
        buf.put_u16(0x0000); // NSCOUNT
        buf.put_u16(0x0000); // ARCOUNT

        let q = question("google.com");
        buf.extend_from_slice(&q.to_bytes());

        let bytes = buf.freeze();
        let request = DnsRequest::parse(&bytes).expect("parse dns request from Bytes");
        assert_eq!(request.header.id, 0x1234);
        assert_eq!(request.header.qdcount, 1);
        assert_eq!(request.questions.len(), 1);
        assert_eq!(request.questions[0].name, "google.com");
        assert!(matches!(request.questions[0].record_type, DnsRecordType::A));
        assert!(matches!(
            request.questions[0].record_class,
            DnsRecordClass::IN
        ));
    }

    #[test]
    fn test_dns_request_roundtrip_bytes_with_compression() {
        // Build a request with two questions:
        // Q1: full name, Q2: name via compression pointer into Q1.
        let mut buf = BytesMut::new();
        buf.put_u16(0x4321); // id
        buf.put_u8(0x01); // flags: RD=1
        buf.put_u8(0x00); // flags2
        buf.put_u16(0x0002); // QDCOUNT = 2
        buf.put_u16(0x0000); // ANCOUNT
        buf.put_u16(0x0000); // NSCOUNT
        buf.put_u16(0x0000); // ARCOUNT

        // Remember start of first QNAME (offset from start of message).
        let q1_offset = buf.len();
        let q1 = question("example.com");
        buf.extend_from_slice(&q1.to_bytes());

        // Q2: compressed name pointing to q1_offset.
        let pointer = 0xC000 | (q1_offset as u16);
        buf.put_u16(pointer);
        buf.put_u16(1); // QTYPE = A
        buf.put_u16(1); // QCLASS = IN

        let bytes = buf.freeze();
        let request = DnsRequest::parse(&bytes).expect("parse compressed dns request");
        assert_eq!(request.header.id, 0x4321);
        assert_eq!(request.header.qdcount, 2);
        assert_eq!(request.questions.len(), 2);
        assert_eq!(request.questions[0].name, "example.com");
        assert_eq!(request.questions[1].name, "example.com");
        assert!(matches!(request.questions[0].record_type, DnsRecordType::A));
        assert!(matches!(request.questions[1].record_type, DnsRecordType::A));
        assert!(matches!(
            request.questions[0].record_class,
            DnsRecordClass::IN
        ));
        assert!(matches!(
            request.questions[1].record_class,
            DnsRecordClass::IN
        ));
    }

    #[test]
    fn test_decode_domain_name_with_label_prefix_and_pointer() {
        let mut msg = Vec::new();
        let suffix_offset = msg.len();
        msg.extend_from_slice(&encode_domain_name("example.com"));
        let mixed_offset = msg.len();
        msg.put_u8(3);
        msg.extend_from_slice(b"www");
        msg.put_u16(0xC000 | suffix_offset as u16);

        let parser = DnsParser::new(&msg);
        let (name, next_offset) = parser
            .read_domain_name_at(mixed_offset)
            .expect("mixed name");
        assert_eq!(name, "www.example.com");
        assert_eq!(next_offset, mixed_offset + 6);
    }

    #[test]
    fn test_decode_domain_name_rejects_self_pointer_cycle() {
        let msg = [0xC0, 0x00];
        assert!(DnsParser::new(&msg).read_domain_name_at(0).is_none());
    }

    #[test]
    fn test_decode_domain_name_rejects_multi_pointer_cycle() {
        let msg = [0xC0, 0x02, 0xC0, 0x00];
        assert!(DnsParser::new(&msg).read_domain_name_at(0).is_none());
    }

    #[test]
    fn test_decode_domain_name_rejects_reserved_label_prefixes() {
        let reserved_01 = [0x40, 0x00];
        let reserved_10 = [0x80, 0x00];
        assert!(DnsParser::new(&reserved_01)
            .read_domain_name_at(0)
            .is_none());
        assert!(DnsParser::new(&reserved_10)
            .read_domain_name_at(0)
            .is_none());
    }

    #[test]
    fn test_parse_questions_standalone_slice_still_roundtrips() {
        let q1 = question("google.com");
        let q2 = question("codecrafters.io");
        let wire: Vec<u8> = [q1.to_bytes(), q2.to_bytes()].concat();

        let mut parser = DnsParser::new(&wire);
        let questions = parser
            .read_questions(2)
            .expect("parse standalone questions");
        assert_eq!(questions.len(), 2);
        assert_eq!(questions[0].name, "google.com");
        assert_eq!(questions[1].name, "codecrafters.io");
    }
}
