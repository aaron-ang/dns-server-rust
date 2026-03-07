pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}
impl DnsPacket {
    pub fn builder() -> DnsPacketBuilder {
        DnsPacketBuilder::default()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.header.to_bytes());
        for question in &self.questions {
            bytes.extend(question.to_bytes());
        }
        for answer in &self.answers {
            bytes.extend(answer.to_bytes());
        }
        bytes
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
impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
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

    #[cfg(test)]
    pub fn response(packet_id: u16, question_count: u16, answer_count: u16) -> Self {
        DnsHeader {
            packet_id,
            question_count,
            answer_record_count: answer_count,
            ..Self::new()
        }
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
        let mut bytes = [0u8; 12];
        bytes[0..2].copy_from_slice(&self.packet_id.to_be_bytes());
        bytes[2] = (self.query_response_indicator as u8) << 7
            | (self.operation_code << 3)
            | (self.authoritative_answer as u8) << 2
            | (self.truncation as u8) << 1
            | self.recursion_desired as u8;
        bytes[3] =
            (self.recursion_available as u8) << 7 | (self.reserved << 4) | self.response_code;
        bytes[4..6].copy_from_slice(&self.question_count.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.answer_record_count.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.authority_record_count.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.additional_record_count.to_be_bytes());
        bytes.to_vec()
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
pub struct DnsQuestion {
    pub name: String,
    pub record_type: DnsRecordType,
    pub record_class: DnsRecordClass,
}
impl DnsQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(encode_domain_name(&self.name));
        bytes.extend((self.record_type as u16).to_be_bytes());
        bytes.extend((self.record_class as u16).to_be_bytes());
        bytes
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
        let mut bytes = Vec::new();
        bytes.extend(encode_domain_name(&self.name));
        bytes.extend((self.record_type as u16).to_be_bytes());
        bytes.extend((self.record_class as u16).to_be_bytes());
        bytes.extend(self.ttl.to_be_bytes());
        bytes.extend((self.rdata.len() as u16).to_be_bytes());
        bytes.extend(&self.rdata);
        bytes
    }
}

pub struct RequestHeader {
    pub id: u16,
    pub opcode: u8,
    pub rd: bool,
}
impl Default for RequestHeader {
    fn default() -> Self {
        Self {
            id: 1234,
            opcode: 0,
            rd: false,
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
        Some(Self { id, opcode, rd })
    }
}

pub(crate) fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in name.split('.') {
        bytes.push(part.len() as u8);
        bytes.extend(part.as_bytes());
    }
    bytes.push(0);
    bytes
}
