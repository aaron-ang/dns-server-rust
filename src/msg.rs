pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
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
        bytes
    }
}

#[derive(Default)]
pub struct DnsPacketBuilder {
    questions: Vec<DnsQuestion>,
}
impl DnsPacketBuilder {
    pub fn add_question(mut self, question: DnsQuestion) -> Self {
        self.questions.push(question);
        self
    }

    pub fn build(self) -> DnsPacket {
        DnsPacket {
            header: DnsHeader {
                question_count: self.questions.len() as u16,
                ..DnsHeader::new()
            },
            questions: self.questions,
        }
    }
}

#[derive(Clone)]
enum QueryResponse {
    QuestionPacket,
    ReplyPacket,
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0u8; 12];
        bytes[0..2].copy_from_slice(&self.packet_id.to_be_bytes());
        bytes[2] = (self.query_response_indicator.clone() as u8) << 7
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
        for part in self.name.split('.') {
            bytes.push(part.len() as u8);
            bytes.extend(part.as_bytes());
        }
        bytes.push(0);

        bytes.extend((self.record_type as u16).to_be_bytes());
        bytes.extend((self.record_class as u16).to_be_bytes());
        bytes
    }
}
