#[derive(Debug, Clone, Copy)]
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

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0] = (self.packet_id >> 8) as u8;
        bytes[1] = self.packet_id as u8;
        bytes[2] = (self.query_response_indicator.clone() as u8) << 7
            | (self.operation_code << 3)
            | (self.authoritative_answer as u8) << 2
            | (self.truncation as u8) << 1
            | self.recursion_desired as u8;
        bytes[3] =
            (self.recursion_available as u8) << 7 | (self.reserved << 4) | self.response_code;
        bytes[4] = (self.question_count >> 8) as u8;
        bytes[5] = self.question_count as u8;
        bytes[6] = (self.answer_record_count >> 8) as u8;
        bytes[7] = self.answer_record_count as u8;
        bytes[8] = (self.authority_record_count >> 8) as u8;
        bytes[9] = self.authority_record_count as u8;
        bytes[10] = (self.additional_record_count >> 8) as u8;
        bytes[11] = self.additional_record_count as u8;
        bytes
    }
}
