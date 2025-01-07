#[allow(unused_imports)]
use std::net::UdpSocket;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidHeader,
    InvalidQuestion,
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
struct DnsMessageHeader {
    id: u16,
    qr: bool,
    op_code: u8, // 4bit
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

impl TryFrom<&[u8]> for DnsMessageHeader {
    type Error = Error;

    fn try_from(header_bytes: &[u8]) -> Result<Self> {
        if header_bytes.len() != 12 {
            return Err(Error::InvalidHeader);
        }

        let id = u16::from_be_bytes([header_bytes[0], header_bytes[1]]);

        let flags1 = header_bytes[2];
        let qr = (flags1 & 0b1000_0000) != 0;
        let op_code = (flags1 & 0b0111_1000) >> 3;
        let aa = (flags1 & 0b0000_0100) != 0;
        let tc = (flags1 & 0b0000_0010) != 0;
        let rd = (flags1 & 0b0000_0001) != 0;

        let flags2 = header_bytes[3];
        let ra = (flags2 & 0b1000_0000) != 0;
        let z = (flags2 & 0b0111_0000) >> 4;
        let rcode = flags2 & 0b0000_1111;

        let qd_count = u16::from_be_bytes([header_bytes[4], header_bytes[5]]);
        let an_count = u16::from_be_bytes([header_bytes[6], header_bytes[7]]);
        let ns_count = u16::from_be_bytes([header_bytes[8], header_bytes[9]]);
        let ar_count = u16::from_be_bytes([header_bytes[10], header_bytes[11]]);

        Ok(DnsMessageHeader {
            id,
            qr,
            op_code,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        })
    }
}

impl From<&DnsMessageHeader> for [u8; 12] {
    fn from(header: &DnsMessageHeader) -> Self {
        let mut buf = [0u8; 12];

        // ID
        buf[0..2].copy_from_slice(&header.id.to_be_bytes());

        // Flags byte 1
        buf[2] = ((header.qr as u8) << 7)
            | (header.op_code << 3)
            | ((header.aa as u8) << 2)
            | ((header.tc as u8) << 1)
            | (header.rd as u8);

        // Flags byte 2
        buf[3] = ((header.ra as u8) << 7) | (header.z << 4) | header.rcode;

        // Counts
        buf[4..6].copy_from_slice(&header.qd_count.to_be_bytes());
        buf[6..8].copy_from_slice(&header.an_count.to_be_bytes());
        buf[8..10].copy_from_slice(&header.ns_count.to_be_bytes());
        buf[10..12].copy_from_slice(&header.ar_count.to_be_bytes());

        buf
    }
}

#[derive(Debug)]
struct DnsMessageQuestion {
    name: Vec<u8>,
    qtype: u16,
    class: u16,
    size_in_bytes: usize,
}

impl TryFrom<&[u8]> for DnsMessageQuestion {
    type Error = Error;

    fn try_from(question_bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        if question_bytes[0] == 0 {
            return Err(Error::InvalidQuestion);
        }

        if question_bytes[0] == b'\0' {
            return Err(Error::InvalidQuestion);
        }

        if question_bytes.len() < question_bytes[0] as usize + 1 {
            return Err(Error::InvalidQuestion);
        }

        let mut name: Vec<u8> = question_bytes
            .iter()
            .take_while(|b| **b != b'\0')
            .map(|b| b.to_owned())
            .collect();

        name.push(b'\0');

        if name.len() + 4 > question_bytes.len() {
            return Err(Error::InvalidQuestion);
        }

        let qtype =
            u16::from_be_bytes([question_bytes[name.len()], question_bytes[name.len() + 1]]);

        let class = u16::from_be_bytes([
            question_bytes[name.len() + 2],
            question_bytes[name.len() + 3],
        ]);

        let size_in_bytes = name.len() + 4;

        Ok(DnsMessageQuestion {
            name,
            qtype,
            class,
            size_in_bytes,
        })
    }
}

impl From<&DnsMessageQuestion> for Vec<u8> {
    fn from(question: &DnsMessageQuestion) -> Self {
        let mut buf: Vec<u8> = Vec::from(question.name.as_slice());

        buf.extend_from_slice(&question.qtype.to_be_bytes());
        buf.extend_from_slice(&question.class.to_be_bytes());

        buf
    }
}

#[derive(Debug)]
struct DnsMessageResponse<'a> {
    name: &'a Vec<u8>,
    qtype: u16,
    class: u16,
    ttl: u32,
    length: u16,
    data: Vec<u8>,
}

impl<'a> From<&'a DnsMessageResponse<'a>> for Vec<u8> {
    fn from(response: &DnsMessageResponse) -> Self {
        let mut buf: Vec<u8> = Vec::from(response.name.as_slice());

        buf.extend_from_slice(&response.qtype.to_be_bytes());
        buf.extend_from_slice(&response.class.to_be_bytes());
        buf.extend_from_slice(&response.ttl.to_be_bytes());
        buf.extend_from_slice(&response.length.to_be_bytes());
        buf.extend_from_slice(&response.data[..]);

        buf
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                let mut request_header: DnsMessageHeader = (&buf[0..12])
                    .try_into()
                    .expect("incorrect DNS message header");

                let mut questions: Vec<DnsMessageQuestion> = Vec::new();
                let mut index = 12;
                for _ in 0..request_header.qd_count {
                    let question: DnsMessageQuestion = (&buf[index..]).try_into().unwrap();
                    index += question.size_in_bytes;
                    questions.push(question);
                }

                let answers: Vec<DnsMessageResponse> = questions
                    .iter()
                    .map(|q| {
                        let data = vec![1, 1, 1, 1];

                        DnsMessageResponse {
                            name: &q.name,
                            qtype: q.qtype,
                            class: q.class,
                            ttl: 60,
                            length: data.len() as u16,
                            data,
                        }
                    })
                    .collect();

                // reponses section

                request_header.qr = true;
                request_header.qd_count = 1;
                request_header.an_count = 1;

                if request_header.op_code == 0 {
                    request_header.rcode = 0;
                } else {
                    request_header.rcode = 4;
                }

                let response_header = request_header;
                let response_header_bytes: [u8; 12] = (&response_header).into();

                // let fixed_name = {
                //     let mut buf: Vec<u8> = vec![12];
                //     buf.extend_from_slice("codecrafters".as_bytes());
                //     buf.push(2);
                //     buf.extend_from_slice("io".as_bytes());
                //     buf.push(b'\0');

                //     buf
                // };

                let response_question_bytes: Vec<u8> =
                    questions.iter().flat_map(Vec::from).collect();

                let response_answer_bytes: Vec<u8> = answers.iter().flat_map(Vec::from).collect();

                udp_socket
                    .send_to(
                        &([
                            Vec::from(response_header_bytes),
                            response_question_bytes,
                            response_answer_bytes,
                        ]
                        .concat()),
                        source,
                    )
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
