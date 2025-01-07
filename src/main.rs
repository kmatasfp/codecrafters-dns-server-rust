use std::net::UdpSocket;

use bytes::{BufMut, BytesMut};

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

fn dns_questions_from_bytes(
    data: &[u8],
    size: usize,
    nr_of_questions: &u16,
) -> Result<Vec<DnsMessageQuestion>> {
    // todo retun number of bytes read
    fn parse_question(
        data: &[u8],
        size: &usize,
        q_index: usize,
    ) -> Result<(DnsMessageQuestion, usize)> {
        // todo return number of bytes read
        fn parse_labels(data: &[u8], l_index: usize) -> Result<(Vec<u8>, usize)> {
            fn is_valid_compression_pointer(byte: &u8) -> bool {
                byte >> 6 & 0b0000_0011 == 0b0000_0011
            }

            let mut labels = Vec::new();
            let mut index = l_index;
            loop {
                match &data[index] {
                    0 => {
                        labels.push(b'\0');
                        break;
                    }
                    len @ 1..=63 => {
                        labels.extend_from_slice(&data[index..index + *len as usize + 1]);
                        index += *len as usize + 1;
                    }
                    pointer if is_valid_compression_pointer(pointer) => {
                        let mut offset = u16::from_be_bytes([*pointer, data[index + 1]]);
                        offset &= !(0b11 << 14); // zero out leftmost 2 bits

                        let (compressed_labels, _) = parse_labels(data, offset as usize - 12)?; // -12 because of headers are 12 bytes

                        index += 1;

                        labels.extend(compressed_labels);
                        break;
                    }
                    _ => return Err(Error::InvalidQuestion),
                }
            }

            Ok((labels, index + 1 - l_index))
        }

        if data[q_index] == 0 {
            return Err(Error::InvalidQuestion);
        }

        if *size < q_index + data[q_index] as usize + 1 {
            return Err(Error::InvalidQuestion);
        }

        let (labels, label_size_in_bytes) = parse_labels(data, q_index)?;

        if q_index + label_size_in_bytes + 4 > *size {
            return Err(Error::InvalidQuestion);
        }

        let qtype = u16::from_be_bytes([
            data[q_index + label_size_in_bytes],
            data[q_index + label_size_in_bytes + 1],
        ]);

        let class = u16::from_be_bytes([
            data[q_index + label_size_in_bytes + 2],
            data[q_index + label_size_in_bytes + 3],
        ]);

        let size_in_bytes = label_size_in_bytes + 4;

        Ok((
            DnsMessageQuestion {
                name: labels,
                qtype,
                class,
            },
            size_in_bytes,
        ))
    }

    let mut questions: Vec<DnsMessageQuestion> = Vec::new();
    let mut index = 0;
    for _ in 0..*nr_of_questions {
        let (question, size_in_bytes) = parse_question(data, &size, index)?;
        index += size_in_bytes;
        questions.push(question);
    }

    Ok(questions)
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

                if let Ok(mut request_header) = DnsMessageHeader::try_from(&buf[0..12]) {
                    if let Ok(questions) =
                        dns_questions_from_bytes(&buf[12..], size - 12, &request_header.qd_count)
                    {
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
                        request_header.qd_count = questions.len() as u16;
                        request_header.an_count = answers.len() as u16;

                        if request_header.op_code == 0 {
                            request_header.rcode = 0;
                        } else {
                            request_header.rcode = 4;
                        }

                        let response_header = request_header;
                        let response_header_bytes: [u8; 12] = (&response_header).into();

                        let response_question_bytes: Vec<u8> =
                            questions.iter().flat_map(Vec::from).collect();

                        let response_answer_bytes: Vec<u8> =
                            answers.iter().flat_map(Vec::from).collect();

                        let mut response_bytes = BytesMut::with_capacity(
                            response_answer_bytes.len()
                                + response_question_bytes.len()
                                + response_answer_bytes.len(),
                        );

                        response_bytes.put_slice(&response_header_bytes);
                        response_bytes.put_slice(&response_question_bytes);
                        response_bytes.put_slice(&response_answer_bytes);

                        if let Err(e) = udp_socket.send_to(&response_bytes.freeze()[..], source) {
                            eprintln!("Failed to send response, {}", e);
                        }
                    } else {
                        eprintln!("Failed to parse questions from {:?}", buf);
                    }
                } else {
                    eprintln!("Failed to parse header from {:?}", buf);
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
