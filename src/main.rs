#[allow(unused_imports)]
use std::net::UdpSocket;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidHeader,
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

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let request_header: DnsMessageHeader = (&buf[0..12])
                    .try_into()
                    .expect("incorrect DNS message header");

                println!(
                    "Received {} bytes from {}, {:?}",
                    size, source, request_header
                );

                let response_header = DnsMessageHeader {
                    id: 1234,
                    qr: true,
                    op_code: 0,
                    aa: false,
                    tc: false,
                    rd: false,
                    ra: false,
                    z: 0,
                    rcode: 0,
                    qd_count: 0,
                    an_count: 0,
                    ns_count: 0,
                    ar_count: 0,
                };

                let response: [u8; 12] = (&response_header).into();
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
