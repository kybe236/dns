use std::{error::Error, fmt};

#[derive(Debug)]
pub enum DnsError {
    InvalidZFlag(i32),
    InvalidOpcodeFlag(i32),
    InvalidRcodeFlag(i32),
    InvalidQType(u16),
    InvalidQClass(u16),
    UdpSocketError(u16),
}

impl Error for DnsError {}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DnsError::InvalidZFlag(v) => write!(f, "Invalid Z flag {v} (should be 0)"),
            DnsError::InvalidOpcodeFlag(v) => write!(f, "Invalid opcode flag {v} (should be 0-2)"),
            DnsError::InvalidRcodeFlag(v) => write!(f, "Invalid rcode flag {v} (should be 0-5)"),
            DnsError::InvalidQType(v) => write!(f, "Invalid qtype {v} (should be in https://en.wikipedia.org/wiki/List_of_DNS_record_types) (contact me if im wrong!)"),
            DnsError::InvalidQClass(v) => write!(f, "Invalid qclass {v} (should be in rfc6895) (contact me if im wrong!)"),
            DnsError::UdpSocketError(v) => write!(f, "UdpSocket returned Error: {v}"),
        }
    }
}
