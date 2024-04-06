use std::{error::Error, fmt};

#[derive(Debug)]
pub enum DnsError {
    InvalidZFlag(i32),
    InvalidOpcodeFlag(i32),
    InvalidRcodeFlag(i32),
}

impl Error for DnsError {}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DnsError::InvalidZFlag(v) => write!(f, "Invalid Z flag {v} (should be 0)"),
            DnsError::InvalidOpcodeFlag(v) => write!(f, "Invalid opcode flag {v} (should be 0-2)"),
            DnsError::InvalidRcodeFlag(v) => write!(f, "Invalid rcode flag {v} (should be 0-5)"),
        }
    }
}