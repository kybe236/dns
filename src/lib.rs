//! DNS Client in Development
//!
//! # Goals
//! Make an dns client that supports all dns options.
//! 
//! 

mod dns_error;

use dns_error::DnsError;

use std::{
    error::Error,
    process::{self},
};

/// All communications inside of the domain protocol are carried in a single
/// format called a message.  The top level format of message is divided
/// into 5 sections (some of which are empty in certain cases) shown below:
#[allow(unused)]
#[derive(Debug)]
pub struct Message {
    /// The header section is always present.  The header includes fields that
    /// specify which of the remaining sections are present, and also specify
    /// whether the message is a query or a response, a standard query or some
    /// other opcode, etc.
    pub header: Header,
    /// The question section contains fields that describe a
    /// question to a name server.  These fields are a query type (QTYPE), a
    /// query class (QCLASS), and a query domain name (QNAME).
    pub question: Vec<Question>,
    /// The answer section contains RRs that answer the question.
    answer: Option<Vec<Resource>>,
    /// the authority section contains RRs that point toward an authoritative name server.
    authority: Option<Vec<Resource>>,
    /// the additional records section contains RRs
    /// which relate to the query, but are not strictly answers for the question.
    additional: Option<Vec<Resource>>,
}
impl Message {
    /// # Creates a new DnsOption
    ///
    /// # Example
    ///
    /// ```
    /// use dns::Message;
    ///
    /// let options = Message::new();
    /// ```
    pub fn new() -> Message {
        Message {
            header: Header::new(),
            question: vec![],
            answer: None,
            authority: None,
            additional: None,
        }
    }

    /// # Sets the domain name
    ///
    /// # Arguments
    ///
    /// takes a vector of strings as an argument.
    ///
    /// # Example
    ///
    /// ```
    /// use dns::Message;
    ///
    /// let mut question = Message::new();
    ///
    /// question.set_questions(vec!["www.google.com".to_string()]);
    /// ```
    ///
    /// # Note
    ///
    /// The domain name is represented as a sequence of labels, where
    /// each label consists of a length octet followed by that
    /// number of octets.  The domain name terminates with the
    /// zero length octet for the null label of the root.  Note
    /// that this field may be an odd number of octets; no
    /// padding is used.
    pub fn set_questions(&mut self, questions: Vec<String>) {
        let mut res = vec![];
        for label in questions {
            let parts = label.split('.');
            let mut new_parts = vec![];
            for part in parts {
                new_parts.push(part.len() as u8);
                for c in part.chars() {
                    new_parts.push(c as u8);
                }
            }
            res.append(&mut new_parts);
        }
        res.push(0);
        for _ in res.iter() {
            self.header.qdcount += 1;
            self.question.push(Question {
                qname: res.clone(),
                qtype: 0,
                qclass: 0,
            });
        }
    }

    pub fn from(vec: Vec<u8>) -> Message {
        let mut header = Header::new();
        header.id = u16::from_be_bytes([vec[0], vec[1]]);
        header.flags = u16::from_be_bytes([vec[2], vec[3]]);
        header.qdcount = u16::from_be_bytes([vec[4], vec[5]]);
        header.ancount = u16::from_be_bytes([vec[6], vec[7]]);
        header.nscount = u16::from_be_bytes([vec[8], vec[9]]);
        header.arcount = u16::from_be_bytes([vec[10], vec[11]]);

        let mut question = vec![];
        let mut i = 12;
        for _ in 0..header.qdcount {
            let mut qname = vec![];
            while vec[i] != 0 {
                qname.push(vec[i]);
                i += 1;
            }
            qname.push(0);
            i += 1;
            let qtype = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let qclass = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            question.push(Question {
                qname,
                qtype,
                qclass,
            });
        }

        let mut answer = vec![];

        for _ in 0..header.ancount {
            let mut name = vec![];
            while vec[i] != 0 {
                name.push(vec[i]);
                i += 1;
            }
            name.push(0);
            i += 1;
            let rtype = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let rclass = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let ttl = u32::from_be_bytes([vec[i], vec[i + 1], vec[i + 2], vec[i + 3]]);
            i += 4;
            let rdlength = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let mut rdata = vec![];
            for _ in 0..rdlength {
                rdata.push(vec[i]);
                i += 1;
            }
            answer.push(Resource {
                name,
                rtype,
                rclass,
                ttl,
                rdlength,
                rdata,
            });
        }

        let mut authority = vec![];
        for _ in 0..header.nscount {
            let mut name = vec![];
            while vec[i] != 0 {
                name.push(vec[i]);
                i += 1;
            }
            name.push(0);
            i += 1;
            let rtype = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let rclass = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let ttl = u32::from_be_bytes([vec[i], vec[i + 1], vec[i + 2], vec[i + 3]]);
            i += 4;
            let rdlength = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let mut rdata = vec![];
            for _ in 0..rdlength {
                rdata.push(vec[i]);
                i += 1;
            }
            authority.push(Resource {
                name,
                rtype,
                rclass,
                ttl,
                rdlength,
                rdata,
            });
        }

        let mut additional = vec![];
        for _ in 0..header.arcount {
            let mut name = vec![];
            while vec[i] != 0 {
                name.push(vec[i]);
                i += 1;
            }
            name.push(0);
            i += 1;
            let rtype = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let rclass = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let ttl = u32::from_be_bytes([vec[i], vec[i + 1], vec[i + 2], vec[i + 3]]);
            i += 4;
            let rdlength = u16::from_be_bytes([vec[i], vec[i + 1]]);
            i += 2;
            let mut rdata = vec![];
            for _ in 0..rdlength {
                rdata.push(vec[i]);
                i += 1;
            }
            additional.push(Resource {
                name,
                rtype,
                rclass,
                ttl,
                rdlength,
                rdata,
            });
        }

        Message {
            header,
            question,
            answer: Some(answer),
            authority: Some(authority),
            additional: Some(additional),
        }
    }

    pub fn get_packet(&self) -> Vec<u8> {
        let mut res = vec![];
        res.extend_from_slice(&self.header.id.to_be_bytes());
        res.extend_from_slice(&self.header.flags.to_be_bytes());
        res.extend_from_slice(&self.header.qdcount.to_be_bytes());
        res.extend_from_slice(&self.header.ancount.to_be_bytes());
        res.extend_from_slice(&self.header.nscount.to_be_bytes());
        res.extend_from_slice(&self.header.arcount.to_be_bytes());
        for question in &self.question {
            res.extend_from_slice(&question.qname);
            res.extend_from_slice(&question.qtype.to_be_bytes());
            res.extend_from_slice(&question.qclass.to_be_bytes());
        }
        res
    }

    pub fn send(&self) -> Result<Message, Box<dyn Error>> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:12321")?;

        let data = self.get_packet();

        socket.send_to(&data, "1.1.1.1")?;

        let mut buf = [0; 8192];
        let (amt, _) = socket.recv_from(&mut buf)?;

        let res = Message::from(buf[..amt].to_vec());

        Ok(res)
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct Header {
    /// A 16 bit identifier assigned by the program that
    /// generates any kind of query.
    /// This identifier is copied the corresponding reply and can be used by the requester
    /// to match up replies to outstanding queries.
    pub id: u16,
    /// See the [`Header::set_flags()`] method for more information.
    flags: u16,
    /// An unsigned 16 bit integer specifying the number of
    /// entries in the question section.
    pub qdcount: u16,
    /// an unsigned 16 bit integer specifying the number of
    /// resource records in the answer section.
    pub ancount: u16,
    /// an unsigned 16 bit integer specifying the number of name
    /// server resource records in the authority records
    /// section.
    pub nscount: u16,
    /// an unsigned 16 bit integer specifying the number of
    /// resource records in the additional records section.
    pub arcount: u16,
}
impl Header {
    /// # Creates a new DnsOption
    ///
    /// # Example
    ///
    /// ```
    /// use dns::Header;
    ///
    /// let options = Header::new();
    /// ```
    ///
    /// # Note
    ///
    /// This method creates a new DnsOption with the following default values:
    ///
    /// - id: 0
    /// - flags: 0
    /// - question: Vec::new()
    /// - qdcount: 0
    /// - ancount: 0
    /// - nscount: 0
    /// - arcount: 0
    /// - qtype: 0
    /// - qclass: 0
    pub fn new() -> Header {
        Header {
            id: 0,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// # Sets the id
    ///
    /// # Arguments
    ///
    /// takes 1 u16 argument.
    ///
    /// # Example
    ///
    /// ```
    /// use dns::Header;
    ///
    /// let mut options = Header::new();
    /// options.set_id(1234);
    /// ```
    pub fn set_id(&mut self, id: u16) {
        self.id = id;
    }
    /// # Sets the request flags
    ///
    /// # Arguments
    ///
    /// takes 1 u16 argument with the following format:
    ///
    /// - 1 bit: QR (Query/Response)
    ///
    ///    A one bit field that specifies whether this message is a query (0),
    ///    or a response (1).   
    /// <br />
    ///
    /// - 4 bits: Opcode
    ///     A four bit field that specifies kind of query in this
    ///     message.  This value is set by the originator of a query
    ///     and copied into the response.  The values are:
    ///     
    ///     - `0`:               a standard query (QUERY)
    ///     
    ///     - `1`:               an inverse query (IQUERY)
    ///     
    ///     - `2`:               a server status request (STATUS)
    ///     
    ///     - `3-15`:            reserved for future use
    ///
    /// DNS Header Flags
    /// [(source)](https://www.rfc-editor.org/rfc/rfc1035.html)
    ///
    /// - 1 bit: AA (Authoritative Answer)
    ///
    ///     Authoritative Answer - this bit is valid in responses,
    ///     and specifies that the responding name server is an
    ///     authority for the domain name in question section.
    ///     Note that the contents of the answer section may
    ///     have multiple owner names because of aliases.   
    ///<br />
    /// - 1 bit: TC (Truncated)
    ///
    ///     TrunCation - specifies that this message was truncated
    /// due to length greater than that permitted on the transmission
    /// channel.  
    ///<br />
    /// - 1 bit: RD (Recursion Desired)
    ///
    ///     Recursion Desired - this bit may be set in a query and
    ///     is copied into the response.  If RD is set, it directs
    ///     the name server to pursue the query recursively.
    ///     Recursive query support is optional.  
    ///<br />
    /// - 1 bit: RA (Recursion Available)
    ///
    ///     Recursion Available - this be is set or cleared in
    ///     a response, and denotes whether recursive query
    ///     support is available in the name server.  
    ///<br />
    /// - 3 bits: Z (Reserved)
    ///
    ///     Reserved for future use.  Must be zero in all
    ///     queries and responses.  
    ///<br />
    /// - 4 bits: RCODE (Response Code)
    ///
    ///     Response code - this 4 bit field is set as part of responses.  The values have the following interpretation:
    ///
    ///     - `0`:       No error condition
    ///
    ///     - `1`:      Format error - The name server was
    ///                 unable to interpret the query.
    ///
    ///     - `2`:       Server failure - The name server was
    ///                 unable to process this query due to a
    ///                 problem with the name server.
    ///
    ///     - `3`:       Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    ///
    ///     - `4`:       Not Implemented - The name server does not support the requested kind of query.
    ///
    ///     - `5`:       Refused - The name server refuses to perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
    ///
    ///     - `6-15`:    Reserved for future use.
    ///
    /// # Example
    ///
    /// ```
    /// use dns::Header;
    ///
    /// let mut options = Header::new();
    /// options.set_flags(0b0000_0000_0000_0000);
    /// ```
    pub fn set_flags(&mut self, flags: u16) -> Result<(), Box<dyn Error>> {
        let mut test = flags & 0b0_1111_000_0000_0000;
        test = test >> 11;
        if test > 2 {
            return Err(Box::new(DnsError::InvalidOpcodeFlag(test as i32)));
        }
        test = flags & 0b0000_0000_0111_0000;
        test = test >> 4;
        if test != 0 {
            return Err(Box::new(DnsError::InvalidZFlag(test as i32)));
        }
        let test = flags & 0b0000_0000_0000_1111;
        if test > 5 {
            return Err(Box::new(DnsError::InvalidRcodeFlag(test as i32)));
        }
        self.flags = flags;
        Ok(())
    }
}
impl Default for Header {
    fn default() -> Self {
        Header::new()
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct Question {
    /// a domain name represented as a sequence of labels, where
    /// each label consists of a length octet followed by that
    /// number of octets.  The domain name terminates with the
    /// zero length octet for the null label of the root.  Note
    /// that this field may be an odd number of octets; no
    /// padding is used.
    qname: Vec<u8>,
    ///  a two octet code which specifies the type of the query.
    ///  The values for this field include all codes valid for a
    ///  TYPE field, together with some more general codes which
    ///  can match more than one type of RR.
    pub qtype: u16,     // ! TODO add seter with checks
    /// a two octet code that specifies the class of the query.
    /// For example, the QCLASS field is IN for the Internet.
    pub qclass: u16,    // ! TODO add seter with checks
}
impl Question {
    /// # Creates a new Question
    ///
    /// # Example
    ///
    /// ```
    /// use dns::Question;
    ///
    /// let question = Question::new();
    /// ```
    pub fn new() -> Question {
        Question {
            qname: Vec::new(),
            qtype: 0,
            qclass: 0,
        }
    }
}

/// The answer, authority, and additional sections all share the same
/// format: a variable number of resource records, where the number of
/// records is specified in the corresponding count field in the header.
/// Each resource record has the following format:
#[allow(unused)]
#[derive(Debug)]
pub struct Resource {
    /// a domain name to which this resource record pertains.
    name: Vec<u8>,
    /// two octets containing one of the RR type codes.  This
    /// field specifies the meaning of the data in the RDATA field.
    rtype: u16,
    /// two octets which specify the class of the data in the RDATA field.
    rclass: u16,
    /// a 32 bit unsigned integer that specifies the time
    /// interval (in seconds) that the resource record may be
    /// cached before it should be discarded.  Zero values are
    /// interpreted to mean that the RR can only be used for the
    /// transaction in progress, and should not be cached.
    ttl: u32,
    /// an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    rdlength: u16,
    /// a variable length string of octets that describes the
    /// resource.  The format of this information varies
    /// according to the TYPE and CLASS of the resource record.
    /// For example, the if the TYPE is A and the CLASS is IN,
    /// the RDATA field is a 4 octet ARPA Internet address.
    rdata: Vec<u8>,
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_set_questions() {
        let mut options = Message::new();
        options.set_questions(vec!["www.google.com".to_string()]);
        println!("{:#?}", options);
        assert_eq!(
            options.question[0].qname,
            vec![3, 119, 119, 119, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0]
        )
    }

    #[test]
    fn header_set_flags() {
        let mut options = Header::new();
        options.set_flags(0b0000_0000_0000_0000).unwrap();
        assert_eq!(options.flags, 0b0000_0000_0000_0000);
    }

    #[test]
    #[should_panic]
    fn header_dosnt_allow_wrong_opcode() {
        let mut options = Header::new();
        options.set_flags(0b0111_1000_0000_0000).unwrap();
    }

    #[test]
    #[should_panic]
    fn header_dosnt_allow_wrong_z() {
        let mut options = Header::new();
        options.set_flags(0b0000_0000_0000_1111).unwrap();
    }

    
}
