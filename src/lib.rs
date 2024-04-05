//! DNS Client in Development
//!
//! # Goals
//! Make an dns client that supports all dns options.

pub fn dns(options: DnsOption) {
    println!("DNS lookup for {:#?}", options);
}

#[derive(Debug)]
pub struct DnsOption {
    /// A 16 bit identifier assigned by the program that
    /// generates any kind of query.
    /// This identifier is copied the corresponding reply and can be used by the requester
    /// to match up replies to outstanding queries.
    id: u16,
    /// See the [`DnsOption::set_flags()`] method for more information.
    flags: u16,
    /// See [`Question`] for more information.
    question: Vec<Question>,
    /// An unsigned 16 bit integer specifying the number of
    /// entries in the question section.
    qdcount: u16,
    /// an unsigned 16 bit integer specifying the number of
    /// resource records in the answer section.
    ancount: u16,
    /// an unsigned 16 bit integer specifying the number of name
    /// server resource records in the authority records
    /// section.
    nscount: u16,
    /// an unsigned 16 bit integer specifying the number of
    /// resource records in the additional records section.
    arcount: u16,
    qtype: u16,
    qclass: u16,
}

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
    qtype: u16,
    /// a two octet code that specifies the class of the query.
    /// For example, the QCLASS field is IN for the Internet.
    qclass: u16,
}

impl DnsOption {
    /// # Creates a new DnsOption
    /// 
    /// # Example
    /// 
    /// ```
    /// use dns::DnsOption;
    /// 
    /// let options = DnsOption::new();
    /// ```
    pub fn new() -> DnsOption {
        DnsOption {
            id: 0,
            flags: 0,
            question: Vec::new(),
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            qtype: 0,
            qclass: 0,
        }
    }
    pub fn set_name(&mut self, name: Vec<String>) {
        let mut res = vec![];
        for label in name {
            let parts = label.split(".");
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
        self.question.push(Question {
            qname: res,
            qtype: 1,
            qclass: 1,
        });
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
    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns() {
        let mut options = DnsOption::new();
        options.set_name(vec!["www.google.com".to_string()]);
        println!("{:#?}", options);
        assert_eq!(options.question[0].qname, vec![3, 119, 119, 119, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0])
    }
}