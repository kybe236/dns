use std::vec;

use dns::*;

fn main() {
    let mut dns = Message::new();
    dns.set_questions(vec![String::from("www.google.com")]);
    dns.question[0].qtype = 1;
    dns.question[0].qclass = 1;
    
}