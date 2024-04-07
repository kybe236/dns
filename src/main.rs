use std::{error::Error, vec};

use dns::*;

fn main() -> Result<(), Box<dyn Error>> {
    let mut dns = Message::new();
    dns.set_questions(vec![String::from("www.google.com")]);
    dns.question[0].set_qtype(1)?;
    dns.question[0].set_qclass(1)?;
    let res = dns.send()?;
    println!("{:#?}", res);
    Ok(())
}