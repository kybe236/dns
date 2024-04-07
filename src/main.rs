use std::{error::Error, vec};

use dns::*;

fn main() -> Result<(), Box<dyn Error>> {
    let mut dns = Message::new();
    dns.set_questions(vec![String::from("_minecraft._tcp.GrieferGames.de")])?;
    dns.question[0].set_qtype(33)?;
    dns.question[0].set_qclass(1)?;
    let res = dns.send()?;
    println!("{:#?}", res);
    Ok(())
}