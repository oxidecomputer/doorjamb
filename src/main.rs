use std::{sync::Arc, thread::JoinHandle};

use anyhow::Result;
pub use args::*;
use client::DoorClient;
use server::DoorServer;

mod args;
pub mod client;
pub mod server;
#[allow(unused)]
mod sys;
mod threads;
mod upanic;

fn main() -> Result<()> {
    let door = "/tmp/THEDOOR";

    let opts = getopts::Options::new()
        .optflag("c", "", "be the client")
        .optflag("t", "", "be a LOT of clients")
        .parsing_style(getopts::ParsingStyle::StopAtFirstFree)
        .parse(std::env::args().skip(1))?;

    if opts.opt_present("t") {
        let dc = Arc::new(DoorClient::new(door)?);

        let threads: Vec<JoinHandle<String>> = (0..16)
            .map(|thr| {
                let dc = Arc::clone(&dc);
                std::thread::spawn(move || loop {
                    match dc.call() {
                        Ok(r) => println!("{thr}: res = {:?}", r.as_bytes()),
                        Err(e) => return format!("ERROR: {e}"),
                    }
                })
            })
            .collect::<Vec<_>>();

        for t in threads {
            t.join().unwrap();
        }

        return Ok(());
    }

    if opts.opt_present("c") {
        let dc = DoorClient::new(door)?;
        let res = dc.call()?;
        println!("res = {:?}", res.as_bytes());
        return Ok(());
    }

    let d = DoorServer::new(|mut a| {
        println!("door call! {:?}", a.as_bytes());

        //a.make_return().string("abcdef")

        a.make_return().raw(|buf| {
            buf[25] = b'A';
            26
        })

        //a.make_return().return_u64(0x0000000504030201)
    })?;

    d.force_attach("/tmp/THEDOOR")?;

    println!("door server started; pid {}", std::process::id());

    {
        /*
         * Can we call our own door server?
         */
        println!("---- own server:");

        let dc = d.self_client()?;
        for _ in 0..5 {
            let res = dc.call()?;

            println!("    result: {:?}", res.as_bytes());
        }
        drop(dc);

        println!("---- own server^");
    }

    println!("waiting for unref...");
    d.wait_for_unref();

    println!("closing threads...");
    d.revoke()?;

    Ok(())
}
