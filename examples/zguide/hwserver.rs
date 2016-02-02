#![crate_name = "hwserver"]
extern crate zmq;

use std::time::Duration;
use std::thread::sleep;

fn main() {
    let mut context = zmq::Context::new().unwrap();
    let mut responder = context.socket(zmq::REP).unwrap();
    responder.bind("tcp://*:5555").unwrap();

    loop {
        let mut buffer: Vec<u8> = Vec::with_capacity(10);
        responder.recv_bytes_into_slice(&mut buffer, 0).unwrap();
        println!("Received Hello");
        sleep(Duration::from_secs(1));
        responder.send_bytes("World".as_bytes(), 0).unwrap();
    }
}
