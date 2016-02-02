#![crate_name = "hwclient"]
extern crate zmq;

fn main() {
    println!("Connecting to hello world server...");
    let mut context = zmq::Context::new().unwrap();
    let mut requester = context.socket(zmq::REQ).unwrap();
    requester.connect("tcp://localhost:5555").unwrap();

    for request_nbr in 0..10 {
        let mut buffer: Vec<u8> = Vec::with_capacity(10);
        println!("Sending Hello {}...", request_nbr);
        requester.send_bytes("Hello".as_bytes(), 0).unwrap();
        requester.recv_bytes_into_slice(&mut buffer, 0).unwrap();
        println!("Received World {}", request_nbr);
    }
    requester.close();
    context.shutdown().unwrap();
}
