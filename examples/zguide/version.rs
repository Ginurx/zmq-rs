#![crate_name = "version"]
extern crate zmq_rs as zmq;

fn main() {
    let (major, minor, patch) = zmq::version();
    println!("Current 0MQ version is {}.{}.{}", major, minor, patch);
}
