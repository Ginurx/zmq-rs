#[macro_use]
extern crate zmq;

#[test]
fn version_test() {
    let (major, minor, patch) = zmq::version();
    assert!(
        ZMQ_MAKE_VERSION!(major, minor, patch) >=
        ZMQ_MAKE_VERSION!(4, 1, 4)
    );
}

#[test]
fn context_test() {
    let mut ctx = zmq::Context::new().unwrap();

    ctx.shutdown().unwrap();
}
