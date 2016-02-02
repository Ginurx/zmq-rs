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
fn capability_test() {
    zmq::has_capability("ipc");
    zmq::has_capability("pgm");
    zmq::has_capability("tipc");
    zmq::has_capability("norm");
    zmq::has_capability("curve");
    zmq::has_capability("gssapi");
}

#[test]
fn context_test() {
    let mut ctx = zmq::Context::new().unwrap();

    ctx.set_io_threads(2).unwrap();
    ctx.set_max_sockets(10).unwrap();
    ctx.set_ipv6(1).unwrap();

    ctx.get_io_threads().unwrap();
    ctx.get_max_sockets().unwrap();
    ctx.get_socket_limit().unwrap();
    ctx.is_ipv6_enabled().unwrap();

    ctx.shutdown().unwrap();
}

#[test]
fn message_test() {
    let empty = zmq::Message::new().unwrap();
    zmq::Message::with_capcity(1024).unwrap();
    zmq::Message::from_vec(vec![1,2,3,4,5,6]).unwrap();
    zmq::Message::from_slice(&vec![1,2,3,4,5,6]).unwrap();

    let mut src = zmq::Message::from_slice("message_move_src".as_bytes()).unwrap();
    let mut dst = zmq::Message::new().unwrap();

    zmq::Message::msg_move(&mut dst, &mut src).unwrap();

    unsafe {
        let slice = std::slice::from_raw_parts(dst.get_data_ptr(), dst.len());
        let s = std::str::from_utf8(std::mem::transmute(slice)).unwrap();
        assert_eq!(s, "message_move_src");
    }

    let src = zmq::Message::from_slice("message_copy_src".as_bytes()).unwrap();
    let mut dst = zmq::Message::new().unwrap();

    zmq::Message::msg_copy(&mut dst, &src).unwrap();
    unsafe {
        let slice = std::slice::from_raw_parts(dst.get_data_ptr(), dst.len());
        let s = std::str::from_utf8(std::mem::transmute(slice)).unwrap();
        assert_eq!(s, "message_copy_src");
    }

    assert_eq!(empty.has_more(), false);
    empty.get_property(zmq::MORE).unwrap();
    //empty.get_property(zmq::SRCFD).unwrap();
    empty.get_property(zmq::SHARED).unwrap();

    empty.get_meta("Socket-Type").is_some();
    empty.get_meta("Identity").is_some();
    empty.get_meta("Resource").is_some();
}

#[test]
fn socket_test() {
    let mut ctx = zmq::Context::new().unwrap();

    let mut req = ctx.socket(zmq::REQ).unwrap();
    let mut rep = ctx.socket(zmq::REP).unwrap();

    let bindpoint = "inproc://test";
    rep.bind(bindpoint).unwrap();
    req.connect(bindpoint).unwrap();

    let msg = zmq::Message::from_slice("req".as_bytes()).unwrap();
    req.send_msg(msg, 0).unwrap();
    let _recv_msg = rep.recv_msg(0).unwrap();

    rep.send_str("str", 0 ).unwrap();
    let recv_str = req.recv_string(0).unwrap().unwrap();
    assert_eq!(&recv_str, "str");

    rep.unbind(bindpoint).unwrap();
    req.disconnect(bindpoint).unwrap();

    req.close().unwrap();
    rep.close().unwrap();

    ctx.shutdown().unwrap();
}
