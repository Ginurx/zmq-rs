use std::mem::transmute;
use std::ffi;
use super::*;
use libc::{ c_int, c_void, size_t, c_short, c_long };
use ::std;
use ::zmq_sys;

fn bytes_to_string(bytes: Vec<u8>) -> String {
    unsafe { ffi::CStr::from_ptr(transmute(bytes.as_ptr())).to_str().unwrap().to_string() }
}

fn str_to_cstr_bytes(s: &str) -> Vec<u8> {
    let cstr = ffi::CString::new(s).unwrap();
    //cstr.into_bytes_with_nul()            // currently unstable
    cstr.as_bytes_with_nul().to_vec()
}

macro_rules! getsockopt_template(
    // function name to declare, option name, query/return type
    ($name: ident, $opt: expr, $t: ty) => {
        fn $name(&self) -> Result<$t, Error> {
            let mut optval: $t = std::default::Default::default();
            let mut optval_len: size_t = std::mem::size_of::<$t>() as size_t;
            let optval_ptr = &mut optval as *mut $t;

            let rc = unsafe { zmq_sys::zmq_getsockopt(self.socket, $opt as c_int, transmute(optval_ptr), &mut optval_len) };
            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                Ok(optval)
            }
        }
    };
    // function name to declare, option name, query type, query count, map queried value to return value, return type
    ($name: ident, $opt: expr, $t: ty, $n: expr, $rmap: expr, $r: ty) => {
        fn $name(&self) -> Result<$r, Error> {
            let mut optval: Vec<$t> = Vec::with_capacity($n);

            let mut optval_len: size_t = (optval.capacity() * std::mem::size_of::<$t>()) as size_t;
            let optval_ptr = optval.as_mut_ptr();

            let rc = unsafe {
                zmq_sys::zmq_getsockopt(self.socket, $opt as c_int,
                    transmute(optval_ptr), &mut optval_len)
            };

            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                unsafe { optval.set_len(optval_len); }
                Ok($rmap(optval))
            }
        }
    };
    // function name to declare, option name, query type, map queried value to return value, return type
    ($name: ident, $opt: expr, $t: ty, $rmap: expr, $r: ty) => {
        fn $name(&self) -> Result<$r, Error> {
            let mut optval: $t = std::default::Default::default();
            let mut optval_len: size_t = std::mem::size_of::<$t>() as size_t;
            let optval_ptr = &mut optval as *mut $t;

            let rc = unsafe { zmq_sys::zmq_getsockopt(self.socket, $opt as c_int, transmute(optval_ptr), &mut optval_len) };
            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                Ok($rmap(optval))
            }
        }
    };
    // function name to declare, option name, query type, query count
    ($name: ident, $opt: expr, $t: ty, $n: expr) => {
        fn $name(&self) -> Result<Vec<$t>, Error> {
            let mut optval: Vec<$t> = Vec::with_capacity($n);

            let mut optval_len: size_t = (optval.capacity() * std::mem::size_of::<$t>()) as size_t;
            let optval_ptr = optval.as_mut_ptr();

            let rc = unsafe {
                zmq_sys::zmq_getsockopt(self.socket, $opt as c_int,
                    transmute(optval_ptr), &mut optval_len)
            };

            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                unsafe { optval.set_len(optval_len); }
                Ok(optval)
            }
        }
    };
);

macro_rules! setsockopt_nullptr_template(
    ($name: ident, $opt: expr) => {
        fn $name(&self) -> Result<(), Error> {
            let optval_len: size_t = 0;
            let optval_ptr: *const u8 = std::ptr::null();

            let rc = unsafe {
                zmq_sys::zmq_setsockopt(self.socket, $opt as c_int,
                    transmute(optval_ptr), optval_len)
            };

            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                Ok(())
            }
        }
    };
);

macro_rules! setsockopt_template(
    // function name to declare, option name, optval type
    ($name: ident, $opt: expr, $t: ty) => {
        fn $name(&self, optval: &$t) -> Result<(), Error> {
            let optval_len: size_t = std::mem::size_of::<$t>() as size_t;
            let optval_ptr = optval as *const $t;

            let rc = unsafe { zmq_sys::zmq_setsockopt(self.socket, $opt as c_int, transmute(optval_ptr), optval_len) };
            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                Ok(())
            }
        }
    };

    // function name to declare, option name
    ($name: ident, $opt: expr) => {
        fn $name(&self, optval: &[u8]) -> Result<(), Error> {
            let optval_len: size_t = optval.len() as size_t;
            let optval_ptr: *const u8 = optval.as_ptr();

            let rc = unsafe {
                zmq_sys::zmq_setsockopt(self.socket, $opt as c_int,
                    transmute(optval_ptr), optval_len)
            };

            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                Ok(())
            }
        }
    };

    ($name: ident, $opt: expr, $t: ty, $map: expr) => {
        fn $name(&self, optval: $t) -> Result<(), Error> {
            let optval: Vec<u8> = $map(optval);
            let optval_len: size_t = optval.len() as size_t;

            let optval_ptr: *const u8 = optval.as_ptr();

            let rc = unsafe {
                zmq_sys::zmq_setsockopt(self.socket, $opt as c_int,
                    transmute(optval_ptr), optval_len)
            };

            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                Ok(())
            }
        }
    };
);

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
enum SocketOption {
    AFFINITY = 4,
    IDENTITY = 5,
    SUBSCRIBE = 6,
    UNSUBSCRIBE = 7,
    RATE = 8,
    RECOVERY_IVL = 9,
    SNDBUF = 11,
    RCVBUF = 12,
    RCVMORE = 13,
    FD = 14,
    EVENTS = 15,
    TYPE = 16,
    LINGER = 17,
    RECONNECT_IVL = 18,
    BACKLOG = 19,
    RECONNECT_IVL_MAX = 21,
    MAXMSGSIZE = 22,
    SNDHWM = 23,
    RCVHWM = 24,
    MULTICAST_HOPS = 25,
    RCVTIMEO = 27,
    SNDTIMEO = 28,
    LAST_ENDPOINT = 32,
    ROUTER_MANDATORY = 33,
    TCP_KEEPALIVE = 34,
    TCP_KEEPALIVE_CNT = 35,
    TCP_KEEPALIVE_IDLE = 36,
    TCP_KEEPALIVE_INTVL = 37,
    IMMEDIATE = 39,
    XPUB_VERBOSE = 40,
    ROUTER_RAW = 41,
    IPV6 = 42,
    MECHANISM = 43,
    PLAIN_SERVER = 44,
    PLAIN_USERNAME = 45,
    PLAIN_PASSWORD = 46,
    CURVE_SERVER = 47,
    CURVE_PUBLICKEY = 48,
    CURVE_SECRETKEY = 49,
    CURVE_SERVERKEY = 50,
    PROBE_ROUTER = 51,
    REQ_CORRELATE = 52,
    REQ_RELAXED = 53,
    CONFLATE = 54,
    ZAP_DOMAIN = 55,
    ROUTER_HANDOVER = 56,
    TOS = 57,
    CONNECT_RID = 61,
    GSSAPI_SERVER = 62,
    GSSAPI_PRINCIPAL = 63,
    GSSAPI_SERVICE_PRINCIPAL = 64,
    GSSAPI_PLAINTEXT = 65,
    HANDSHAKE_IVL = 66,
    SOCKS_PROXY = 68,
    XPUB_NODROP = 69,
}

pub struct Socket {
    socket: *mut c_void,
}

// todo: zmq_msg_send, zmq_msg_recv
impl Socket {
    pub fn from_raw(socket: *mut c_void) -> Socket {
        Socket { socket: socket }
    }

    /// Close 0MQ socket
    ///
    /// Binding of `int zmq_close (void *s);`
    ///
    /// It's not mandatory to call this function since socket can be closed automatically on dropping
    /// The function will destroy this socket.
    /// Any outstanding messages physically received from the network
    /// but not yet received by the application with recv() shall be discarded.
    /// The behaviour for discarding messages sent by the application with send()
    /// but not yet physically transferred to the network depends on the value of
    /// the ZMQ_LINGER socket option for the specified socket.
    pub fn close(self) {
        drop(self)
    }

    fn close_underly(&mut self) {
        let rc = unsafe { zmq_sys::zmq_close(self.socket) };
        if rc == -1 {
            panic!(Error::from_last_err());
        }
    }

    ///  Accept incoming connections on a socket
    ///
    /// Binding of `int zmq_bind (void *socket, const char *endpoint);`
    ///
    /// The function binds the socket to a local endpoint and then accepts incoming connections on that endpoint.
    pub fn bind(&mut self, endpoint: &str) -> Result<(), Error> {
        let endpoint_cstr = ffi::CString::new(endpoint).unwrap();
        let rc = unsafe { zmq_sys::zmq_bind(self.socket, endpoint_cstr.as_ptr()) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Create outgoing connection from socket
    ///
    /// Binding of `int zmq_connect (void *socket, const char *endpoint);`
    ///
    /// The function connects the socket to an endpoint and then accepts incoming connections on that endpoint.
    pub fn connect(&mut self, endpoint: &str) -> Result<(), Error> {
        let endpoint_cstr = ffi::CString::new(endpoint).unwrap();
        let rc = unsafe { zmq_sys::zmq_connect(self.socket, endpoint_cstr.as_ptr()) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Stop accepting connections on a socket
    ///
    /// Binding of `int zmq_unbind (void *socket, const char *endpoint);`
    ///
    /// The function will unbind a socket specified by the socket argument from the endpoint specified by the endpoint argument.
    pub fn unbind(&mut self, endpoint: &str) -> Result<(), Error> {
        let endpoint_cstr = ffi::CString::new(endpoint).unwrap();
        let rc = unsafe { zmq_sys::zmq_unbind(self.socket, endpoint_cstr.as_ptr()) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Disconnect a socket
    ///
    /// Binding of `int zmq_disconnect (void *socket, const char *endpoint);`
    ///
    /// The function will disconnect socket from the endpoint specified by the endpoint argument.
    /// Any outstanding messages physically received from the network but not yet received by the application with recv() will be discarded.
    /// The behaviour for discarding messages sent by the application with send() but
    /// not yet physically transferred to the network depends on the value of the ZMQ_LINGER socket option for the socket.
    pub fn disconnect(&mut self, endpoint: &str) -> Result<(), Error> {
        let endpoint_cstr = ffi::CString::new(endpoint).unwrap();
        let rc = unsafe { zmq_sys::zmq_disconnect(self.socket, endpoint_cstr.as_ptr()) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Send a message part on a socket
    ///
    /// Binding of `int zmq_msg_send (zmq_msg_t *msg, void *socket, int flags);`
    pub fn send_msg(&mut self, mut msg: Message, flags: SocketFlag) -> Result<i32, Error> {
        let rc = unsafe { zmq_sys::zmq_msg_send(&mut msg.msg, self.socket, flags.into_raw() as c_int) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(rc)
        }
    }

    /// Receive a message part from a socket
    ///
    /// Binding of `int zmq_msg_recv (zmq_msg_t *msg, void *socket, int flags);`
    pub fn recv_into_msg(&mut self, msg: &mut Message, flags: SocketFlag) -> Result<i32, Error> {
        let rc = unsafe { zmq_sys::zmq_msg_recv(&mut msg.msg, self.socket, flags.into_raw() as c_int) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(rc)
        }
    }

    /// Receive a message part from a socket
    ///
    /// Binding of `int zmq_msg_recv (zmq_msg_t *msg, void *socket, int flags);`
    pub fn recv_msg(&mut self, flags: SocketFlag) -> Result<Message, Error> {
        let mut msg = try!(Message::new());
        match self.recv_into_msg(&mut msg, flags) {
            Ok(_) => Ok(msg),
            Err(e) => Err(e),
        }
    }

    /// Send bytes on a socket
    ///
    /// Data will be copied into a Message object in order to be sent.
    pub fn send_bytes(&mut self, data: &[u8], flags: SocketFlag) -> Result<i32, Error> {
        let msg = try!(Message::from_slice(data));
        self.send_msg(msg, flags)
    }

    /// Send a constant-memory message part on a socket
    ///
    /// Binding of `ZMQ_EXPORT int zmq_send_const (void *s, const void *buf, size_t len, int flags);`
    ///
    /// The message buffer is assumed to be constant-memory(static) and will therefore not be copied or deallocated in any way
    pub fn send_const_bytes(&mut self, data: &'static [u8], flags: SocketFlag) -> Result<i32, Error> {
        let rc = unsafe { zmq_sys::zmq_send_const(self.socket, transmute(data.as_ptr()), data.len(), flags.into_raw()) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(rc)
        }
    }

    /// Send a UTF-8 string on socket
    pub fn send_str(&mut self, data: &str, flags: SocketFlag) -> Result<i32, Error> {
        self.send_bytes(data.as_bytes(), flags)
    }

    /// Receive bytes from a socket
    pub fn recv_bytes(&mut self, flags: SocketFlag) -> Result<Vec<u8>, Error> {
        match self.recv_msg(flags) {
            Ok(msg) => Ok(msg.to_vec()),
            Err(e) => Err(e),
        }
    }

    /// Receive bytes into a mutable slice
    /// # Caution
    /// *Any bytes exceeding the length of buffer will be truncated.*
    pub fn recv_bytes_into_slice(&mut self, buffer: &mut [u8], flags: SocketFlag) -> Result<i32, Error> {
        let rc = unsafe { zmq_sys::zmq_recv(self.socket, transmute(buffer.as_mut_ptr()), buffer.len(), flags.into_raw()) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(rc)
        }
    }

    /// Receive a UTF-8 string from socket
    pub fn recv_string(&mut self, flags: SocketFlag) -> Result<Result<String, Vec<u8>>, Error> {
        match self.recv_bytes(flags) {
            Ok(msg) => {
                Ok({
                    let s = String::from_utf8(msg);
                    if s.is_ok() {
                        Ok(s.unwrap())
                    } else {
                        Err(s.unwrap_err().into_bytes())
                    }
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Monitor socket events
    ///
    /// Binding of `int zmq_socket_monitor (void *socket, char *endpoint, int events);`
    ///
    /// The method lets an application thread track socket events (like connects) on a ZeroMQ socket
    pub fn socket_monitor(&mut self, endpoint: &str, events: &Vec<SocketEvent>) -> Result<(), Error> {
        let mut event_mask: i32 = 0;
        for event in events {
            event_mask |= Clone::clone(event) as i32;
        }

        let endpoint_cstr = ffi::CString::new(endpoint).unwrap();
        let rc = unsafe { zmq_sys::zmq_socket_monitor(self.socket, endpoint_cstr.as_ptr(), event_mask) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Start built-in 0MQ proxy
    ///
    /// Binding of `int zmq_proxy (const void *frontend, const void *backend, const void *capture);`
    ///
    /// The function starts the built-in ØMQ proxy in the current application thread.
    pub fn run_proxy(frontend: &mut Socket, backend: &mut Socket) -> Result<(), Error> {
        let rc = unsafe { zmq_sys::zmq_proxy(frontend.socket, backend.socket, std::ptr::null_mut()) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Start built-in 0MQ proxy
    ///
    /// Binding of `int zmq_proxy (const void *frontend, const void *backend, const void *capture);` or
    /// `int zmq_proxy_steerable (const void *frontend, const void *backend, const void *capture, const void *control);`
    ///
    /// The function starts the built-in ØMQ proxy in the current application thread.
    /// The proxy will send all messages, received on both frontend and backend, to the capture socket.
    /// The capture socket should be a ZMQ_PUB, ZMQ_DEALER, ZMQ_PUSH, or ZMQ_PAIR socket.
    /// If the control socket is not None, the proxy supports control flow.
    /// If PAUSE is received on this socket, the proxy suspends its activities.
    /// If RESUME is received, it goes on. If TERMINATE is received, it terminates smoothly.
    /// At start, the proxy runs normally as if run_proxy was used.
    pub fn run_proxy_ex(frontend: &mut Socket, backend: &mut Socket,
    capture: Option<&mut Socket>, control: Option<&mut Socket>) -> Result<(), Error> {
        let capture_ptr = if capture.is_none() { std::ptr::null_mut() } else { capture.unwrap().socket };

        let rc = {
            if control.is_none() {
                unsafe { zmq_sys::zmq_proxy(frontend.socket, backend.socket, capture_ptr) }
            } else {
                unsafe { zmq_sys::zmq_proxy_steerable(frontend.socket, backend.socket, capture_ptr, control.unwrap().socket) }
            }
        };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Create a poll item from current socket
    ///
    /// # Safty
    /// There is no lifetime guarantee that poll item does not live out socket
    pub fn as_poll_item(&self) -> PollItem {
        PollItem::from_socket(&self)
    }

    ///  input/output multiplexing
    ///
    /// Binding of `int zmq_poll (zmq_pollitem_t *items, int nitems, long timeout);`
    pub fn poll(items: &mut [PollItem], nitems: i32, timeout: i32) -> Result<i32, Error> {
        let rc = unsafe { zmq_sys::zmq_poll(transmute(items.as_mut_ptr()), nitems as c_int, timeout as c_long) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(rc)
        }
    }

    //-------------------------------- get options ----------------------------------- //

    getsockopt_template!(get_affinity, SocketOption::AFFINITY, u64);
    getsockopt_template!(get_backlog, SocketOption::BACKLOG, i32);
    getsockopt_template!(get_curve_publickey, SocketOption::CURVE_PUBLICKEY, u8, 32);
    getsockopt_template!(get_curve_printable_publickey, SocketOption::CURVE_PUBLICKEY, u8, 41,
        |r: Vec<u8>| {
            bytes_to_string(r)
        }, String);
    getsockopt_template!(get_curve_secretkey, SocketOption::CURVE_SECRETKEY, u8, 32);
    getsockopt_template!(get_curve_printable_secretkey, SocketOption::CURVE_SECRETKEY, u8, 41,
        |r: Vec<u8>| {
            bytes_to_string(r)
        }, String);
    getsockopt_template!(get_curve_serverkey, SocketOption::CURVE_SERVERKEY, u8, 32);
    getsockopt_template!(get_curve_printable_serverkey, SocketOption::CURVE_SERVERKEY, u8, 41,
        |r: Vec<u8>| {
            bytes_to_string(r)
        }, String);
    getsockopt_template!(get_events, SocketOption::EVENTS, PollEvent);
    getsockopt_template!(get_fd, SocketOption::FD, SocketFd);
    getsockopt_template!(is_gssapi_plaintext, SocketOption::GSSAPI_PLAINTEXT, i32, |r| { r > 0 }, bool);
    getsockopt_template!(get_gssapi_principal, SocketOption::GSSAPI_PRINCIPAL, u8, 256,
        |r: Vec<u8>| {
            bytes_to_string(r)
        }, String);
    getsockopt_template!(is_gssapi_server, SocketOption::GSSAPI_SERVER, i32, |r| { r > 0 }, bool);
    getsockopt_template!(get_gssapi_service_principal, SocketOption::GSSAPI_SERVICE_PRINCIPAL, u8, 256,
        |r: Vec<u8>| {
            bytes_to_string(r)
        }, String);
    getsockopt_template!(get_handshake_ivl, SocketOption::HANDSHAKE_IVL, i32);
    getsockopt_template!(get_identity, SocketOption::IDENTITY, u8, 256);
    getsockopt_template!(is_immediate, SocketOption::IMMEDIATE, i32, |r| { r > 0 }, bool);
    //getsockopt_template!(get_ipv4only, SocketOption::IPV4ONLY, i32);      // deprecated
    getsockopt_template!(is_ipv6_enabled, SocketOption::IPV6, i32, |r| { r > 0 }, bool);
    /// Get last endpoint bound for TCP and IPC transports
    /// if last endpoint has more than 2048 bytes, method call will be failed.
    getsockopt_template!(get_last_endpoint, SocketOption::LAST_ENDPOINT, u8, 2048,
        |r: Vec<u8>| {
            bytes_to_string(r)
        }, String);
    getsockopt_template!(get_linger, SocketOption::LINGER, i32);
    getsockopt_template!(get_max_msg_size, SocketOption::MAXMSGSIZE, i64);
    getsockopt_template!(get_mechanism, SocketOption::MECHANISM, i32);
    getsockopt_template!(get_multicast_hops, SocketOption::MULTICAST_HOPS, i32);
    getsockopt_template!(get_plain_password, SocketOption::PLAIN_PASSWORD, u8, 256,
        |r: Vec<u8>| {
            bytes_to_string(r)
        }, String);
    getsockopt_template!(is_plain_server, SocketOption::PLAIN_SERVER, i32, |r| { r > 0 }, bool);
    getsockopt_template!(get_plain_username, SocketOption::PLAIN_USERNAME, u8, 256,
        |r: Vec<u8>| {
            bytes_to_string(r)
        }, String);
    getsockopt_template!(get_rate, SocketOption::RATE, i32);
    getsockopt_template!(get_rcvbuf, SocketOption::RCVBUF, i32);
    getsockopt_template!(get_rcvhwm, SocketOption::RCVHWM, i32);
    getsockopt_template!(can_rcvmore, SocketOption::RCVMORE, i32, |r| { r > 0 }, bool);
    getsockopt_template!(get_rcvtimeo, SocketOption::RCVTIMEO, i32);
    getsockopt_template!(get_reconnect_ivl, SocketOption::RECONNECT_IVL, i32);
    getsockopt_template!(get_reconnect_ivl_max, SocketOption::RECONNECT_IVL_MAX, i32);
    getsockopt_template!(get_recovery_ivl, SocketOption::RECOVERY_IVL, i32);
    getsockopt_template!(get_sndbuf, SocketOption::SNDBUF, i32);
    getsockopt_template!(get_sndhwm, SocketOption::SNDHWM, i32);
    getsockopt_template!(get_sndtimeo, SocketOption::SNDTIMEO, i32);
    getsockopt_template!(get_tcp_keepalive, SocketOption::TCP_KEEPALIVE, i32);
    getsockopt_template!(get_tcp_keepalive_cnt, SocketOption::TCP_KEEPALIVE_CNT, i32);
    getsockopt_template!(get_tcp_keepalive_idle, SocketOption::TCP_KEEPALIVE_IDLE, i32);
    getsockopt_template!(get_tcp_keepalive_intvl, SocketOption::TCP_KEEPALIVE_INTVL, i32);
    getsockopt_template!(get_tos, SocketOption::TOS, i32);
    getsockopt_template!(get_type, SocketOption::TYPE, SocketType);
    getsockopt_template!(get_zap_domain, SocketOption::ZAP_DOMAIN, u8, 256,
        |r: Vec<u8>| {
            bytes_to_string(r)
        }, String);

    //-------------------------------- set options ----------------------------------- //
    setsockopt_template!(set_affinity, SocketOption::AFFINITY, u64);
    setsockopt_template!(set_backlog, SocketOption::BACKLOG, i32);
    setsockopt_template!(set_connect_rid, SocketOption::CONNECT_RID);
    setsockopt_template!(set_conflate, SocketOption::CONFLATE, i32);
    setsockopt_template!(set_curve_publickey, SocketOption::CURVE_PUBLICKEY);
    setsockopt_template!(set_curve_plaintext_publickey, SocketOption::CURVE_PUBLICKEY, &str,
        |s| { str_to_cstr_bytes(s) });
    setsockopt_template!(set_curve_secretkey, SocketOption::CURVE_SECRETKEY);
    setsockopt_template!(set_curve_plaintext_secretkey, SocketOption::CURVE_SECRETKEY, &str,
        |s| { str_to_cstr_bytes(s) });
    setsockopt_template!(set_curve_server, SocketOption::CURVE_SERVER, i32);
    setsockopt_template!(set_curve_serverkey, SocketOption::CURVE_SERVERKEY);
    setsockopt_template!(set_curve_plaintext_serverkey, SocketOption::CURVE_SERVERKEY, &str,
        |s| { str_to_cstr_bytes(s) });
    setsockopt_template!(set_gssapi_plaintext, SocketOption::GSSAPI_PLAINTEXT, i32);
    setsockopt_template!(set_gssapi_principal, SocketOption::GSSAPI_PRINCIPAL, &str,
        |s| { str_to_cstr_bytes(s) });
    setsockopt_template!(set_gssapi_server, SocketOption::GSSAPI_SERVER, i32);
    setsockopt_template!(set_gssapi_service_principal, SocketOption::GSSAPI_SERVICE_PRINCIPAL, &str,
        |s| { str_to_cstr_bytes(s) });
    setsockopt_template!(set_handshake_ivl, SocketOption::HANDSHAKE_IVL, i32);
    setsockopt_template!(set_identity, SocketOption::IDENTITY);
    setsockopt_template!(set_immediate, SocketOption::IMMEDIATE, i32);
    setsockopt_template!(set_ipv6, SocketOption::IPV6, i32);
    setsockopt_template!(set_linger, SocketOption::LINGER, i32);
    setsockopt_template!(set_max_msg_size, SocketOption::MAXMSGSIZE, i64);
    setsockopt_template!(set_multicast_hops, SocketOption::MULTICAST_HOPS, i32);
    setsockopt_template!(set_plain_password, SocketOption::PLAIN_PASSWORD, &str,
        |s| { str_to_cstr_bytes(s) });
    setsockopt_nullptr_template!(set_plain_password_empty, SocketOption::PLAIN_PASSWORD);
    setsockopt_template!(set_plain_server, SocketOption::PLAIN_SERVER, i32);
    setsockopt_template!(set_plain_username, SocketOption::PLAIN_USERNAME, &str,
        |s| { str_to_cstr_bytes(s) });
    setsockopt_nullptr_template!(set_plain_username_empty, SocketOption::PLAIN_USERNAME);
    setsockopt_template!(set_probe_router, SocketOption::PROBE_ROUTER, i32);
    setsockopt_template!(set_rate, SocketOption::RATE, i32);
    setsockopt_template!(set_rcvbuf, SocketOption::RCVBUF, i32);
    setsockopt_template!(set_rcvhwm, SocketOption::RCVHWM, i32);
    setsockopt_template!(set_rcvtimeo, SocketOption::RCVTIMEO, i32);
    setsockopt_template!(set_reconnect_ivl, SocketOption::RECONNECT_IVL, i32);
    setsockopt_template!(set_reconnect_ivl_max, SocketOption::RECONNECT_IVL_MAX, i32);
    setsockopt_template!(set_recovery_ivl, SocketOption::RECOVERY_IVL, i32);
    setsockopt_template!(set_req_correlate, SocketOption::REQ_CORRELATE, i32);
    setsockopt_template!(set_req_relaxed, SocketOption::REQ_RELAXED, i32);
    setsockopt_template!(set_router_handover, SocketOption::ROUTER_HANDOVER, i32);
    setsockopt_template!(set_router_mandatory, SocketOption::ROUTER_MANDATORY, i32);
    setsockopt_template!(set_router_raw, SocketOption::ROUTER_RAW, i32);
    setsockopt_template!(set_sndbuf, SocketOption::SNDBUF, i32);
    setsockopt_template!(set_sndhwm, SocketOption::SNDHWM, i32);
    setsockopt_template!(set_sndtimeo, SocketOption::SNDTIMEO, i32);
    setsockopt_template!(set_subscribe, SocketOption::SUBSCRIBE);
    setsockopt_template!(set_tcp_keepalive, SocketOption::TCP_KEEPALIVE, i32);
    setsockopt_template!(set_tcp_keepalive_cnt, SocketOption::TCP_KEEPALIVE_CNT, i32);
    setsockopt_template!(set_tcp_keepalive_idle, SocketOption::TCP_KEEPALIVE_IDLE, i32);
    setsockopt_template!(set_tcp_keepalive_intvl, SocketOption::TCP_KEEPALIVE_INTVL, i32);
    setsockopt_template!(set_tos, SocketOption::TOS, i32);
    setsockopt_template!(set_unsubscribe, SocketOption::UNSUBSCRIBE);
    setsockopt_template!(set_xpub_verbose, SocketOption::XPUB_VERBOSE, i32);
    setsockopt_template!(set_zqp_domain, SocketOption::ZAP_DOMAIN, &str,
        |s| { str_to_cstr_bytes(s) });
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.close_underly()
    }
}

pub type PollEvent = c_int;

pub const POLLIN: PollEvent = 1;
pub const POLLOUT: PollEvent = 2;
pub const POLLERR: PollEvent = 4;

#[cfg(target_os = "windows")]
pub type SocketFd = ::libc::intptr_t;
#[cfg(not(target_os = "windows"))]
pub type SocketFd = c_int;

#[repr(C)]
pub struct PollItem {
    pub socket: *mut c_void,
    pub fd: SocketFd,
    pub events: c_short,
    pub revents: c_short,
}

impl PollItem {
    pub fn from_socket(socket: &Socket) -> PollItem {
        PollItem {
            socket: socket.socket,
            fd: 0,
            events: 0,
            revents: 0,
        }
    }

    pub fn from_fd(fd: SocketFd) -> PollItem {
        PollItem {
            socket: std::ptr::null_mut(),
            fd: fd,
            events: 0,
            revents: 0,
        }
    }

    pub fn set_socket(&mut self, socket: &Socket) -> &mut PollItem {
        self.socket = socket.socket;
        self.fd = 0;
        self
    }

    pub fn set_fd(&mut self, fd: SocketFd) -> &mut PollItem {
        self.socket = std::ptr::null_mut();
        self.fd = fd;
        self
    }

    pub fn clear_events(&mut self) -> &mut PollItem {
        self.events = 0;
        self
    }

    pub fn reg_event(&mut self, ev: PollEvent) -> &mut PollItem {
        self.events |= ev as c_short;
        self
    }

    pub fn unreg_event(&mut self, ev: PollEvent) -> &mut PollItem {
        self.events &= !(ev as c_short);
        self
    }

    /// Clear all returned events
    pub fn clear_revents(&mut self) -> &mut PollItem {
        self.revents = 0;
        self
    }

    /// Does this PollItem have the specified PollEvent returned.
    pub fn has_revent(&self, ev: PollEvent) -> bool {
        (self.revents & (ev as c_short)) > 0
    }
}
