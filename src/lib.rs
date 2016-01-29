#![allow(dead_code)]

extern crate libc;
extern crate zmq_sys;

use std::ffi;
use std::vec::Vec;
use std::slice;
use std::mem::transmute;
use libc::{ c_int, c_void, size_t };

pub const ZMQ_VERSION_MAJOR:i32 = 4;
pub const ZMQ_VERSION_MINOR:i32 = 1;
pub const ZMQ_VERSION_PATCH:i32 = 4;

macro_rules! ret_when_null {
    ($ptr: expr) => {{
        if $ptr.is_null() {
            return Err(Error::from_last_err());
        }
    }}
}

#[macro_export]
macro_rules! ZMQ_MAKE_VERSION {
    ($major: expr, $minor: expr, $patch: expr) => {
        {
            $major * 10000 + $minor * 100 + $patch
        }
    }
}

pub const ZMQ_VERSION:i32 = ZMQ_MAKE_VERSION!(
    ZMQ_VERSION_MAJOR,
    ZMQ_VERSION_MINOR,
    ZMQ_VERSION_PATCH
);

/*
const ZMQ_HAUSNUMERO: c_int = 156384712;

const ENOTSUP: c_int = (ZMQ_HAUSNUMERO + 1);
const EPROTONOSUPPORT: c_int = (ZMQ_HAUSNUMERO + 2);
const ENOBUFS: c_int = (ZMQ_HAUSNUMERO + 3);
const ENETDOWN: c_int = (ZMQ_HAUSNUMERO + 4);
const EADDRINUSE: c_int = (ZMQ_HAUSNUMERO + 5);
const EADDRNOTAVAIL: c_int = (ZMQ_HAUSNUMERO + 6);
const ECONNREFUSED: c_int = (ZMQ_HAUSNUMERO + 7);
const EINPROGRESS: c_int = (ZMQ_HAUSNUMERO + 8);
const ENOTSOCK: c_int = (ZMQ_HAUSNUMERO + 9);
const EMSGSIZE: c_int = (ZMQ_HAUSNUMERO + 10);
const EAFNOSUPPORT: c_int = (ZMQ_HAUSNUMERO + 11);
const ENETUNREACH: c_int = (ZMQ_HAUSNUMERO + 12);
const ECONNABORTED: c_int = (ZMQ_HAUSNUMERO + 13);
const ECONNRESET: c_int = (ZMQ_HAUSNUMERO + 14);
const ENOTCONN: c_int = (ZMQ_HAUSNUMERO + 15);
const ETIMEDOUT: c_int = (ZMQ_HAUSNUMERO + 16);
const EHOSTUNREACH: c_int = (ZMQ_HAUSNUMERO + 17);
const ENETRESET: c_int = (ZMQ_HAUSNUMERO + 18);

const EFSM: c_int = (ZMQ_HAUSNUMERO + 51);
const ENOCOMPATPROTO: c_int = (ZMQ_HAUSNUMERO + 52);
const ETERM: c_int = (ZMQ_HAUSNUMERO + 53);
const EMTHREAD: c_int = (ZMQ_HAUSNUMERO + 54);
*/

fn errno() -> c_int {
    unsafe {
        zmq_sys::zmq_errno()
    }
}

fn strerror(errnum: c_int) -> String {
    unsafe {
        let s = zmq_sys::zmq_strerror(errnum);
        ffi::CStr::from_ptr(s).to_str().unwrap().to_string()
    }
}

/// Report 0MQ library version
///
/// Binding of `void zmq_version (int *major, int *minor, int *patch)`
///
/// The function will return tuple of major, minor and patch of the ØMQ library version.
pub fn version() -> (i32, i32, i32) {
    let mut major = 0;
    let mut minor = 0;
    let mut patch = 0;

    unsafe {
        zmq_sys::zmq_version(&mut major, &mut minor, &mut patch);
    }

    (major as i32, minor as i32, patch as i32)
}

#[derive(Clone)]
pub struct Error {
    err_num: c_int,
    err_str: String,
}

impl Error {
    fn from_last_err() -> Error {
        let err_num = errno();
        let err_str = strerror(err_num);

        Error {
            err_num: err_num,
            err_str: err_str,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} (code {})", self.err_str, self.err_num)
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        &self.err_str
    }
}

#[allow(non_camel_case_types)]
pub enum ContextSetOption {
    ZMQ_IO_THREADS = 1,
    ZMQ_MAX_SOCKETS = 2,
    ZMQ_THREAD_PRIORITY = 3,
    ZMQ_THREAD_SCHED_POLICY = 4,
    ZMQ_IPV6 = 42,
}

#[allow(non_camel_case_types)]
pub enum ContextGetOption {
    ZMQ_IO_THREADS = 1,
    ZMQ_MAX_SOCKETS = 2,
    ZMQ_SOCKET_LIMIT = 3,
    ZMQ_IPV6 = 42,
}

pub struct Context {
    ctx_ptr: *mut c_void,
}

impl Context {
    /// Create new 0MQ context
    ///
    /// Binding of `void *zmq_ctx_new ();`
    ///
    /// The function creates a new ØMQ context.
    /// # Thread safety
    /// A ØMQ context is thread safe and may be shared among as many application threads as necessary,
    /// without any additional locking required on the part of the caller.
    pub fn new() -> Result<Context, Error> {
        let ctx_ptr = unsafe { zmq_sys::zmq_ctx_new() };
        ret_when_null!(ctx_ptr);
        Ok(Context {
            ctx_ptr: ctx_ptr,
        })
    }

    /// Destroy a 0MQ context
    ///
    /// Binding of `int zmq_ctx_term (void *context);`
    /// This function will be called automatically when context goes out of scope
    fn term(&mut self) -> Option<Error> {
        let rc = unsafe { zmq_sys::zmq_ctx_term(self.ctx_ptr) };
        if rc == -1 {
            Some(Error::from_last_err())
        } else {
            None
        }
    }

    /// Shutdown a 0MQ context
    ///
    /// Binding of `int zmq_ctx_shutdown (void *context);`
    ///
    /// The function will shutdown the ØMQ context context.
    /// Context shutdown will cause any blocking operations currently in progress on sockets open within context to return immediately with an error code of ETERM.
    /// With the exception of Socket::Close(), any further operations on sockets open within context will fail with an error code of ETERM.
    pub fn shutdown(&self) -> Option<Error> {
        let rc = unsafe { zmq_sys::zmq_ctx_shutdown(self.ctx_ptr) };
        if rc == -1 {
            Some(Error::from_last_err())
        } else {
            None
        }
    }

    /// Set context options
    ///
    /// Bindnig of `int zmq_ctx_set (void *context, int option_name, int option_value);`
    ///
    /// The function will set the option specified by the option_name argument to the value of the option_value argument.
    pub fn set_option(&self, option_name: ContextSetOption, option_value: c_int) -> Option<Error> {
        let rc = unsafe { zmq_sys::zmq_ctx_set(self.ctx_ptr, option_name as c_int, option_value) };
        if rc == -1 {
            Some(Error::from_last_err())
        } else {
            None
        }
    }

    /// Get context options
    ///
    /// Binding of `int zmq_ctx_get (void *context, int option_name);`
    ///
    /// The function will return the option specified by the option_name argument.
    pub fn get_option(&self, option_name: ContextGetOption) -> Result<c_int, Error> {
        let rc = unsafe { zmq_sys::zmq_ctx_get(self.ctx_ptr, option_name as c_int) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(rc)
        }
    }

    /// Create 0MQ socket
    ///
    /// Binding of `void *zmq_socket (void *context, int type);`
    ///
    /// The type argument specifies the socket type, which determines the semantics of communication over the socket.
    /// The newly created socket is initially unbound, and not associated with any endpoints.
    /// In order to establish a message flow a socket must first be connected to at least one endpoint with Scoket::Connect,
    /// or at least one endpoint must be created for accepting incoming connections with Socket::Bind().
    pub fn socket(&self, t: SocketType) -> Result<Socket, Error> {
        let socket = unsafe { zmq_sys::zmq_socket(self.ctx_ptr, t as c_int) };
        ret_when_null!(socket);
        Ok(Socket { socket: socket })
    }
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Drop for Context {
    fn drop(&mut self) {
        self.term().unwrap();
    }
}

const MSG_SIZE: usize = 64;

pub struct Message {
    msg: zmq_sys::zmq_msg_t,
}

unsafe extern "C" fn zmq_free_fn(data: *mut c_void, hint: *mut c_void) {
    let len = transmute(hint);
    let slice = slice::from_raw_parts_mut(transmute::<*mut c_void, *mut u8>(data), len);
    let _: Box<[u8]> = Box::from_raw(slice);
}

impl Message {
    /// initialise empty 0MQ message.
    ///
    /// Binding of `int zmq_msg_init (zmq_msg_t *msg);`.
    ///
    /// The function will return a message object to represent an empty message.
    /// This function is most useful when called before receiving a message.
    pub fn new() -> Result<Message, Error> {
        let mut msg = zmq_sys::zmq_msg_t { unknown: [0; MSG_SIZE] };
        let rc = unsafe { zmq_sys::zmq_msg_init(&mut msg) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(Message { msg: msg })
        }
    }

    ///  Initialise 0MQ message of a specified size.
    ///
    /// Binding of `int zmq_msg_init_size (zmq_msg_t *msg, size_t size);`.
    ///
    /// The function will allocate any resources required to store a message size bytes long and
    /// return a message object to represent the newly allocated message.
    pub fn with_capcity(len: usize) -> Result<Message, Error> {
        let mut msg = zmq_sys::zmq_msg_t { unknown: [0; MSG_SIZE] };
        let rc = unsafe { zmq_sys::zmq_msg_init_size(&mut msg, len as size_t) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(Message { msg: msg })
        }
    }

    /// Initialise 0MQ message from a supplied std::vec::Vec<u8>.
    ///
    /// Binding of `int zmq_msg_init_data (zmq_msg_t *msg, void *data,
    ///    size_t size, zmq_free_fn *ffn, void *hint);`.
    ///
    /// The function will take ownership of the Vec and
    /// return a message object to represent the content referenced by the Vec.
    ///
    /// No copy of data will be performed.
    pub fn from_vec(vec: Vec<u8>) -> Result<Message, Error> {
        let len = vec.len() as size_t;
        let data = vec.into_boxed_slice();
        let free_fn = unsafe { transmute(zmq_free_fn) };

        let mut msg = zmq_sys::zmq_msg_t { unknown: [0; MSG_SIZE] };
        let rc = unsafe {
            zmq_sys::zmq_msg_init_data(&mut msg, Box::into_raw(data) as *mut c_void, len,
                free_fn, transmute(len))
            };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(Message { msg: msg })
        }
    }

    /// Move content of a message to another message.
    ///
    /// Binding of `int zmq_msg_move (zmq_msg_t *dest, zmq_msg_t *src);`.
    ///
    /// Move the content of the message object referenced by src to the message object referenced by dest.
    /// No actual copying of message content is performed,
    /// dest is simply updated to reference the new content.
    /// src becomes an empty message after calling Message::msg_move().
    /// The original content of dest, if any, will be released
    pub fn msg_move(dest: &mut Message, src: &mut Message) -> Option<Error> {
        let rc = unsafe {
            zmq_sys::zmq_msg_move(&mut dest.msg, &mut src.msg)
        };
        if rc == -1 {
            Some(Error::from_last_err())
        } else {
            None
        }
    }

    /// Copy content of a message to another message.
    ///
    /// Binding of `int zmq_msg_copy (zmq_msg_t *dest, zmq_msg_t *src);`.
    ///
    /// Copy the message object referenced by src to the message object referenced by dest.
    /// The original content of dest, if any, will be released.
    pub fn msg_copy(dest: &mut Message, src: &Message) -> Option<Error> {
        let rc = unsafe {
            zmq_sys::zmq_msg_copy(&mut dest.msg, transmute(&src.msg))
        };
        if rc == -1 {
            Some(Error::from_last_err())
        } else {
            None
        }
    }

    /// Retrieve pointer to message content.
    ///
    /// Binding of `void *zmq_msg_data (zmq_msg_t *msg);`.
    ///
    /// The function will return a pointer to the message content.
    pub unsafe fn get_data_pointer(&mut self) -> *mut c_void {
        zmq_sys::zmq_msg_data(&mut self.msg)
    }

    /// Retrieve message content size in bytes
    ///
    /// Binding of `size_t zmq_msg_size (zmq_msg_t *msg);`
    ///
    /// The function will return the size in bytes of the content of the message.
    pub fn len(&self) -> usize {
        unsafe { zmq_sys::zmq_msg_size(transmute(&self.msg)) }
    }

    ///  Indicate if there are more message parts to receive
    ///
    /// Binding of `int zmq_msg_more (zmq_msg_t *message);`
    ///
    /// The function indicates whether this is part of a multi-part message, and there are further parts to receive.
    /// This method is identical to xxxxx with an argument of ZMQ_MORE.
    pub fn has_more(&self) -> bool {
        unsafe { zmq_sys::zmq_msg_more(transmute(&self.msg)) > 0 }
    }

    /// Get message property
    ///
    /// Binding of `int zmq_msg_get (zmq_msg_t *message, int property);`
    ///
    /// The function will return the value for the property specified by the property argument.
    pub fn get_property(&self, property: MessageProperty) -> Result<i32, Error> {
        let rc = unsafe { zmq_sys::zmq_msg_get(transmute(&self.msg), property as c_int) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else  {
            Ok(rc)
        }
    }

    // zmq_msg_set is not used this while
    // pub fn set_property(&mut self, property: c_int, optval: i32) -> Option<Error> { }

    /// Get message metadata property
    ///
    /// Binding of `const char *zmq_msg_gets (zmq_msg_t *message, const char *property);`
    ///
    /// The function will return the string value for the metadata property specified by the property argument.
    /// Metadata is defined on a per-connection basis during the ZeroMQ connection handshake as specified in <rfc.zeromq.org/spec:37>.
    /// The following ZMTP properties can be retrieved with the function:
    /// `Socket-Type`
    /// `Identity`
    /// `Resource`
    /// Additionally, when available for the underlying transport,
    /// the Peer-Address property will return the IP address of the remote endpoint as returned by getnameinfo(2).
    /// Other properties may be defined based on the underlying security mechanism.
    pub fn get_meta<'a>(&'a self, property: &str) -> Option<&'a str> {
        let prop_cstr = ffi::CString::new(property).unwrap();

        let returned_str_ptr = unsafe { zmq_sys::zmq_msg_gets(transmute(&self.msg), transmute(prop_cstr.as_ptr())) };
        if returned_str_ptr.is_null() {
            None
        } else {
            unsafe { Some(ffi::CStr::from_ptr(returned_str_ptr).to_str().unwrap()) }
        }
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        let rc = unsafe { zmq_sys::zmq_msg_close(&mut self.msg) };
        if rc != 0 {
            panic!(Error::from_last_err());
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum SocketType {
    PAIR        = 0,
    PUB         = 1,
    SUB         = 2,
    REQ         = 3,
    REP         = 4,
    DEALER      = 5,
    ROUTER      = 6,
    PULL        = 7,
    PUSH        = 8,
    XPUB        = 9,
    XSUB        = 10,
    ZMQ_STREAM  = 11,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum SocketOption {
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

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum MessageProperty {
    MORE        = 1,
    SRCFD       = 2,
    SHARED      = 3,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum SendRecvOption {
    DONTWAIT    = 1,
    SNDMORE     = 2,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum SecurityMechanism {
    ZMQ_NULL    = 0,
    ZMQ_PLAIN   = 1,
    ZMQ_CURVE   = 2,
    ZMQ_GSSAPI  = 3,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum SocketEvent {
    CONNECTED         = 0x0001,
    CONNECT_DELAYED   = 0x0002,
    CONNECT_RETRIED   = 0x0004,
    LISTENING         = 0x0008,
    BIND_FAILED       = 0x0010,
    ACCEPTED          = 0x0020,
    ACCEPT_FAILED     = 0x0040,
    CLOSED            = 0x0080,
    CLOSE_FAILED      = 0x0100,
    DISCONNECTED      = 0x0200,
    MONITOR_STOPPED   = 0x0400,
    ALL               = 0xFFFF,
}

pub struct Socket {
    socket: *mut c_void,
}

impl Socket {
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
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.close_underly()
    }
}
