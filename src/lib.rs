#![allow(dead_code)]

extern crate libc;
extern crate zmq_ffi;
#[macro_use]
extern crate cfg_if;

mod socket;
mod errno;
pub use socket::*;
pub use errno::*;

use std::ops::{ Deref, DerefMut };
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

fn errno() -> c_int {
    unsafe {
        zmq_ffi::zmq_errno()
    }
}

fn strerror(errnum: c_int) -> String {
    unsafe {
        let s = zmq_ffi::zmq_strerror(errnum);
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
        zmq_ffi::zmq_version(&mut major, &mut minor, &mut patch);
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

    pub fn get_errno(&self) -> Errno {
        self.err_num as Errno
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

type ContextOption = c_int;

const IO_THREADS: ContextOption = 1;         //  get     /   set
const MAX_SOCKETS: ContextOption = 2;        //  get     /   set
const SOCKET_LIMIT: ContextOption = 3;       //  get     /
const THREAD_PRIORITY: ContextOption = 3;    //          /   set
const THREAD_SCHED_POLICY: ContextOption = 4;//          /   set
const IPV6: ContextOption = 42;              //  get     /   set

macro_rules! getctxopt_template {
    ($name: ident, $opt: expr) => {
        pub fn $name(&self) -> Result<i32, Error> {
            let rc = unsafe { zmq_ffi::zmq_ctx_get(self.ctx_ptr, $opt as c_int) };
            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                Ok(rc)
            }
        }
    };
    ($name: ident, $opt: expr, $map: expr, $rt: ty) => {
        pub fn $name(&self) -> Result<$rt, Error> {
            let rc = unsafe { zmq_ffi::zmq_ctx_get(self.ctx_ptr, $opt as c_int) };
            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                Ok($map(rc))
            }
        }
    };
}

macro_rules! setctxopt_template {
    ($name: ident, $opt: expr) => {
        pub fn $name(&mut self, optval: i32) -> Result<(), Error> {
            let rc = unsafe { zmq_ffi::zmq_ctx_set(self.ctx_ptr,  $opt as c_int, optval as c_int) };
            if rc == -1 {
                Err(Error::from_last_err())
            } else {
                Ok(())
            }
        }
    };
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
        let ctx_ptr = unsafe { zmq_ffi::zmq_ctx_new() };
        ret_when_null!(ctx_ptr);
        Ok(Context {
            ctx_ptr: ctx_ptr,
        })
    }

    /// Destroy a 0MQ context
    ///
    /// Binding of `int zmq_ctx_term (void *context);`
    /// This function will be called automatically when context goes out of scope
    fn term(&mut self) -> Result<(), Error> {
        let rc = unsafe { zmq_ffi::zmq_ctx_term(self.ctx_ptr) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Shutdown a 0MQ context
    ///
    /// Binding of `int zmq_ctx_shutdown (void *context);`
    ///
    /// The function will shutdown the ØMQ context context.
    /// Context shutdown will cause any blocking operations currently in progress on sockets open within context to return immediately with an error code of ETERM.
    /// With the exception of Socket::Close(), any further operations on sockets open within context will fail with an error code of ETERM.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        let rc = unsafe { zmq_ffi::zmq_ctx_shutdown(self.ctx_ptr) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    getctxopt_template!(get_io_threads, IO_THREADS);
    getctxopt_template!(get_max_sockets, MAX_SOCKETS);
    getctxopt_template!(get_socket_limit, SOCKET_LIMIT);
    getctxopt_template!(is_ipv6_enabled, IPV6, |r| { r > 0 }, bool);

    setctxopt_template!(set_io_threads, IO_THREADS);
    setctxopt_template!(set_max_sockets, MAX_SOCKETS);
    setctxopt_template!(set_thread_priority, THREAD_PRIORITY);
    setctxopt_template!(set_thread_sched_policy, THREAD_SCHED_POLICY);
    setctxopt_template!(set_ipv6, IPV6);

    /// Create 0MQ socket
    ///
    /// Binding of `void *zmq_socket (void *context, int type);`
    ///
    /// The type argument specifies the socket type, which determines the semantics of communication over the socket.
    /// The newly created socket is initially unbound, and not associated with any endpoints.
    /// In order to establish a message flow a socket must first be connected to at least one endpoint with Scoket::Connect,
    /// or at least one endpoint must be created for accepting incoming connections with Socket::Bind().
    pub fn socket(&self, t: SocketType) -> Result<Socket, Error> {
        let socket = unsafe { zmq_ffi::zmq_socket(self.ctx_ptr, t as c_int) };
        ret_when_null!(socket);
        Ok(Socket::from_raw(socket))
    }
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Drop for Context {
    fn drop(&mut self) {
        loop {
            match self.term() {
                Ok(_) => { },
                Err(e) => {
                    if e.get_errno() == EINTR {
                        continue;
                    } else {
                        break;
                    }
                }
            }
        }

    }
}

const MSG_SIZE: usize = 64;

pub struct Message {
    msg: zmq_ffi::zmq_msg_t,
}

unsafe extern "C" fn zmq_free_fn(data: *mut c_void, hint: *mut c_void) {
    let slice = slice::from_raw_parts_mut(data as *mut u8, hint as usize);
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
        let mut msg = zmq_ffi::zmq_msg_t { unknown: [0; MSG_SIZE] };
        let rc = unsafe { zmq_ffi::zmq_msg_init(&mut msg) };
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
        let mut msg = zmq_ffi::zmq_msg_t { unknown: [0; MSG_SIZE] };
        let rc = unsafe { zmq_ffi::zmq_msg_init_size(&mut msg, len as size_t) };
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

        let mut msg = zmq_ffi::zmq_msg_t { unknown: [0; MSG_SIZE] };
        let rc = unsafe {
            zmq_ffi::zmq_msg_init_data(&mut msg, Box::into_raw(data) as *mut c_void, len,
                zmq_free_fn, len as *mut _)
            };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(Message { msg: msg })
        }
    }

    pub fn from_slice(data: &[u8]) -> Result<Message, Error> {
        unsafe {
            let mut msg = try!(Message::with_capcity(data.len()));
            std::ptr::copy_nonoverlapping(data.as_ptr(), msg.as_mut_ptr(), data.len());
            Ok(msg)
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
    pub fn msg_move(dest: &mut Message, src: &mut Message) -> Result<(), Error> {
        let rc = unsafe {
            zmq_ffi::zmq_msg_move(&mut dest.msg, &mut src.msg)
        };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Copy content of a message to another message.
    ///
    /// Binding of `int zmq_msg_copy (zmq_msg_t *dest, zmq_msg_t *src);`.
    ///
    /// Copy the message object referenced by src to the message object referenced by dest.
    /// The original content of dest, if any, will be released.
    pub fn msg_copy(dest: &mut Message, src: &Message) -> Result<(), Error> {
        let rc = unsafe {
            zmq_ffi::zmq_msg_copy(&mut dest.msg, transmute(&src.msg))
        };
        if rc == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(())
        }
    }

    /// Retrieve pointer to message content.
    ///
    /// Binding of `void *zmq_msg_data (zmq_msg_t *msg);`.
    ///
    /// The function will return a pointer to the message content.
    pub unsafe fn get_data_ptr(&mut self) -> *mut c_void {
        zmq_ffi::zmq_msg_data(&mut self.msg)
    }

    /// Retrieve pointer to message content.
    ///
    /// Binding of `void *zmq_msg_data (zmq_msg_t *msg);`.
    ///
    /// The function will return a pointer to the message content.
    pub unsafe fn get_const_data_ptr(&self) -> *const c_void {
        zmq_ffi::zmq_msg_data(transmute(&self.msg))
    }

    /// Retrieve message content size in bytes
    ///
    /// Binding of `size_t zmq_msg_size (zmq_msg_t *msg);`
    ///
    /// The function will return the size in bytes of the content of the message.
    pub fn len(&self) -> usize {
        unsafe { zmq_ffi::zmq_msg_size(transmute(&self.msg)) }
    }

    ///  Indicate if there are more message parts to receive
    ///
    /// Binding of `int zmq_msg_more (zmq_msg_t *message);`
    ///
    /// The function indicates whether this is part of a multi-part message, and there are further parts to receive.
    /// This method is identical to xxxxx with an argument of ZMQ_MORE.
    pub fn has_more(&self) -> bool {
        unsafe { zmq_ffi::zmq_msg_more(transmute(&self.msg)) > 0 }
    }

    /// Get message property
    ///
    /// Binding of `int zmq_msg_get (zmq_msg_t *message, int property);`
    ///
    /// The function will return the value for the property specified by the property argument.
    pub fn get_property(&self, property: MessageProperty) -> Result<i32, Error> {
        let rc = unsafe { zmq_ffi::zmq_msg_get(transmute(&self.msg), property as c_int) };
        if rc == -1 {
            Err(Error::from_last_err())
        } else  {
            Ok(rc)
        }
    }

    // zmq_msg_set is not used this while
    // pub fn set_property(&mut self, property: c_int, optval: i32) -> Result<(), Error> { }

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

        let returned_str_ptr = unsafe { zmq_ffi::zmq_msg_gets(transmute(&self.msg), transmute(prop_cstr.as_ptr())) };
        if returned_str_ptr.is_null() {
            None
        } else {
            unsafe { Some(ffi::CStr::from_ptr(returned_str_ptr).to_str().unwrap()) }
        }
    }
}

impl Deref for Message {
    type Target = [u8];

    fn deref<'a>(&'a self) -> &'a [u8] {
        unsafe {
            let ptr = self.get_const_data_ptr();
            let len = self.len() as usize;
            slice::from_raw_parts(transmute(ptr), len)
        }
    }
}

impl DerefMut for Message {
    fn deref_mut<'a>(&'a mut self) -> &'a mut [u8] {
        unsafe {
            let ptr = self.get_data_ptr();
            let len = self.len() as usize;
            slice::from_raw_parts_mut(transmute(ptr), len)
        }
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        loop {
            let rc = unsafe { zmq_ffi::zmq_msg_close(&mut self.msg) };
            if rc != 0 {
                let e = Error::from_last_err();
                if e.get_errno() == EINTR {
                    continue;
                } else {
                    panic!(e);
                }

            } else {
                break;
            }
        }
    }
}

pub type SocketType = c_int;
pub const PAIR: SocketType = 0;
pub const PUB: SocketType = 1;
pub const SUB: SocketType = 2;
pub const REQ: SocketType = 3;
pub const REP: SocketType = 4;
pub const DEALER: SocketType = 5;
pub const ROUTER: SocketType = 6;
pub const PULL: SocketType = 7;
pub const PUSH: SocketType = 8;
pub const XPUB: SocketType = 9;
pub const XSUB: SocketType = 10;
pub const STREAM: SocketType = 11;

pub type MessageProperty = c_int;
pub const MORE: MessageProperty = 1;
pub const SRCFD: MessageProperty = 2;
pub const SHARED: MessageProperty = 3;


pub type SecurityMechanism = c_int;
pub const ZMQ_NULL: SecurityMechanism = 0;
pub const ZMQ_PLAIN: SecurityMechanism = 1;
pub const ZMQ_CURVE: SecurityMechanism = 2;
pub const ZMQ_GSSAPI: SecurityMechanism = 3;

/// Check a ZMQ capability
///
/// Bindng of `int zmq_has (const char *capability);`
///
/// The function shall report whether a specified capability is available in the library
pub fn has_capability(capability: &str) -> bool {
    let capability_cstr = ffi::CString::new(capability).unwrap();
    let rc = unsafe { zmq_ffi::zmq_has(capability_cstr.as_ptr()) };
    rc == 1
}

//  Encryption functions
/*  Encode data with Z85 encoding. Returns encoded data                       */
//ZMQ_EXPORT char *zmq_z85_encode (char *dest, const uint8_t *data, size_t size);

/// Encode a binary key as Z85 printable text
///
/// Binding of `char *zmq_z85_encode (char *dest, const uint8_t *data, size_t size);`
///
/// The function will encode the binary block specified by data and size into a string in dest.
/// The size of the binary block must be divisible by 4.
pub fn z85_encode(data: &[u8]) -> Result<String, Error> {
    let len = data.len() as i32 * 5 / 4 + 1;
    let mut dest: Vec<u8> = Vec::with_capacity(len as usize);

    let rc = unsafe { zmq_ffi::zmq_z85_encode(transmute(dest.as_mut_ptr()), data.as_ptr(), data.len()) };
    if rc.is_null() {
        Err(Error::from_last_err())
    } else {
        unsafe {
            dest.set_len(len as usize);
            let cstr = ffi::CStr::from_ptr(transmute(dest.as_ptr()));

            Ok(String::from_utf8(cstr.to_bytes().to_vec()).unwrap())
        }
    }
}

///  Decode a binary key from Z85 printable text
///
/// Binding of `uint8_t *zmq_z85_decode (uint8_t *dest, const char *string);`
///
/// The function will decode string into dest. The length of string in bytes shall be divisible by 5
pub fn z85_decode(encoded: &str) -> Result<Vec<u8>, Error> {
    let encoded_cstr = ffi::CString::new(encoded).unwrap();
    let len = (encoded_cstr.as_bytes().len() as i32 * 4 / 5) as i32;
    let mut dest: Vec<u8> = Vec::with_capacity(len as usize);

    let rc = unsafe { zmq_ffi::zmq_z85_decode(dest.as_mut_ptr(), encoded_cstr.as_ptr()) };
    if rc.is_null() {
        Err(Error::from_last_err())
    } else  {
        unsafe {
            dest.set_len(len as usize);
        }
        Ok(dest)
    }
}


/// Generate z85-encoded public and private keypair with libsodium.
///
/// Binding of `int zmq_curve_keypair (char *z85_public_key, char *z85_secret_key);`
///
/// The function will return a newly generated random keypair consisting of a public key and a secret key.
/// The keys are encoded using z85_encode().
pub fn gen_curve_keypair() -> Result<(String, String), Error> {
    let mut public_key: Vec<u8> = Vec::with_capacity(41);
    let mut secret_key: Vec<u8> = Vec::with_capacity(41);

    let rc = unsafe {
        zmq_ffi::zmq_curve_keypair(
            transmute(public_key.as_mut_ptr()),
            transmute(secret_key.as_mut_ptr())
        )
    };
    if rc == -1 {
        Err(Error::from_last_err())
    } else  {
        unsafe {
            public_key.set_len(40);
            secret_key.set_len(40);
        }
        Ok((String::from_utf8(public_key).unwrap(), String::from_utf8(secret_key).unwrap()))
    }
}
