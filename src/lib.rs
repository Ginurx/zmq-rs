//! Module: zmq

extern crate libc;
extern crate zmq_sys;

use std::ffi;
use std::sync::atomic::{ AtomicBool, Ordering };
use libc::{ c_int, c_void };

pub const ZMQ_VERSION_MAJOR:i32 = 4;
pub const ZMQ_VERSION_MINOR:i32 = 1;
pub const ZMQ_VERSION_PATCH:i32 = 4;

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

pub struct Error {
    err_num: c_int,
}

impl Error {
    fn from_last_err() -> Error {
        let err_num = errno();

        Error {
            err_num: err_num
        }
    }
}

pub fn errno() -> c_int {
    unsafe {
        zmq_sys::zmq_errno()
    }
}

pub fn strerror(errnum: c_int) -> String {
    unsafe {
        let s = zmq_sys::zmq_strerror(errnum);
        ffi::CStr::from_ptr(s).to_str().unwrap().to_string()
    }
}

pub fn version() -> (i32, i32, i32) {
    let mut major = 0;
    let mut minor = 0;
    let mut patch = 0;

    unsafe {
        zmq_sys::zmq_version(&mut major, &mut minor, &mut patch);
    }

    (major as i32, minor as i32, patch as i32)
}

macro_rules! ret_while_null {
    ($ptr: expr) => {{
        if $ptr.is_null() {
            return Err(Error::from_last_err());
        }
    }}
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

struct Context {
    ctx_ptr: *mut c_void,
}

impl Context {
    /// void *zmq_ctx_new (void)
    pub fn new() -> Result<Context, Error> {
        let ctx_ptr = unsafe { zmq_sys::zmq_ctx_new() };
        ret_while_null!(ctx_ptr);

        Ok(Context {
            ctx_ptr: ctx_ptr,
        })
    }

    /// int zmq_ctx_term (void *context)
    fn term(&mut self) -> Option<Error> {        // trasnfer owner
        let ret_val = unsafe { zmq_sys::zmq_ctx_term(self.ctx_ptr) };
        if ret_val == -1 {
            Some(Error::from_last_err())
        } else {
            None
        }
    }

    /// int zmq_ctx_shutdown (void *ctx_)
    pub fn shutdown(&self) -> Option<Error> {
        let ret_val = unsafe { zmq_sys::zmq_ctx_shutdown(self.ctx_ptr) };
        if ret_val == -1 {
            Some(Error::from_last_err())
        } else {
            None
        }
    }

    /// int zmq_ctx_set (void *context, int option, int optval)
    pub fn set(&self, option_name: ContextSetOption, option_value: c_int) -> Option<Error> {
        let ret_val = unsafe { zmq_sys::zmq_ctx_set(self.ctx_ptr, option_name as c_int, option_value) };
        if ret_val == -1 {
            Some(Error::from_last_err())
        } else {
            None
        }
    }

    /// int zmq_ctx_get (void *context, int option)
    pub fn get(&self, option_name: ContextGetOption) -> Result<c_int, Error> {
        let ret_val = unsafe { zmq_sys::zmq_ctx_get(self.ctx_ptr, option_name as c_int) };
        if ret_val == -1 {
            Err(Error::from_last_err())
        } else {
            Ok(ret_val)
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.term().unwrap();
    }
}
