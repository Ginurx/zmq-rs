//! Module: zmq

extern crate libc;
extern crate zmq_sys;

use std::ffi;
use libc::c_int;

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

const ZMQ_HAUSNUMERO: isize = 156384712;

pub enum PosixErrCode {
    ENOTSUP = (ZMQ_HAUSNUMERO + 1),
    EPROTONOSUPPORT = (ZMQ_HAUSNUMERO + 2),
    ENOBUFS = (ZMQ_HAUSNUMERO + 3),
    ENETDOWN = (ZMQ_HAUSNUMERO + 4),
    EADDRINUSE = (ZMQ_HAUSNUMERO + 5),
    EADDRNOTAVAIL = (ZMQ_HAUSNUMERO + 6),
    ECONNREFUSED = (ZMQ_HAUSNUMERO + 7),
    EINPROGRESS = (ZMQ_HAUSNUMERO + 8),
    ENOTSOCK = (ZMQ_HAUSNUMERO + 9),
    EMSGSIZE = (ZMQ_HAUSNUMERO + 10),
    EAFNOSUPPORT = (ZMQ_HAUSNUMERO + 11),
    ENETUNREACH = (ZMQ_HAUSNUMERO + 12),
    ECONNABORTED = (ZMQ_HAUSNUMERO + 13),
    ECONNRESET = (ZMQ_HAUSNUMERO + 14),
    ENOTCONN = (ZMQ_HAUSNUMERO + 15),
    ETIMEDOUT = (ZMQ_HAUSNUMERO + 16),
    EHOSTUNREACH = (ZMQ_HAUSNUMERO + 17),
    ENETRESET = (ZMQ_HAUSNUMERO + 18),
}

pub enum ZMQErrCode {
    EFSM = (ZMQ_HAUSNUMERO + 51),
    ENOCOMPATPROTO = (ZMQ_HAUSNUMERO + 52),
    ETERM = (ZMQ_HAUSNUMERO + 53),
    EMTHREAD = (ZMQ_HAUSNUMERO + 54)
}

pub enum Error {
    OSError (c_int),
    WinError (PosixErrCode),
    ZMQError (ZMQErrCode),
}

pub fn errno() -> i32 {
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
