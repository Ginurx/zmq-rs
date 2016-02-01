extern crate libc;
pub type Errno = libc::c_int;

pub const EPERM: Errno = 1;
pub const ENOENT: Errno = 2;
pub const ESRCH: Errno = 3;
pub const EINTR: Errno = 4;
pub const EIO: Errno = 5;
pub const ENXIO: Errno = 6;
pub const E2BIG: Errno = 7;
pub const ENOEXEC: Errno = 8;
pub const EBADF: Errno = 9;
pub const ECHILD: Errno = 10;
pub const EAGAIN: Errno = 11;
pub const ENOMEM: Errno = 12;
pub const EACCES: Errno = 13;
pub const EFAULT: Errno = 14;
pub const EBUSY: Errno = 16;
pub const EEXIST: Errno = 17;
pub const EXDEV: Errno = 18;
pub const ENODEV: Errno = 19;
pub const ENOTDIR: Errno = 20;
pub const EISDIR: Errno = 21;
pub const ENFILE: Errno = 23;
pub const EMFILE: Errno = 24;
pub const ENOTTY: Errno = 25;
pub const EFBIG: Errno = 27;
pub const ENOSPC: Errno = 28;
pub const ESPIPE: Errno = 29;
pub const EROFS: Errno = 30;
pub const EMLINK: Errno = 31;
pub const EPIPE: Errno = 32;
pub const EDOM: Errno = 33;
pub const EDEADLK: Errno = 36;
pub const ENAMETOOLONG: Errno = 38;
pub const ENOLCK: Errno = 39;
pub const ENOSYS: Errno = 40;
pub const ENOTEMPTY: Errno = 41;

const ZMQ_HAUSNUMERO: Errno = 156384712;

/*  Native 0MQ error codes.                                                   */
pub const EFSM: Errno = (ZMQ_HAUSNUMERO + 51);
pub const ENOCOMPATPROTO: Errno = (ZMQ_HAUSNUMERO + 52);
pub const ETERM: Errno = (ZMQ_HAUSNUMERO + 53);
pub const EMTHREAD: Errno = (ZMQ_HAUSNUMERO + 54);

cfg_if! {
    if #[cfg(target_os = "windows")] {
        pub const ENOTSUP: Errno = (ZMQ_HAUSNUMERO + 1);
        pub const EPROTONOSUPPORT: Errno = (ZMQ_HAUSNUMERO + 2);
        pub const ENOBUFS: Errno = (ZMQ_HAUSNUMERO + 3);
        pub const ENETDOWN: Errno = (ZMQ_HAUSNUMERO + 4);
        pub const EADDRINUSE: Errno = (ZMQ_HAUSNUMERO + 5);
        pub const EADDRNOTAVAIL: Errno = (ZMQ_HAUSNUMERO + 6);
        pub const ECONNREFUSED: Errno = (ZMQ_HAUSNUMERO + 7);
        pub const EINPROGRESS: Errno = (ZMQ_HAUSNUMERO + 8);
        pub const ENOTSOCK: Errno = (ZMQ_HAUSNUMERO + 9);
        pub const EMSGSIZE: Errno = (ZMQ_HAUSNUMERO + 10);
        pub const EAFNOSUPPORT: Errno = (ZMQ_HAUSNUMERO + 11);
        pub const ENETUNREACH: Errno = (ZMQ_HAUSNUMERO + 12);
        pub const ECONNABORTED: Errno = (ZMQ_HAUSNUMERO + 13);
        pub const ECONNRESET: Errno = (ZMQ_HAUSNUMERO + 14);
        pub const ENOTCONN: Errno = (ZMQ_HAUSNUMERO + 15);
        pub const ETIMEDOUT: Errno = (ZMQ_HAUSNUMERO + 16);
        pub const EHOSTUNREACH: Errno = (ZMQ_HAUSNUMERO + 17);
        pub const ENETRESET: Errno = (ZMQ_HAUSNUMERO + 18);
    } else {
        pub const ENOTSUP: Errno = libc::EOPNOTSUPP;
        pub const EPROTONOSUPPORT: Errno = libc::EPROTONOSUPPORT;
        pub const ENOBUFS: Errno = libc::ENOBUFS;
        pub const ENETDOWN: Errno = libc::ENETDOWN;
        pub const EADDRINUSE: Errno = libc::EADDRINUSE;
        pub const EADDRNOTAVAIL: Errno = libc::EADDRNOTAVAIL;
        pub const ECONNREFUSED: Errno = libc::ECONNREFUSED;
        pub const EINPROGRESS: Errno = libc::EINPROGRESS;
        pub const ENOTSOCK: Errno = libc::ENOTSOCK;
        pub const EMSGSIZE: Errno = libc::EMSGSIZE;
        pub const EAFNOSUPPORT: Errno = libc::EAFNOSUPPORT;
        pub const ENETUNREACH: Errno = libc::ENETUNREACH;
        pub const ECONNABORTED: Errno = libc::ECONNABORTED;
        pub const ECONNRESET: Errno = libc::ECONNRESET;
        pub const ENOTCONN: Errno = libc::ENOTCONN;
        pub const ETIMEDOUT: Errno = libc::ETIMEDOUT;
        pub const EHOSTUNREACH: Errno = libc::EHOSTUNREACH;
        pub const ENETRESET: Errno = libc::ENETRESET;
    }
}
