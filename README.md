# zmq-rs
Another ZeroMQ bindings for Rust

Created for ZMQ 4.1.4

Inspired by erickt's [rust-zmq](https://github.com/erickt/rust-zmq),
but aimming at providing better Windows compatiblity.

## Windows Usage

Please provide below two environment variables before cargo build

Set ZMQ_LIB_PATH to the folder contains zeromq dll and

set ZMQ_LIB_NAME to dll name without 'lib' prefix.

For example, we have libzmq.dll at "C:\zmq\bin\".

Type these commands in CMD

```
set ZMQ_LIB_PATH=C:\zmq\bin\
set ZMQ_LIB_NAME=zmq

cargo build
```
