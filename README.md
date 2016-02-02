# zmq-rs
A ZeroMQ Rust binding under the MIT license

Tracking latest stable ZMQ - 4.1.4 (currently)

***Caution:***
deprecated APIs in 4.1.4 are not accessable

I hope someone could help me improve the quality of this documentation.

APIs are under reviewing, they might be changed in future until 1.0

If you have any suggestion, please post an issue. Thx.

## Feature

- Windows compatible
- Up-to-date

## Windows Usage

Please provide following two environment variables before cargo build

Set ZMQ_LIB_PATH to the folder contains zeromq dll.

Set ZMQ_LIB_NAME to dll name without 'lib' prefix.

For example, we have libzmq.dll at "C:\zmq\bin\".

Type following commands in CMD

*** git bash has problem to read system environment variables ***


```
set ZMQ_LIB_PATH=C:\zmq\bin\
set ZMQ_LIB_NAME=zmq

cargo build
```


*** Because latest ZMQ binary package is not available on officail site. ***

*** Windows user have to build it by him(her)self. ***

## Linux usage
Just `cargo build` when libzmq.so is in the default linker search path.

## Credits
Inspired by erickt's [rust-zmq](https://github.com/erickt/rust-zmq)
