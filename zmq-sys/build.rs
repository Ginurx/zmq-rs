
use std::env;

fn main() {
    let zmq_lib_path_var = env::var("ZMQ_LIB_PATH");
    if zmq_lib_path_var.is_ok() {
        let zmq_lib_path = zmq_lib_path_var.unwrap();
        println!("cargo:rustc-link-search=native={}", zmq_lib_path);
    }

    let mut zmq_lib_name: String = "zmq".to_string();
    let zmq_lib_name_var = env::var("ZMQ_LIB_NAME");
    if zmq_lib_name_var.is_ok() {
        zmq_lib_name = zmq_lib_name_var.unwrap();
    }

    println!("cargo:rustc-link-lib=dylib={}", zmq_lib_name);
}
