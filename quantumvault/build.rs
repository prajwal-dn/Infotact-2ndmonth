use std::{env, process::Command};

fn main() {
    let out = env::var("OUT_DIR").unwrap();
    let obj = format!("{out}/oqs_shim.o");
    let archive = format!("{out}/libqv_oqs_shim.a");

    assert!(
        Command::new("gcc")
            .args([
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fPIC",
                "-I/usr/local/include",
                "-c",
                "src/crypto/oqs_shim.c",
                "-o",
                &obj
            ])
            .status()
            .expect("gcc unavailable")
            .success()
    );

    assert!(
        Command::new("ar")
            .args(["crus", &archive, &obj])
            .status()
            .expect("ar unavailable")
            .success()
    );

    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-lib=static=qv_oqs_shim");
    println!("cargo:rustc-link-lib=dylib=oqs");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");
    println!("cargo:rerun-if-changed=src/crypto/oqs_shim.c");
    println!("cargo:rustc-link-lib=dylib=ssl");
    println!("cargo:rustc-link-lib=dylib=crypto");
}
