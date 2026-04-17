// Build script for netlogger-rs
//
// This script:
// 1. Generates vmlinux.h from the running kernel BTF if not present
// 2. Compiles the eBPF program and generates Rust bindings via libbpf-cargo
//
// Requirements:
// - clang
// - bpftool
// - libbpf-devel

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

const SRC_PATH: &str = "src/bpf/program.bpf.c";
const HEADER_PATH: &str = "src/bpf/program.h";
const VMLINUX_PATH: &str = "src/bpf/vmlinux.h";
const HEADERS_DIR_PATH: &str = "src/bpf";
const EXPECT_MESSAGE: &str = "Failed to create vmlinux.h try creating it yourself with command 'bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h'";

fn main() {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    );

    let out = manifest_dir.join("src").join("bpf").join("program_skel.rs");

    let vmlinux_path = manifest_dir.join(VMLINUX_PATH);

    let headers_path = manifest_dir.join(HEADERS_DIR_PATH);

    // Check if clang exists
    Command::new("clang").arg("--version").output().expect(
        "clang not found. Install it: Fedora: dnf install clang | Ubuntu: apt install clang",
    );
    
    // Generate vmlinux.h if not present
    if !vmlinux_path.exists() {
        // Check if bpftool exists
        Command::new("bpftool")
            .arg("--version")
            .output()
            .expect("bpftool not found. Install it: Fedora: dnf install bpftool | Ubuntu: apt install linux-tools-common");

        let output = Command::new("bpftool")
            .arg("btf")
            .arg("dump")
            .arg("file")
            .arg("/sys/kernel/btf/vmlinux")
            .arg("format")
            .arg("c")
            .output()
            .expect(EXPECT_MESSAGE);

        assert!(
            output.status.success(),
            "{}, error: {:?}",
            EXPECT_MESSAGE,
            String::from_utf8_lossy(&output.stderr)
        );

        fs::write(&vmlinux_path, output.stdout).expect(EXPECT_MESSAGE);
    }

    // Generate content of program_skel.rs with libbpf-cargo
    SkeletonBuilder::new()
        .source(SRC_PATH)
        .clang_args([OsStr::new("-I"), headers_path.as_os_str()])
        .build_and_generate(&out)
        .unwrap();

    // Suppress warnings in generated skeleton
    let content = fs::read_to_string(&out).unwrap();
    fs::write(&out, format!("#![allow(warnings)]\n{}", content)).unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={SRC_PATH}");
    println!("cargo:rerun-if-changed={HEADER_PATH}");
    println!("cargo:rerun-if-changed={VMLINUX_PATH}");
}
