# netlogger-rs

**netlogger-rs** is an eBPF-based network monitoring and filtering tool for Linux, written in Rust. Designed for malware researchers and security professionals.

Monitor and control network activity of a target process and its entire process tree.

## Features

- **Process tree monitoring** — traces the target process and all its children spawned via `fork()`
- **Real-time connection logging** — captures outgoing TCP connection attempts via eBPF tracepoints
- **IP blocking** — blocks TCP connections to specific addresses using `cgroup/connect4` and `cgroup/connect6`
- **Address statistics** — tracks connection counts per destination address
- **CO-RE support** — compiled once, runs on any kernel 5.14+ with BTF enabled
- **Low overhead** — eBPF programs run in kernel space without modifying kernel source

## Requirements

### Build
- Rust stable
- clang
- bpftool
- libbpf-devel

### Runtime
- Linux kernel 5.14+ with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- Root privileges or `CAP_BPF` + `CAP_NET_ADMIN`

## Installation

```bash
git clone https://github.com/VsKlsch/netlogger-rs
cd netlogger-rs
cargo build --release
```

Binaries will be available at:
- `target/release/netlogger-gui`
- `target/release/netlogger-cli`

## Usage

```bash
# GUI
sudo ./target/release/netlogger-gui --target-pid <PID>

# CLI
sudo ./target/release/netlogger-cli --target-pid <PID>
```

Replace `<PID>` with the PID of the process you want to monitor.

## Roadmap

> ⚠️ **Current status: 0.0.3** — approaching first public release.

- **0.0.3** — documentation, GitHub Actions CI, public release
- **0.0.4** — extended blocking modes, address map export, UDP monitoring via `sendto`/`sendmsg` tracepoints
- **0.1.0** — sandbox mode (launch target process through netlogger with a predefined blocking scheme), launch under a specific user identity while retaining root privileges for BPF, workspace crates refactoring

## License

netlogger-rs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3.

See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

Bug reports and feature requests are accepted via [GitHub Issues](https://github.com/VsKlsch/netlogger-rs/issues).