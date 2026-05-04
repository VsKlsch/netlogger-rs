# netlogger-rs

**netlogger-rs** is an eBPF-based network monitoring and filtering tool for Linux, written in Rust. Designed for malware researchers and security professionals.

Monitor and control network activity of a target process and its entire process tree.

## Features

- **Process tree monitoring** — traces the target process and all its children spawned via `fork()`
- **Real-time connection logging** — captures outgoing TCP (`connect`) and UDP (`sendmsg`) connection attempts via eBPF cgroup hooks
- **IP filtering with dual-mode profiles** — deny-all or pass-all base profile, combined with a per-address block/allow list; filtering applied at `cgroup/connect4/6` and `cgroup/sendmsg4/6`
- **Address statistics** — tracks connection counts per destination address
- **Profile export/import** — save and load IP list configurations as JSON
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

## Interface

### GUI (`netlogger-gui`)
- Real-time connection table with sorting by any field
- Address statistics with connection counts
- IP blocking and unblocking directly from the statistics table
- Summary panel with total connections and unique addresses

### CLI (`netlogger-cli`)
- Real-time connection logging to stdout

## Roadmap

> ⚠️ **Current status: 0.0.4** — documentation and code cleanup.

- **0.0.3** — GitHub Actions CI, public release
- **0.0.4** — consolidated cgroup-based filtering (TCP + UDP in cgroup hooks, removed sys_enter/sys_exit tracepoints), profiles import/export
- **0.1.0** — sandbox mode (launch target process through netlogger with a predefined blocking scheme), launch under a specific user identity while retaining root privileges for BPF, workspace crates refactoring, additional protocol support

## License

netlogger-rs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3.

See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

Bug reports and feature requests are accepted via [GitHub Issues](https://github.com/VsKlsch/netlogger-rs/issues).