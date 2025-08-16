# ebpf-memory-monitor

## Prerequisites

For now, using the library requires building the ebpf programs locally. This may change in the future, but currently the following is required:

1. stable rust toolchains: `rustup toolchain install stable`
2. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
3. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
4. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
5. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
6. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo test --release --config 'target."cfg(all())".runner="sudo -E"' -- --nocapture
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## License

With the exception of eBPF code, ebpf-memory-monitor is distributed under the terms
of the [MIT license].

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
