simple_bpf
==========

Proof of Concept for loading eBPF hooks with `libbpf-rs`. The current hook tries to capture if a file defined at `MONITORED_FILE` was accessed.

# Build 
```sh
cargo build --release
./target/release/simple_bpf

# Static build might be possible (works 70% of time)
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu
```