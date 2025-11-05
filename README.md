# tiny-bpf

A collection of minimal eBPF examples demonstrating various eBPF capabilities.

## Prerequisites

- Linux kernel with eBPF support (kernel >= 5.x recommended)
- clang/LLVM (for compiling BPF programs)
- bpftool (for generating skeleton headers and viewing trace output)
- libelf and zlib development libraries

### Installing Prerequisites on Arch Linux

```bash
sudo pacman -S libelf zlib clang llvm bpf
```

## Getting Started

### 1. Clone the repository with submodules

```bash
git clone --recurse-submodules https://github.com/John-Lin/tiny-bpf.git
cd tiny-bpf
```

Or if you already cloned without submodules:

```bash
cd tiny-bpf
git submodule update --init --recursive
```

### 2. Build libbpf from source

```bash
cd libbpf/src
make
cd ../..
```

Note: The examples use static linking and link directly to `libbpf/src/libbpf.a`, so you don't need `make install`.

## Examples

Each example is self-contained in the `examples/` directory with its own Makefile.

- **[01-hello](examples/01-hello/)** - Minimal eBPF program that traces `execve` system calls
- **[02-global-variable](examples/02-global-variable/)** - Using global variables to pass data from userspace to kernel space
- **[03-bpf-to-bpf-calls](examples/03-bpf-to-bpf-calls/)** - Demonstrates BPF-to-BPF function calls
- **[04-open-file](examples/04-open-file/)** - Tracing file open operations via `openat` syscall
- **[05-bpf-map-array](examples/05-bpf-map-array/)** - Using BPF array map to track syscalls
- **[06-bpf-map-hash](examples/06-bpf-map-hash/)** - Using BPF hash map to count `execve` calls per user
- **[07-bpf-map-perf-buffer](examples/07-bpf-map-perf-buffer/)** - Using perf event array to send data to userspace
- **[08-bpf-map-ring-buffer](examples/08-bpf-map-ring-buffer/)** - Using ring buffer to send data to userspace
- **[09-bpf-map-percpu-array](examples/09-bpf-map-percpu-array/)** - Using per-CPU array map for packet counting in XDP
- **[10-scratch-buffer](examples/10-scratch-buffer/)** - Using per-CPU array as scratch buffer for large data structures

See each example's README for build and usage instructions (where available).
