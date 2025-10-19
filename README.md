# tiny-bpf

A collection of minimal eBPF examples demonstrating various eBPF capabilities.

## Prerequisites

- Linux kernel with eBPF support (kernel >= 5.x recommended)
- clang/LLVM (for compiling BPF programs)
- bpftool (for generating skeleton headers and viewing trace output)
- libelf and zlib development libraries

## Getting Started

### 1. Clone the repository with submodules

```bash
git clone --recurse-submodules https://github.com/John-Lin/tiny-bpf.git
```

Or if you already cloned without submodules:

```bash
git submodule update --init --recursive
```

### 2. Build libbpf

```bash
cd libbpf/src
make
cd ../..
```

## Examples

Each example is self-contained in the `examples/` directory with its own Makefile and README.

- **[hello](examples/hello/)** - Minimal eBPF program that traces `execve` system calls
- **[bpf-to-bpf-calls](examples/bpf-to-bpf-calls/)** - Demonstrates BPF-to-BPF function calls

See each example's README for build and usage instructions.
