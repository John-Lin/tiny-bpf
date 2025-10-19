# tiny-bpf

A minimal eBPF program that traces `execve` system calls using tracepoints.

## Prerequisites

- Linux kernel with eBPF support (kernel >= 5.x recommended)
- clang/LLVM
- bpftool
- libelf and zlib development libraries

## Building

### 1. Clone the repository with submodules

```bash
git clone --recurse-submodules <repository-url>
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

### 3. Build the project

```bash
make
```

## Running

```bash
sudo ./tp_execve
```

To view the traced syscalls in another terminal:

```bash
sudo bpftool prog tracelog
```

Press Ctrl-C to stop the program.
