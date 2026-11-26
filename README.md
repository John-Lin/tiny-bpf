# tiny-bpf

A collection of minimal eBPF examples demonstrating various eBPF capabilities.

## Prerequisites

- Linux kernel >= 5.14
- Linux userspace API (UAPI) headers (for examples that build without `vmlinux.h`)
- clang/LLVM (for compiling BPF programs)
- bpftool (for generating skeleton headers and viewing trace output)
- libelf and zlib development libraries

Examples `01`, `02`, `06`, `09`, and `12` do not need access to the kernel's `vmlinux` [BTF](https://docs.kernel.org/bpf/btf.html). The other examples use `/sys/kernel/btf/vmlinux` to generate `vmlinux.h` and need kernel BTF at load time. All examples still build BPF objects with their own BTF and use `bpftool` to generate skeletons.

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

### 2. Start a Lima VM (optional)

For a dedicated Linux development VM, use the [Lima](https://lima-vm.io/)
configuration in [`infra/lima/lima.yaml`](infra/lima/lima.yaml). It requires
Lima 2.0 or newer and provisions a Debian 13 guest with the eBPF build tools
and kernel BTF.

Run from the repository root:

```bash
limactl start --name=tiny-bpf-dev --mount-only .:w ./infra/lima/lima.yaml
limactl shell tiny-bpf-dev
```

Only the repository is mounted from the host, with write access so the guest
can build the examples. Continue with the steps below inside the guest. Use
`sudo` in the guest when running examples that load eBPF programs, and exit the
guest before running `limactl stop tiny-bpf-dev` on the host. For subsequent
sessions, restart the VM with `limactl start tiny-bpf-dev`.

### 3. Build libbpf from source

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
- **[11-reserve-submit](examples/11-reserve-submit/)** - Using ring buffer reserve/submit API to send data to userspace
- **[12-tail-calls](examples/12-tail-calls/)** - Using BPF tail calls to chain multiple BPF programs via program array map

See each example's README for build and usage instructions (where available).
