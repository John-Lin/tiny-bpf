# tiny-bpf agent guide

## Examples

- Keep each example self-contained and focused on one eBPF concept. When changing a map or event layout, check both the BPF program and its userspace consumer.
- Preserve the distinction between Linux UAPI headers and generated `vmlinux.h`: UAPI-only examples must build without `/sys/kernel/btf/vmlinux`. When changing header generation, verify that a failed command leaves no partial header for the next build.
- Use syscall constants from the target architecture's headers. `12-tail-calls` currently uses x86-64 syscall numbers; an ARM64 attach does not verify its dispatch.

## Verification

1. Run eBPF build and runtime checks on Linux. On macOS, use the [README's Lima setup](README.md#2-start-a-lima-vm-optional) when either check is needed. Follow the README for prerequisites and the vendored libbpf build.
2. Run `make -C examples/<directory>` for each affected example. For toolchain or libbpf changes, build all examples from a clean tree; Make can otherwise reuse stale generated headers or skip relinking. Keep generated headers and binaries out of Git.
3. For behavior changes, load and attach the program, trigger the relevant event, and check the expected output or map value. Test XDP on an isolated interface, not the VM's SSH interface. `13-fentry` needs kernel BTF and BPF trampoline support on the target architecture.
4. Report the kernel and architecture, separating build, attach, and event checks.

## libbpf upgrades

Pin an upstream release in `libbpf/`. Compare the old and new pins with the same toolchain and kernel. Record the header source and `bpftool` version: the Makefiles resolve `<bpf/...>` headers and `bpftool` from the build environment, while linking the vendored `libbpf.a`.
