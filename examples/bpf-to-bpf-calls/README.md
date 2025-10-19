# BPF-to-BPF Calls Example

Demonstrates BPF-to-BPF function calls by extracting syscall numbers from tracepoint context.

## Building

```bash
make
```

## Running

```bash
sudo ./bpf_to_bpf_calls
```

## Viewing Output

In another terminal, view the trace output:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Or use bpftool:

```bash
sudo bpftool prog tracelog
```

You should see syscall numbers printed for each `execve` call.

## Cleaning

```bash
make clean
```
