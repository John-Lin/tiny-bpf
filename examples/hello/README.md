# Hello World eBPF Example

A minimal eBPF program that traces `execve` system calls and prints "Hello World!" for each execution.

## Building

```bash
make
```

## Running

```bash
sudo ./hello
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

You should see "Hello World!" printed each time a new process is executed.

## Cleaning

```bash
make clean
```
