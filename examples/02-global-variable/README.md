# Global Variable Example

Demonstrates how to use global variables in eBPF programs to pass data from userspace to kernel space. This example filters `read` system calls by a specific process ID.

## Building

```bash
make
```

## Running

Provide a target PID to monitor:

```bash
sudo ./global_variable <PID>
```

For example, to monitor process 1234:

```bash
sudo ./global_variable 1234
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

You should see messages printed each time the target process performs a `read` syscall.

## Cleaning

```bash
make clean
```
