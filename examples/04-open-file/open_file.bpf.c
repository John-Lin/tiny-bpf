#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Checking the format of the tracepoint event
// sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format

// or using bpftrace to list the tracepoint fields
// sudo bpftrace -vl tracepoint:syscalls:sys_enter_openat

struct sys_enter_openat_args {
  __u64 unused;
  int dfd;
  const char *filename;
  int flags;
  umode_t mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct sys_enter_openat_args *ctx) {
  bpf_printk("File %s", ctx->filename);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
