#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Checking the format of the tracepoint event
// sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
// ID: 747
// format:
//         field:unsigned short common_type;  offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;  offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;  offset:3;       size:1;
//         signed:0; field:int common_pid;   offset:4;  size:4; signed:1;
//
//         field:int __syscall_nr; offset:8;  size:4; signed:1;
//         field:int dfd;  offset:16;size:8;  signed:0;
//         field:const char * filename;       offset:24;      size:8; signed:0;
//         field:int flags;        offset:32; size:8; signed:0;
//         field:umode_t mode;     offset:40; size:8; signed:0;

// or using bpftrace to list the tracepoint fields
// sudo bpftrace -vl tracepoint:syscalls:sys_enter_openat
// tracepoint:syscalls:sys_enter_openat
//     int __syscall_nr
//     int dfd
//     const char * filename
//     int flags
//     umode_t mode

// To get BTF info for vmlinux
// sudo bpftool btf dump file /sys/kernel/btf/vmlinux | less
// find "trace_event_raw_sys_enter"

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
  // user space pointer to filename is the second argument
  const char *filename_ptr = (const char *)ctx->args[1];
  char filename[256];

  if (filename_ptr) {
    bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);
    bpf_printk("File: %s", filename);
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
