#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// program array map to hold references to other BPF programs
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 512); // syscall numbers can be large
  __type(key, __u32);
  __type(value, __u32); // program FD
} syscall_progs SEC(".maps");

SEC("raw_tracepoint/sys_enter") int hello(struct bpf_raw_tracepoint_args *ctx) {
  __u32 opcode = (__u32)ctx->args[1]; // args[1] holds syscall numbers

  // attempt tail call to the program registered for this syscall
  bpf_tail_call(ctx, &syscall_progs, opcode);

  // missed tail call
  bpf_printk("Another syscall: %d\n", ctx->args[0]);
  return 0;
}

// tail call programs for specific syscalls
SEC("raw_tracepoint")
int hello_exec(void *ctx) {
  bpf_printk("Executing a program\n");
  return 0;
}

SEC("raw_tracepoint")
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
  __u32 opcode = (__u32)ctx->args[1];
  switch (opcode) {
  case 222: // creating a timer
    bpf_printk("Creating a time\n");
    break;
  case 226: // deleting a timer
    bpf_printk("Deleting a timer\n");
    break;
  default:
    bpf_printk("Other timer-related syscall: %d\n", opcode);
    break;
  }
  return 0;
}

SEC("raw_tracepoint")
int ignore_opcode(void *ctx) {
  // do nothing
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
