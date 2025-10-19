#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

static __attribute__((noinline)) int
get_opcode(struct trace_event_raw_sys_enter *ctx) {
  return ctx->id;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tiny_tp_execve(struct trace_event_raw_sys_enter *ctx) {
  int opcode = get_opcode(ctx);
  bpf_printk("Syscall: %d\n", opcode);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
