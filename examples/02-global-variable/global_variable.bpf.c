#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

int target_pid = 0;

SEC("tracepoint/syscalls/sys_enter_read")
int tiny_global_variable() {
  if (target_pid != 0) {
    bpf_printk("Target PID: %d is reading file\n", target_pid);
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
