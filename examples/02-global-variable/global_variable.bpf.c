#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// .bss section for uninitialized global variable
// runtime dynamic state, such as counters, flags
int read_count;

// .data section for initialized global variable
// configurable parameters, thresholds, etc.
bool disable_logging = true;
int target_pid = -1;

// .rodata section for read-only global variable
// constant strings, version info, etc.
const char str[] = "1.0";

SEC("tracepoint/syscalls/sys_enter_read")
int tiny_global_variable() {
  if (target_pid != -1 && !disable_logging) {
    bpf_printk("Target PID: %d is reading file\n", target_pid);
    read_count++;
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
