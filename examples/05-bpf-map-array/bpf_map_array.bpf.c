#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 512);
  __type(key, int);
  __type(value, u8);
} syscalls_seen SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
  u32 id = ctx->id;
  u8 *flag;

  flag = bpf_map_lookup_elem(&syscalls_seen, &id);
  if (!flag) /* can't happen */
    return 0;

  if (*flag == 0)
    *flag = 1;

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
