#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, u64);
} counter_table SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(void *ctx) {
  u64 uid;
  u64 counter = 0;
  u64 *p;

  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  p = bpf_map_lookup_elem(&counter_table, &uid);
  if (p != 0) {
    counter = *p;
  }
  counter++;
  bpf_map_update_elem(&counter_table, &uid, &counter, BPF_ANY);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
