#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} ring_buff SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct event);
} heap SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
  struct event *e;
  int zero = 0;
  const char *filename_ptr;

  e = bpf_map_lookup_elem(&heap, &zero);
  if (!e) // should not happen
    return 0;

  filename_ptr = (const char *)ctx->args[0];
  bpf_printk("filename_ptr = %p\n", filename_ptr);

  e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  e->pid = bpf_get_current_pid_tgid() >> 32;

  bpf_get_current_comm(&e->command, sizeof(e->command));
  bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

  bpf_ringbuf_output(&ring_buff, e, sizeof(*e), 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
