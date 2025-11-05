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
  __type(value, struct data_t);
} heap SEC(".maps");

struct data_t {
  int pid;
  int uid;
  char command[16];
  char filename[512];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
  struct data_t *data;
  int zero = 0;
  const char *filename_ptr;

  data = bpf_map_lookup_elem(&heap, &zero);
  if (!data) // should not happen
    return 0;

  filename_ptr = (const char *)ctx->args[0];

  data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  data->pid = bpf_get_current_pid_tgid() >> 32;

  bpf_get_current_comm(&data->command, sizeof(data->command));
  bpf_probe_read_user_str(&data->filename, sizeof(data->filename),
                          filename_ptr);

  bpf_ringbuf_output(&ring_buff, data, sizeof(*data), 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
