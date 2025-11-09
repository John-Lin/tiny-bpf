#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(u32));
} perf_buff SEC(".maps");

struct data_t {
  int pid;
  int uid;
  char comm[16];
  char filename[256];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
  struct data_t data = {};
  const char *filename_ptr;
  filename_ptr = (const char *)ctx->args[0];

  data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  data.pid = bpf_get_current_pid_tgid() >> 32;

  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename_ptr);

  bpf_perf_event_output(ctx, &perf_buff, BPF_F_CURRENT_CPU, &data,
                        sizeof(data));
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
