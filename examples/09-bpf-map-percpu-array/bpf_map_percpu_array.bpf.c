#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u64);
} packet_cnt SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
  u32 key = 0;
  u64 *val;

  val = bpf_map_lookup_elem(&packet_cnt, &key);
  if (val)
    (*val)++;
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
