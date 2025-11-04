#include "bpf_map_percpu_array.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
  struct bpf_map_percpu_array_bpf *skel;
  struct bpf_link *link = NULL;
  int err;
  int ncpus = libbpf_num_possible_cpus();
  __u32 key = 0;
  __u64 values[ncpus];
  __u64 sum;

  printf("Number of possible CPUs: %d\n", ncpus);

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  // Open and load BPF application
  skel = bpf_map_percpu_array_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = bpf_map_percpu_array_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF object\n");
    goto cleanup;
  }

  /* Attach XDP program to wlan0 interface */
  int ifindex = if_nametoindex("wlan0");
  if (ifindex == 0) {
    fprintf(stderr, "Failed to get ifindex for wlan0\n");
    err = 1;
    goto cleanup;
  }

  link = bpf_program__attach_xdp(skel->progs.count_packets, ifindex);
  if (!link) {
    fprintf(stderr, "Failed to attach XDP program to wlan0\n");
    err = 1;
    goto cleanup;
  }

  printf("Successfully attached to wlan0! Tracing packet-in... Press Ctrl-C to "
         "stop.\n");

  // Keep running until user interrupts
  while (1) {
    sleep(1);
    sum = 0;

    bpf_map_lookup_elem(bpf_map__fd(skel->maps.packet_cnt), &key, values);
    for (int i = 0; i < ncpus; i++)
      sum += values[i];

    printf("Total packets: %llu\n", sum);
  }

cleanup:
  bpf_link__destroy(link);
  bpf_map_percpu_array_bpf__destroy(skel);
  return -err;
}
