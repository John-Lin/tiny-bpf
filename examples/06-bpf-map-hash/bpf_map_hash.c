#include "bpf_map_hash.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
  struct bpf_map_hash_bpf *skel;
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  // Open and load BPF application
  skel = bpf_map_hash_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = bpf_map_hash_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF object\n");
    goto cleanup;
  }

  err = bpf_map_hash_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  printf("Successfully attached! Tracing execve syscalls... Press Ctrl-C to "
         "stop.\n");

  // Keep running until user interrupts
  while (1) {
    sleep(2);

    __u32 key, next_key;
    __u64 value;
    int map_fd = bpf_map__fd(skel->maps.counter_table);

    printf("Counter table: ");

    // Iterate through all entries in the map
    __u32 *prev_key = NULL;
    while (bpf_map_get_next_key(map_fd, prev_key, &next_key) == 0) {
      if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
        printf("ID %u: %llu\t", next_key, value);
      }
      key = next_key;
      prev_key = &key;
    }

    printf("\n");
  }

cleanup:
  bpf_map_hash_bpf__destroy(skel);
  return -err;
}
