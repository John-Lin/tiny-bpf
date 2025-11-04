#include "bpf_map_array.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_SYSCALLS 512

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
  struct bpf_map_array_bpf *skel;
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  // Open and load BPF application
  skel = bpf_map_array_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = bpf_map_array_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF object\n");
    goto cleanup;
  }

  err = bpf_map_array_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  printf("Successfully attached! Tracing execve syscalls... Press Ctrl-C to "
         "stop.\n");

  // Keep running until user interrupts
  while (1) {
    sleep(2);
    printf("---\n");

    for (int id = 0; id < MAX_SYSCALLS; id++) {
      __u8 val = 0;
      int key = id;

      err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.syscalls_seen), &key,
                                &val);
      if (err == 0 && val == 1)
        printf("syscall id %d was called\n", id);
    }
  }

cleanup:
  bpf_map_array_bpf__destroy(skel);
  return -err;
}
