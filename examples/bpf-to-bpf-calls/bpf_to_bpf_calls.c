#include "bpf_to_bpf_calls.skel.h"
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
  struct bpf_to_bpf_calls_bpf *skel;
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  // Open and load BPF application
  skel = bpf_to_bpf_calls_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = bpf_to_bpf_calls_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF object\n");
    goto cleanup;
  }

  err = bpf_to_bpf_calls_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  printf("Successfully attached! Tracing execve syscalls... Press Ctrl-C to "
         "stop.\n");

  // Keep running until user interrupts
  while (1) {
    sleep(1);
  }

cleanup:
  bpf_to_bpf_calls_bpf__destroy(skel);
  return -err;
}
