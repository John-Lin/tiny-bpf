#include "global_variable.skel.h"
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
  struct global_variable_bpf *skel;
  int err;

  if (argc < 2) {
    printf("Please provide a pid: ./global_variable 5566\n");
    return 1;
  }

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  // Open and load BPF application
  skel = global_variable_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }

  int pid = atoi(argv[1]);
  // check the value of enable_logging in .data
  // sudo bpftool map dump name global_v.data
  skel->data->target_pid = pid;
  skel->data->disable_logging = false;

  /* Load & verify BPF programs */
  err = global_variable_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF object\n");
    goto cleanup;
  }

  err = global_variable_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  printf("Successfully attached! Tracing read syscalls... Press Ctrl-C to "
         "stop.\n");

  printf("Monitoring read syscalls for PID %d\n", pid);
  // Keep running until user interrupts
  while (1) {
    sleep(1);
    // Read the read_count from .bss
    printf("read_count: %d\n", skel->bss->read_count);
  }

cleanup:
  global_variable_bpf__destroy(skel);
  return -err;
}
