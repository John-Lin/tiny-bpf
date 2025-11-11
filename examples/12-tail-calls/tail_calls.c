#include "tail_calls.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

int main(int argc, char **argv) {
  struct tail_calls_bpf *skel;
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Bump RLIMIT_MEMLOCK to create BPF maps */
  bump_memlock_rlimit();

  /* Clean handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // Open and load BPF application
  skel = tail_calls_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = tail_calls_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF object\n");
    goto cleanup;
  }

  err = tail_calls_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  int fd_prog_ignore = bpf_program__fd(skel->progs.ignore_opcode);
  int fd_prog_exec = bpf_program__fd(skel->progs.hello_exec);
  int fd_prog_timer = bpf_program__fd(skel->progs.hello_timer);
  int fd_map = bpf_map__fd(skel->maps.syscall_progs);

  if (fd_prog_ignore < 0 || fd_prog_exec < 0 || fd_prog_timer < 0 ||
      fd_map < 0) {
    fprintf(stderr, "Failed to get file descriptors for programs or map\n");
    goto cleanup;
  }

  __u32 max_entries = bpf_map__max_entries(skel->maps.syscall_progs);
  for (__u32 i = 0; i < max_entries; i++) {
    if (bpf_map_update_elem(fd_map, &i, &fd_prog_ignore, BPF_ANY) != 0) {
      fprintf(stderr, "Failed to initialize map at key %u\n", i);
    }
  }

  __u32 k;

  k = 59;
  if (bpf_map_update_elem(fd_map, &k, &fd_prog_exec, BPF_ANY) != 0) {
    fprintf(stderr, "Failed to update map for execve syscall\n");
  }

  for (k = 222; k <= 226; k++) {
    if (bpf_map_update_elem(fd_map, &k, &fd_prog_timer, BPF_ANY) != 0) {
      fprintf(stderr, "Failed to update map for timer syscalls\n");
    }
  }

  for (k = 21; k <= 25; k++) {
    if (bpf_map_update_elem(fd_map, &k, &fd_prog_ignore, BPF_ANY) != 0) {
      fprintf(stderr, "Failed to update map for obsolete syscalls\n");
    }
  }

  printf("Successfully attached! Tracing sys_enter with tail calls... Press "
         "Ctrl-C to "
         "stop.\n");

  // Keep running until user interrupts
  while (!exiting) {
    sleep(1);
  }

cleanup:
  tail_calls_bpf__destroy(skel);
  return -err;
}
