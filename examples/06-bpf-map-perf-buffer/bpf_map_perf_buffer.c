#include "bpf_map_perf_buffer.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

struct event {
  int pid;
  int uid;
  char command[16];
  char filename[256];
};

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

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
  const struct event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  printf("%-8s %-5s %-7d %-16s %s\n", ts, "EXEC", e->pid, e->command,
         e->filename);
}

int main(int argc, char **argv) {
  struct perf_buffer *pb = NULL;
  struct perf_buffer_opts pb_opts = {
      .sz = sizeof(struct perf_buffer_opts),
  };
  struct bpf_map_perf_buffer_bpf *skel;
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Bump RLIMIT_MEMLOCK to create BPF maps */
  bump_memlock_rlimit();

  /* Clean handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // Load and verify BPF application
  skel = bpf_map_perf_buffer_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  err = bpf_map_perf_buffer_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  /* Set up perf buffer polling */
  pb = perf_buffer__new(bpf_map__fd(skel->maps.perf_buff), 8, handle_event,
                        NULL, NULL, &pb_opts);
  if (libbpf_get_error(pb)) {
    err = -1;
    fprintf(stderr, "Failed to create perf buffer\n");
    goto cleanup;
  }

  /* Process events */
  printf("%-8s %-5s %-7s %-16s %s\n", "TIME", "EVENT", "PID", "COMM",
         "FILENAME");
  // Keep running until user interrupts
  while (!exiting) {
    err = perf_buffer__poll(pb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  perf_buffer__free(pb);
  bpf_map_perf_buffer_bpf__destroy(skel);
  return -err;
}
