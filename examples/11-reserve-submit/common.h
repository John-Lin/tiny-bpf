#ifndef __COMMON_H
#define __COMMON_H

/* definition of a sample sent to user-space from BPF program */
struct event {
  int pid;
  int uid;
  char comm[16];
  char filename[512];
};

#endif /* __COMMON_H */
