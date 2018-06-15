#include <linux/bpf.h>
#include <linux/bpf_common.h>
#define _GNU_SOURCE
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define __NR_bpf 321

static inline __u64 ptr_to_u64(const void *ptr) {
  return (__u64)(unsigned long)ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                          unsigned int size) {
  return syscall(SYS_bpf, cmd, attr, size);
}

int bpf_obj_get(const char *pathname) {
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.pathname = ptr_to_u64((void *)pathname);

  return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

int bpf_map_lookup_elem(int fd, const void *key, void *value) {
  union bpf_attr attr;

  bzero(&attr, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);

  return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int main() {
  int fd = bpf_obj_get("/sys/fs/bpf/tc/globals/my_map");
  const static int b = 6;
  const static int m = 1 << b;
  int M[m] = {0};
  int V = 0;
  double sum = 0;
  for (unsigned long i = 0; i < m; i++) {
    unsigned long value[2] = {0};
    bpf_map_lookup_elem(fd, &i, &value);
    M[i] = value[0] > value[1] ? value[0] : value[1];
    if (M[i] == 0)
      V++;
    sum += pow(2, -M[i]);
  }
  double E = 0.709 * m * m / sum;
  if (E <= 5 * m / 2) {
    if (V != 0) {
      E = m * log(1.0 * m / V);
    }
  } else if (E > pow(2, 32) / 30) {
    E = -pow(2, 32) * log(1 - E / pow(2, 32));
  }
  printf("%ld\n", lround(E));
  return 0;
}
