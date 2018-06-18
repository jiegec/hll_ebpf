/**
 * Copyright (C) 2018 Jiajie Chen
 *
 * This file is part of hll_ebpf.
 *
 * hll_ebpf is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * hll_ebpf is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with hll_ebpf.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <sys/sysinfo.h>
#define _GNU_SOURCE
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// Adapted from
// https://elixir.bootlin.com/linux/v4.9/source/samples/bpf/libbpf.c
// and its later versions

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

int bpf_map_update_elem(int fd, void *key, void *value,
                        unsigned long long flags) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = ptr_to_u64(key),
      .value = ptr_to_u64(value),
      .flags = flags,
  };

  return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

const static int b = 6;
const static int m = 1 << b;

void clear_file(const char *file) {
  int fd = bpf_obj_get(file);
  for (unsigned long i = 0; i < m; i++) {
    unsigned long value[128] = {0};
    bpf_map_update_elem(fd, &i, &value, 0);
  }
}

long read_file(const char *file) {
  int fd = bpf_obj_get(file);
  int M[m] = {0};
  int V = 0;
  double sum = 0;
  int nprocs = get_nprocs();
  for (unsigned long i = 0; i < m; i++) {
    unsigned long value[128] = {0};
    bpf_map_lookup_elem(fd, &i, &value);
    for (int j = 0; j < nprocs; j++) {
      M[i] = M[i] > value[j] ? M[i] : value[j];
    }
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
  return lround(E);
}

void clear_all() {
  clear_file("/sys/fs/bpf/tc/globals/hll_ebpf_in_saddr");
  clear_file("/sys/fs/bpf/tc/globals/hll_ebpf_out_daddr");
}

void read_all() {
  time_t now;
  time(&now);
  char buf[sizeof "2011-10-08T07:07:09Z"];
  strftime(buf, sizeof buf, "%FT%TZ", gmtime(&now));
  long in = read_file("/sys/fs/bpf/tc/globals/hll_ebpf_in_saddr"),
       out = read_file("/sys/fs/bpf/tc/globals/hll_ebpf_out_daddr");
  printf("In: %ld, Out: %ld\n", in, out);
  FILE *fp = fopen("hll.log", "a");
  if (fp != NULL) {
    fprintf(fp, "%s,%ld,%ld\n", buf, in, out);
    fclose(fp);
  }
}

int main(int argc, char **argv) {
  if (argc < 2 || strcmp(argv[1], "read") == 0) {
    printf("Reading hll counter (read, write):\n");
    read_all();
  } else if (argc >= 2 && strcmp(argv[1], "sample") == 0) {
    printf("Clearing hll counter.\n");
    clear_all();
    int time = 10;
    if (argc == 3) {
      time = atoi(argv[2]);
    }
    printf("Waiting for %d seconds\n", time);
    sleep(time);
    printf("Reading hll counter (read, write):\n");
    read_all();
  } else if (argc >= 2 && strcmp(argv[1], "watch") == 0) {
    int time = 10;
    if (argc == 3) {
      time = atoi(argv[2]);
    }
    while (1) {
      clear_all();
      sleep(time);
      printf("Reading hll counter (read, write):\n");
      read_all();
    }
  } else {
    printf("Usage: read_result [read|sample [nsecs]|watch [nsecs]]\n");
  }
  return 0;
}
