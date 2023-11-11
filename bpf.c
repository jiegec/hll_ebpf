/**
 * Copyright (C) 2018-2023 Jiajie Chen
 * 
 * This file is part of hll_ebpf.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * 
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") hll_ebpf_in_saddr = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
    .pinning = 2 // PIN_GLOBAL_NS
};

struct bpf_map_def SEC("maps") hll_ebpf_out_daddr = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
    .pinning = 2 // PIN_GLOBAL_NS
};

uint32_t Murmur3(uint32_t input, uint32_t seed) {
  uint32_t c1 = 0xcc9e2d51;
  uint32_t c2 = 0x1b873593;
  uint32_t m = 5;
  uint32_t n = 0xe6546b64;
  uint32_t k;

  uint32_t hash = seed;

  k = input;
  k = k * c1;
  k = (k << 15) | (k >> 17);
  k = k * c2;
  hash = hash ^ k;
  hash = (hash << 13) | (hash >> 19);
  hash = hash * m + n;

  hash = hash ^ 0x4;
  hash = hash ^ (hash >> 16);
  hash = hash * 0x85ebca6b;
  hash = hash ^ (hash >> 13);
  hash = hash * 0xc2b2ae35;
  hash = hash ^ (hash >> 16);
  return hash;
}

uint32_t nlz(uint32_t x) {
  if (x == 0)
    return 32;
  uint32_t n = 0;
  if ((x & 0xFFFF0000) == 0) {
    n = n + 16;
    x = x << 16;
  }
  if ((x & 0xFF000000) == 0) {
    n = n + 8;
    x = x << 8;
  }
  if ((x & 0xF0000000) == 0) {
    n = n + 4;
    x = x << 4;
  }
  if ((x & 0x30000000) == 0) {
    n = n + 2;
    x = x << 2;
  }
  if ((x & 0x10000000) == 0) {
    n = n + 1;
    x = x << 1;
  }
  return n;
}

inline uint32_t get_daddr(struct __sk_buff *skb) {
  return load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
}

inline uint32_t get_saddr(struct __sk_buff *skb) {
  return load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
}

inline void update_hll(struct bpf_map_def *map, uint32_t hash) {
  uint32_t b = 6, m = 1 << b; // m = 2^b
  uint32_t index = (hash >> (32 - b));
  uint32_t count = nlz(hash << b) + 1;

  if (index > 256) {
    // impossible, pacify checker
    return ;
  }

  uint32_t *addr = bpf_map_lookup_elem(map, &index);
  if (addr) {
    if (*addr < count) {
      *addr = count;
    }
  }
}

SEC("out_daddr")
int bpf_out_daddr(struct __sk_buff *skb) {
  uint32_t daddr = get_daddr(skb);
  uint32_t hash = Murmur3(daddr, 0);
  update_hll(&hll_ebpf_out_daddr, hash);
  return 0;
}

SEC("in_saddr")
int bpf_in_saddr(struct __sk_buff *skb) {
  uint32_t saddr = get_saddr(skb);
  uint32_t hash = Murmur3(saddr, 0);
  update_hll(&hll_ebpf_in_saddr, hash);
  return 0;
}

char _license[] SEC("license") = "GPL";
