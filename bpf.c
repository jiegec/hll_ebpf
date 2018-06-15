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

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") hll_ebpf_in_saddr = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 256,
    .pinning = 2 // PIN_GLOBAL_NS
};

struct bpf_map_def SEC("maps") hll_ebpf_out_daddr = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 256,
    .pinning = 2 // PIN_GLOBAL_NS
};

u32 Murmur3(u32 input, u32 seed) {
  u32 c1 = 0xcc9e2d51;
  u32 c2 = 0x1b873593;
  u32 m = 5;
  u32 n = 0xe6546b64;
  u32 k;

  u32 hash = seed;

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

inline u32 get_daddr(struct __sk_buff *skb) {
  return load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
}

inline u32 get_saddr(struct __sk_buff *skb) {
  return load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
}

inline void update_hll(struct bpf_map_def *map, u32 hash) {
  u32 b = 6, m = 1 << b; // m = 2^b
  u32 index = (hash >> (32 - b));
  u32 count = nlz(hash << b) + 1;

  if (index > 256) {
    // impossible, pacify checker
    return ;
  }

  u32 *addr = bpf_map_lookup_elem(map, &index);
  if (addr) {
    if (*addr < count) {
      *addr = count;
    }
  }
}

SEC("out_daddr")
int bpf_out_daddr(struct __sk_buff *skb) {
  u32 daddr = get_daddr(skb);
  u32 hash = Murmur3(daddr, 0);
  update_hll(&hll_ebpf_out_daddr, hash);
  return 0;
}

SEC("in_saddr")
int bpf_in_saddr(struct __sk_buff *skb) {
  u32 saddr = get_saddr(skb);
  u32 hash = Murmur3(saddr, 0);
  update_hll(&hll_ebpf_in_saddr, hash);
  return 0;
}

char _license[] SEC("license") = "GPL";
