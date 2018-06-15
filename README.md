hll_epbf
========================


Use eBPF to log the src addrs of inbound packets, and dst addrs of outbound packets, and use hyperloglog for estimation.

Usage
========================

```shell
$ make load
# compiles the bpf and loads it into your kernel
$ make read
# reads the counters collected by the bpf program and estimate the cardinality by hyperloglog
78 # inbound
998 # outbound
```
