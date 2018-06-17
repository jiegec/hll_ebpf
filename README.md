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

How can it be useful?
======================

For example, DDoS detection.

```
$ sudo ./read_result watch 5
# Output the hll estimated in/out remote addrs within each 5 seconds
```

If you use nmap to scan, you can see a spike in the numbers.
If you are DDos-ed, you can see the number get quite large.
Thus, it can be used for a efficient DDoS detection metric.

License
======================

Licensed under GPL v3, with some sources taken from Linux.
