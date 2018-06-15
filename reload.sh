#!/bin/sh
sudo tc qdisc add dev enp0s3 clsact
sudo tc filter del dev enp0s3 egress
sudo tc filter add dev enp0s3 egress bpf obj sockex1_kern.o
