IFACE?=enp0s3
KERN?=$(shell uname -r | awk -F '-' 'BEGIN{OFS="-"}{NF--; print $0}')

bpf.bc: bpf.c bpf_helpers.h
	clang -O2 -emit-llvm -c bpf.c -o bpf.bc

bpf.o: bpf.bc
	llc -march=bpf -filetype=obj -o bpf.o bpf.bc

read_result: read_result.c
	clang read_result.c -o read_result -lm

.PHONY: load
load: bpf.o
	sudo tc qdisc add dev ${IFACE} clsact || true
	sudo tc filter del dev ${IFACE} egress
	sudo tc filter add dev ${IFACE} egress bpf obj bpf.o sec out_daddr
	sudo tc filter del dev ${IFACE} ingress
	sudo tc filter add dev ${IFACE} ingress bpf obj bpf.o sec in_saddr

status:
	sudo tc filter show dev ${IFACE} egress
	sudo tc filter show dev ${IFACE} ingress

unload:
	sudo tc filter del dev ${IFACE} egress
	sudo tc filter del dev ${IFACE} ingress

.PHONY: read
read: read_result
	sudo ./read_result

clean:
	rm -rf ./read_result bpf.bc bpf.o hll.log
