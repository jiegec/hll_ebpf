bpf.o: bpf.c bpf_helpers.h
	clang -O2 -I /usr/src/linux-headers-4.16.0-2-common/include -I /usr/src/linux-headers-4.16.0-2-common/arch/x86/include -emit-llvm -c bpf.c -o - | llc -march=bpf -filetype=obj -o bpf.o

read_result: read_result.c
	clang read_result.c -o read_result -lm

.PHONY: load
load: bpf.o
	sudo tc qdisc add dev enp0s3 clsact || true
	sudo tc filter del dev enp0s3 egress
	sudo tc filter add dev enp0s3 egress bpf obj bpf.o
