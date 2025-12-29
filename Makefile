.PHONY: generate build vmlinux clean

KERNEL_VERSION := $(shell uname -r)
LIBBPF_INCLUDE := /usr/src/linux-headers-$(KERNEL_VERSION)/tools/bpf/resolve_btfids/libbpf/include

all: build

generate:
	go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -cc clang -no-strip -target bpfel -cflags "-O2 -g -Wall -I$(LIBBPF_INCLUDE)" bpf bpf/tasks.c

build: generate
	go build -o psc

vmlinux: 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

test:
	go test ./...

install: build
	install -m 755 psc /usr/local/bin/psc

clean:
	@rm -f bpf_*.go bpf_*.o psc
