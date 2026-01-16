.PHONY: generate build vmlinux clean

KERNEL_VERSION := $(shell uname -r)
LIBBPF_INCLUDE := /usr/src/linux-headers-$(KERNEL_VERSION)/tools/bpf/resolve_btfids/libbpf/include

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/loresuso/psc/cmd.Version=$(VERSION) \
           -X github.com/loresuso/psc/cmd.Commit=$(COMMIT) \
           -X github.com/loresuso/psc/cmd.BuildDate=$(DATE)

all: build

generate: vmlinux
	go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -cc clang -no-strip -target bpfel -cflags "-O2 -g -Wall -I$(LIBBPF_INCLUDE)" tasks bpf/tasks.c
	go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -cc clang -no-strip -target bpfel -cflags "-O2 -g -Wall -I$(LIBBPF_INCLUDE)" files bpf/files.c

build: generate
	go build -ldflags "$(LDFLAGS)" -o psc

vmlinux: 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

test:
	go test ./...

install: build
	install -m 755 psc /usr/local/bin/psc

clean:
	@rm -f tasks_*.go tasks_*.o files_*.go files_*.o psc
