TARGET = hello
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

all: $(TARGET) $(BPF_OBJ)
.PHONY: all 

$(TARGET): $(USER_C) $(USER_SKEL) 
	gcc -Wall -o $(TARGET) $(USER_C) -L../../libbpf/src -l:libbpf.a -lelf -lz

%.bpf.o: %.bpf.c
	clang \
	    -target bpf \
	    -idirafter /usr/include/$(shell gcc -dumpmachine) \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
	- rm $(USER_SKEL)
