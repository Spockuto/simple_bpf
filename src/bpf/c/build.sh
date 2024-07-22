clang -g -O2 -target bpf -c ../openat.bpf.c -o openat.bpf.o
clang -O2 -g -Wall -I/usr/include -I/usr/include/bpf -o load_bpf load_bpf.c -lbpf