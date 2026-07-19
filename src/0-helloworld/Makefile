ARCH := $(shell uname -m)

loader: helloworld.o
	gcc -o loader loader.c -lbpf

helloworld.o:
	clang -O2 -target bpf -c helloworld.bpf.c -o helloworld.o -I/usr/include/$(ARCH)-linux-gnu

clean:
	rm -fr helloworld.o loader
