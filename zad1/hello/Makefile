all: prepare hello-32 hello-64
clean:
	rm -f hello-32 hello-64 *.o # *.so

fakelib.so: fakelib.c
	gcc -m32 -shared -fPIC -o fakelib.so fakelib.c

hello-32.o: hello-32.c
	gcc -m32 -O3 -c -o hello-32.o hello-32.c

hello-32: hello-32.o fakelib.so
	ld -m elf_i386 -o hello-32 hello-32.o fakelib.so

hello-64: hello-64.c libcrossld.so
	gcc -O3 hello-64.c -o hello-64 libcrossld.so


prepare:
	cp ../crossld_main.c .
	cp ../../cmake-build-debug/libcrossld.so .