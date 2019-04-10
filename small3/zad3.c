#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

int foo (char i) {return i*2;}

int (*return_foo()) (char c) {
    return foo;
}

typedef int (*typed) (char);

typed fun() {
    return foo;
}

typedef void (*formatter) (int);

void formatFun(int param) {
    printf ("%08x\n", param);
}

void formFun(int param) {

}

formatter const make_formatter (const char *format) {
    size_t length = 4096;
    void* addr = mmap(NULL, length, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_SHARED, -1, 0);

    mprotect(addr, length, PROT_EXEC);

    return addr;

    /*

    register int res __asm__("rax");

    __asm__ volatile (
        ".lEnd:"
        : "=g"(res)
        : "g"(format)
        : "cc"
    );

    return formatFun;

    */
}

int main () {
    formatter x08_format = make_formatter ("%08x\n");
    formatter xalt_format = make_formatter ("%#x\n");
    formatter d_format = make_formatter ("%d\n");
    formatter verbose_format = make_formatter ("Liczba: %9d!\n");

    int (*ad)(char) = return_foo("c");

    x08_format (0x1234);
    xalt_format (0x5678);
    d_format (0x9abc);
    verbose_format (0xdef0);

    return 0;
}
