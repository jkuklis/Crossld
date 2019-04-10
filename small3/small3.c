#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

extern void dynamic_begin();
extern void dynamic_args();
extern void dynamic_end();

__asm__  (
"dynamic_begin:"
    "mov        %rdi, %rsi;"
"dynamic_args:"
    "movabs     $0, %rdi;"
    "movabs     $0, %rax;"
    "jmp        *%rax;"
    "ret;"
"dynamic_end:"
);

typedef void (*formatter) (int);

formatter const make_formatter (const char *format) {

    long long formatAddress = (long long) &format;

    size_t codelen = dynamic_end - dynamic_begin;

    void *executable_area = mmap(0, codelen,
                                 PROT_READ|PROT_WRITE,
                                 MAP_PRIVATE|MAP_ANONYMOUS,
                                 -1, 0);

    if (!executable_area) perror("mmap");

    memcpy(executable_area, dynamic_begin, codelen);

    long long printfAddress = (long long) ((void *)&printf);

    memcpy(executable_area + (dynamic_args - dynamic_begin) + 2, (void*)formatAddress, 8);
    memcpy(executable_area + (dynamic_args - dynamic_begin) + 12, &printfAddress, 8);

    if (mprotect(executable_area, codelen, PROT_READ|PROT_EXEC))
        perror("mprotect");

    return (formatter) executable_area;
}


int main() {
    formatter x08_format = make_formatter ("%08x\n");
    formatter xalt_format = make_formatter ("%#x\n");
    formatter d_format = make_formatter ("%d\n");
    formatter verbose_format = make_formatter ("Liczba: %9d!\n");

    x08_format (0x1234);
    xalt_format (0x5678);
    d_format (0x9abc);
    verbose_format (0xdef0);

    return 0;
}