#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

void execute_generated_machine_code(const uint8_t *code, size_t codelen)
{
    // in order to manipulate memory protection, we must work with
    // whole pages allocated directly from the operating system.
    static size_t pagesize;
    if (!pagesize) {
        pagesize = sysconf(_SC_PAGESIZE);
        if (pagesize == (size_t)-1) perror("getpagesize");
    }

    // allocate at least enough space for the code + 1 byte
    // (so that there will be at least one INT3 - see below),
    // rounded up to a multiple of the system page size.
    size_t rounded_codesize = ((codelen + 1 + pagesize - 1)
                               / pagesize) * pagesize;

    void *executable_area = mmap(0, rounded_codesize,
                                 PROT_READ|PROT_WRITE,
                                 MAP_PRIVATE|MAP_ANONYMOUS,
                                 -1, 0);
    if (!executable_area) perror("mmap");

    // at this point, executable_area points to memory that is writable but
    // *not* executable.  load the code into it.
    memcpy(executable_area, code, codelen);

    // fill the space at the end with INT3 instructions, to guarantee
    // a prompt crash if the generated code runs off the end.
    // must change this if generating code for non-x86.
    memset(executable_area + codelen, 0xCC, rounded_codesize - codelen);

    // make executable_area actually executable (and unwritable)
    if (mprotect(executable_area, rounded_codesize, PROT_READ|PROT_EXEC))
        perror("mprotect");

    // now we can call it. passing arguments / receiving return values
    // is left as an exercise (consult libffi source code for clues).
    ((void (*)(void)) executable_area)();

    munmap(executable_area, rounded_codesize);
}

int test() {
    uint8_t code[13] = {0x90, 0xc3};
    size_t codelen = sizeof(code);
    execute_generated_machine_code(code, codelen);
}

void formatFun(int param) {
    printf ("%08x\n", param);
}

void formatFun2(int param) {
    printf ("%08x\n", param);
}

void formatFun3(int param) {
    printf ("%08x\n", param);
}

void formatFun4(char *format) {
    printf("%s\n", format);
}

/*
0000000000000000 <formatter>:
   0:	55                   	push   %rbp
   1:	48 89 e5             	mov    %rsp,%rbp
   4:	48 83 ec 10          	sub    $0x10,%rsp
   8:	89 7d fc             	mov    %edi,-0x4(%rbp)
   b:	8b 45 fc             	mov    -0x4(%rbp),%eax
   e:	89 c6                	mov    %eax,%esi
  10:	48 8d 3d 00 00 00 00 	lea    0x0(%rip),%rdi        # 17 <formatter+0x17>
			13: R_X86_64_PC32	.rodata-0x4
  17:	b8 00 00 00 00       	mov    $0x0,%eax
  1c:	e8 00 00 00 00       	callq  21 <formatter2+0x21>
			1d: R_X86_64_PLT32	printf-0x4
  21:	90                   	nop
  22:	c9                   	leaveq
  23:	c3                   	retq
 */

/*
0000000000000a5f <formatFun>:
 a5f:	55                   	push   %rbp
 a60:	48 89 e5             	mov    %rsp,%rbp
 a63:	48 83 ec 10          	sub    $0x10,%rsp
 a67:	89 7d fc             	mov    %edi,-0x4(%rbp)
 a6a:	8b 45 fc             	mov    -0x4(%rbp),%eax
 a6d:	89 c6                	mov    %eax,%esi
 a6f:	48 8d 3d 08 03 00 00 	lea    0x308(%rip),%rdi        # d7e <_IO_stdin_used+0x1e>
 a76:	b8 00 00 00 00       	mov    $0x0,%eax
 a7b:	e8 c0 fc ff ff       	callq  740 <printf@plt>
 a80:	90                   	nop
 a81:	c9                   	leaveq
 a82:	c3                   	retq
 */



extern void dynamic();
extern void dynamic_args();
extern void dynamic_end();

__asm__  (
        "dynamic:"
        "mov %rdi, %rsi;"
        "dynamic_args:"
        "movabs    $0, %rdi;"
        "movabs    $0, %rax;"
        "jmp *%rax;"
        "ret;"
        "dynamic_end:"
        );

typedef void (*formatter) (int);

formatter const make_formatter (const char *format) {

    // printf("Format: %p\n", format);

    // printf("%s\n", format);

    long long formatAddress = (long long) &format;

    // printf("%llu\n", formatLong);

    uint8_t fb[8]; // formatBytes

    for (int i = 0; i < 8; i++) {
        fb[i] = (formatAddress >> (8*i)) % 256;
        // printf("%x\n", fb[i]);
    }

    /*

    uint8_t code[100] = {
            0x55,
            0x48, 0x89, 0xe5,
            0x48, 0x83, 0xec, 0x10,
            0x89, 0x7d, 0xfc,
            0x8b, 0x45, 0xfc,
            0x89, 0xc6,
            0x48, 0xbf, // put format to %rdi
            fb[0], fb[1], fb[2], fb[3], fb[4], fb[5], fb[6], fb[7], // format bytes reversed
            0xb8, 0x00, 0x00, 0x00, 0x00,
//            0xe8, 0xc0, 0xfc, 0xff, 0xff, // call printf
            0x48, 0xb8, // put printf to %rax
//            pb[0], pb[1], pb[2], pb[3], pb[4], pb[5], pb[6], pb[7], // printf bytes reversed
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xd0, // call rax
            0x90,
            0xc9,
            0xc3
    };

     */

    size_t codelen = dynamic_end - dynamic;

//    size_t codelen = 37;

    static size_t pagesize;
    if (!pagesize) {
        pagesize = sysconf(_SC_PAGESIZE);
        if (pagesize == (size_t) - 1) perror("getpagesize");
    }

    size_t rounded_codesize = ((codelen + 1 + pagesize - 1)
                               / pagesize) * pagesize;

    void *executable_area = mmap(0, rounded_codesize,
                                 PROT_READ|PROT_WRITE,
                                 MAP_PRIVATE|MAP_ANONYMOUS,
                                 -1, 0);
    if (!executable_area) perror("mmap");

    memcpy(executable_area, dynamic, codelen);

    long long printfAddress = (long long) ((void *)&printf); // - (void *)(executable_area + 33); // 33 - pos of printf

    uint8_t pb[8]; // printfBytes

    for (int i = 0; i < 8; i++) {
        pb[i] = (printfAddress >> (8*i)) % 256;
//        memset(executable_area + 33 + i, pb[i], 1);
//        printf("%x\n", fb[i]);
    }

    memcpy(executable_area + (dynamic_args - dynamic) + 12, &printfAddress, 8);
    memcpy(executable_area + (dynamic_args - dynamic) + 2, formatAddress, 8);

    //memset(executable_area + codelen, 0xCC, rounded_codesize - codelen);

    if (mprotect(executable_area, rounded_codesize, PROT_READ|PROT_EXEC))
        perror("mprotect");

    return (formatter) executable_area;
}


int main() {
    char f1[] = "%08x\n";
    char f2[] = "%#x\n";
    char f3[] = "%d\n";
    char f4[] = "Liczba: %9d!\n";

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