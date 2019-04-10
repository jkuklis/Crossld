#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

unsigned char *charp;
unsigned char *bin;

void hohoho()
{
    printf("merry mas\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int what;

    charp = malloc(10101);
    memset(charp, 0xc3, 10101);
    mprotect(charp, 10101, PROT_EXEC | PROT_READ | PROT_WRITE);

    __asm__("leal charp, %eax");
    __asm__("call *(%eax)" );

    printf("am I alive?\n");

    char *more = strdup("more heap operations");
    printf("%s\n", more);

    FILE* f = fopen("foo", "rb");

    fseek(f, 0, SEEK_END);
    unsigned int len = ftell(f);
    fseek(f, 0, SEEK_SET);

    bin = (char*)malloc(len);
    printf("read in %lu\n", fread(bin, 1, len, f));
    printf("%p\n", bin);

    fclose(f);
    mprotect(&bin, 10101, PROT_EXEC | PROT_READ | PROT_WRITE);

    asm volatile ("movl %0, %%eax"::"g"(bin));
    __asm__("addl $0x674, %eax");
    __asm__("call *(%eax)" );
    fflush(stdout);

    return 0;
}
