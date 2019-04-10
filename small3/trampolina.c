#include <stdlib.h>
#include <stdio.h>

void formatter2(int param) {
    printf ("%d\n", param);
}

void formatter(int param) {
    printf ("%08x\n", param);
}

int main() {
    formatter2(1234);
    formatter2(5678);
    printf("address: %p\n", (void*)printf);
//    printf("%16x\n", (void*)printf);
    return 0;
}

/*
void formatter (int param) {
    register int res __asm__("rax");

    char c[] = "asd";

    __asm__ volatile (
        "jmp .lEnd\n"
        ".LC1:\n"
        ".string	\"a\"\n"
        ".lEnd:\n"
        : "=g"(res)
        :
        : "cc"
    );

    printf ("%08x\n", param);
}
*/

/*
void formatter (int param, char *c) {
    register int res __asm__("rax");

    __asm__ volatile (
        "jmp .lEnd\n"
        "."

        ".lEnd:"
        : "=g"(res)
        : "g"(c)
        : "cc"
    );

    printf (c, param);
}
*/
