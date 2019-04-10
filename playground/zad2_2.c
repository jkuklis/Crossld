#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/unistd.h>

#define STACK 8192
#define N 10

extern void writeA();
extern void writeB();
extern void exitSuccess();
extern void waitPid(int pid, int* statusPtr, int flags);

int wA() {
	for (int i = 0; i < N; i++) {
		writeA();
	}
	exitSuccess();
	return 0;
}

int wB() {
	for (int i = 0; i < N; i++) {
        writeB();
	}	
	return 0;
}

int clone_VM (char* stack_, int flags_) {
    register int sys_nr __asm__("rax") = __NR_clone;
    register int res __asm__("rax");
    register char* stack __asm__("rsi") = stack_;
    register int flags __asm__("rdi") = flags_;

    __asm__ volatile (
        "mov $0, %%r10\n"
        "syscall\n"
        "cmp $0, %%rax\n"
        "jne .lEnd\n"
        "call wA\n"
        ".lEnd:"
        : "=g"(res)
        : "g"(sys_nr), "g"(stack), "g"(flags)
        : "cc", "rcx", "r11", "memory"
    );

    return res;
}


int main() {
	void **stack;
	
    stack = (void **) malloc(STACK) + STACK / sizeof(*stack);

	if (!stack) {
		printf("Stack not allocated");
	}

    int pid = clone_VM((char*)stack + STACK, CLONE_VM);

	if (pid != -1) {
		wB();
		int *statusPtr;
		waitPid(pid, statusPtr, 0);
		exitSuccess();
	}

	return 0;
}
