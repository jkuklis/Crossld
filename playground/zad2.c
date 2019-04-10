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

int writeA() {
	const char a[] = "A\n";
	for (int i = 0; i < N; i++) {
		syscall(1, 1, a, sizeof(a) - 1);
	}
	_exit(EXIT_SUCCESS);
	return 0;
}

int writeB() {
	const char b[] = "B\n";
	for (int i = 0; i < N; i++) {
		syscall(1, 1, b, sizeof(b) - 1);
	}	
	return 0;
}

int main() {
	void *stack;
	stack = malloc(STACK);
	
	if (!stack) {
		printf("Stack not allocated");
	}

	int pid = clone(&writeA, (char*)stack + STACK, CLONE_VM, 0);

	if (pid != -1) {
		writeB();
		int *statusPtr;
		syscall(247, pid, statusPtr, 0);
		syscall(60, EXIT_SUCCESS);
	}

	return 0;
}
