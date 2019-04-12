void print(char *str) {}
_Noreturn void exit(int status) {
    __builtin_unreachable();
}
