#ifndef CROSSLD_PREPARATION_H
#define CROSSLD_PREPARATION_H

#include "common.h"

void* create_stack();

void* create_exit(long long return_address);

void delete_stack(void *stack);

void* program_entry(const char *filename, const struct function *funcs, int nfuncs, void* exit_fun);

#endif //CROSSLD_PREPARATION_H
