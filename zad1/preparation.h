#ifndef CROSSLD_PREPARATION_H
#define CROSSLD_PREPARATION_H

#include "common.h"

void* create_stack();

// create exit function that jumps back to a specific address
// address after lret in crossld_start will be used for that
void* create_exit(long long return_address);

void* create_starter();

void* create_switcher();

void* program_cleanup(int nfuncs, struct State* state);

#endif //CROSSLD_PREPARATION_H
