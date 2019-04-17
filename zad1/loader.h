#ifndef CROSSLD_LOADER_H
#define CROSSLD_LOADER_H

#include "crossld.h"
#include "common.h"

// load the program into memory, create trampolines and change the relocation addresses
void *image_load (char *elf_start, const struct function *funcs, int nfuncs, struct State* state);

void unload_program(char* elf_start);

#endif //CROSSLD_LOADER_H
