#ifndef CROSSLD_LOADER_H
#define CROSSLD_LOADER_H

#include "crossld.h"

void *image_load (char *elf_start, const struct function *funcs, int nfuncs, void* exit_fun);

#endif //CROSSLD_LOADER_H
