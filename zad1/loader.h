#ifndef CROSSLD_LOADER_H
#define CROSSLD_LOADER_H

#include "crossld.h"

void *image_load (char *elf_start, const struct function *funcs, int nfuncs, const struct function *exit_struct);

#endif //CROSSLD_LOADER_H
