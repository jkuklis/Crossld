#ifndef CROSSLD_CALLED_INVOKER_H
#define CROSSLD_CALLED_INVOKER_H

// handler that actually calls 64-bit functions called by the 32-bit program
void called_invoker(const struct function *to_invoke);

#endif //CROSSLD_CALLED_INVOKER_H
