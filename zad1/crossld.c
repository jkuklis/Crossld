#include "crossld.h"
#include "common.h"
#include "preparation.h"

struct State state;

void prepare_stack() {
    state.stack = create_stack();
}

void prepare_exit() {
    state.exit_fun = create_exit((long long)&(state.return_addr));
}

void prepare_entry(const char *filename, const struct function *funcs, int nfuncs) {
    state.entry = program_entry(filename, funcs, nfuncs, state.exit_fun);
}

void prepare_state(const char *filename, const struct function *funcs, int nfuncs) {
    prepare_stack();
    prepare_exit();
    prepare_entry(filename, funcs, nfuncs);
}

void clean_state() {
    delete_stack(state.stack);
}

__attribute__ ((visibility("default")))
int crossld_start(const char *filename, const struct function *funcs, int nfuncs) {
    prepare_state(filename, funcs, nfuncs);
    if (get_status()) {
        return -1;
    }

//    clean_state();
    return 0;
}