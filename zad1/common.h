#ifndef CROSSLD_COMMON_H
#define CROSSLD_COMMON_H

#include "crossld.h"

struct State {
    void *return_addr;
    void *stack;
    void *entry;
    enum type exit_types[1];
    struct function exit_struct;
    void *starter;
    void *switcher;
    void **trampolines;
    void **invokers;
};

// assert that condition is true, if not, mark error
// with current implementation - print message
// to change that behaviour: CHECK operation instead of CHECK_VERBOSE in assert_msg implementation
int assert_msg(int condition, char* msg);

// get error status
int get_status();

// reset error status
void reset_status();

#endif //CROSSLD_COMMON_H
