#ifndef CROSSLD_COMMON_H
#define CROSSLD_COMMON_H

#include "crossld.h"


struct State {
    void *rbp;
    void *return_addr;
    void *stack;
    void *exit_fun;
    void *entry;
    void *switch_32_to_64;
    void *switch_64_to_32;
};


int assert_msg(int condition, char* msg);

int get_status();

#endif //CROSSLD_COMMON_H
