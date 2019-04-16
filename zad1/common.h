#ifndef CROSSLD_COMMON_H
#define CROSSLD_COMMON_H

#include "crossld.h"


struct State {
    void *rbp;
    void *res;
    void *return_addr;
    void *stack;
    void *exit_fun;
    void *entry;
    enum type exit_types[1];
    struct function exit_struct;
    void *starter;
};


struct State state;



int assert_msg(int condition, char* msg);

int get_status();

#endif //CROSSLD_COMMON_H
