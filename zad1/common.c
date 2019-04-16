#include <stdio.h>
#include <stdlib.h>

#include "common.h"


static int error = EXIT_SUCCESS;

int get_status() {
    return error;
}

int assert_msg_v(int condition, char* msg, int verbose) {
    if (!condition) {
        if (verbose) {
            fprintf(stderr, "%s\n", msg);
        }
        error = EXIT_FAILURE;
        return error;
    }

    return 0;
}

int assert_msg(int condtion, char* msg) {
    return assert_msg_v(condtion, msg, 1);
}