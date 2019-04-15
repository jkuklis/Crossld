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
    }
}

int assert_msg(int condtion, char* msg) {
    assert_msg_v(condtion, msg, 1);
}