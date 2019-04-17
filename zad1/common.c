#include <stdio.h>
#include <stdlib.h>

#include "common.h"

enum Operation {
    CHECK_VERBOSE,
    CHECK,
    GET,
    RESET
};

int assert_handler(int condition, char* msg, enum Operation operation) {
    static int status = EXIT_SUCCESS;

    int verbose = 0;

    switch(operation) {
        case CHECK_VERBOSE:
            verbose = 1;
        case CHECK:
            if (!condition) {
                if (verbose) {
                    fprintf(stderr, "%s\n", msg);
                }
                status = EXIT_FAILURE;
                return 1;
            }
            break;
        case GET:
            return status;

        case RESET:
            status = EXIT_SUCCESS;
            break;
    }

    return 0;
}

int assert_msg(int condtion, char* msg) {
    return assert_handler(condtion, msg, CHECK_VERBOSE);
}

int get_status() {
    return assert_handler(0, "", GET);
}

void reset_status() {
    assert_handler(0, "", RESET);
}