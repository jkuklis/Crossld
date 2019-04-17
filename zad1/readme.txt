Crossld project

To build, run these commands from the main directory:
    
    cmake .
    make

These commands will compile libcrossld.so, file will be located in the main directory.

This shared library can used for invoking 32-bit programs that can use 64-bit functions. The "crossld_start" function sets up the helper state and loads a given program into memory, then jumps into its entry point. 

If this program calls a function with a name that is among the substituted ones, a trampoline will be used to jump into 64-bit code, then call the redefined function, then come back to 32-bit code.
 
This library by default exports symbol "exit", which can be used to come back to the "crossld_start", clean up resources and return the exit code.

Currently debug information about encountered errors is printed to stderr. To change this behaviour, change the operation used by assert_msg in common.c from CHECK_VERBOSE to CHECK.