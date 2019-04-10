#!/bin/bash

gcc -m32 -g -Wall -o loader loader.c -ldl

gcc -m32 -pie -fPIE -o elf elf.c

# ./loader elf
 ./loader ../z1-hello-world/hello/hello-32