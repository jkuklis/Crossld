#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "crossld.h"

#define ASSERT_SAME(received, expected, msg)         \
    if (received != expected) {                      \
        fprintf(stderr, "%s\n", msg);                \
        fprintf(stderr, "Expected: %d\n", expected); \
        fprintf(stderr, "Received: %d\n", received); \
        exit(EXIT_FAILURE);                          \
    }

#define ASSERT_DIFFERENT(received, expected, msg)         \
    if (received == expected) {                      \
        fprintf(stderr, "%s\n", msg);                \
        fprintf(stderr, "Expected: %d\n", expected); \
        fprintf(stderr, "Received: %d\n", received); \
        exit(EXIT_FAILURE);                          \
    }

static char heap[4 * 1024 * 1024];
static int esp = 0;

void *static_alloc(ssize_t size) {
    if (esp + size > (int)sizeof(heap)) {
        printf("Memory ERR: not enough space on the heap");
    }

    esp += size;
    return heap + esp - size;
}


void read_all(int fd, char *buf, size_t sz, off_t offset) {
    while(sz > 0) {
        ssize_t ret = pread(fd, buf, sz, offset);
        assert(ret > 0);
        buf += ret;
        sz -= ret;
        offset += ret;
    }
}

void safe_pread(int fd, void *buf, size_t count, off_t offset) {
    char *cur_buf = (char *)buf;
    while (count) {
        ssize_t read_res = pread(fd, cur_buf, count, offset);
        assert(read_res != -1);
        if (read_res == 0) {
            printf("pread error: unexpected EOF");
        }
        offset += read_res;
        cur_buf += read_res;
        count -= read_res;
    }
}

void safe_read(int fd, void *buf, size_t count) {
    char *cur_buf = (char *)buf;
    while (count) {
        ssize_t read_res = read(fd, cur_buf, count);
        assert(read_res != -1);
        if (read_res == 0) {
            printf("read error: unexpected EOF");
        }
        cur_buf += read_res;
        count -= read_res;
    }
}


Elf32_Ehdr get_elf_header(FILE *elf_file) {
    // get ELF header
    Elf32_Ehdr elf_header;

    if (elf_file) {
        fread(&elf_header, 1, sizeof(elf_header), elf_file);

        ASSERT_SAME(memcmp(elf_header.e_ident, ELFMAG, SELFMAG), 0, "Incorrect ELF: magic number")
        ASSERT_SAME(elf_header.e_type, ET_EXEC, "Incorrect ELF: not exec file type")
        ASSERT_SAME(elf_header.e_machine, EM_386, "Incorrect ELF: wrong architecture")
        ASSERT_SAME(elf_header.e_ident[EI_CLASS], ELFCLASS32, "Incorrect ELF: wrong bit architecture")
        ASSERT_SAME(elf_header.e_ident[EI_VERSION], EV_CURRENT, "Incorrect ELF: version")
        ASSERT_DIFFERENT(elf_header.e_phoff, 0, "Incorrect ELF: No program header table");
        ASSERT_DIFFERENT(elf_header.e_phnum, 0, "Incorrect ELF: No programs in ELF");
    }

    return elf_header;
}


Elf32_Phdr* get_program_headers(FILE *elf_file, const Elf32_Ehdr elf_header) {
    Elf32_Phdr *program_headers;
    ssize_t size = sizeof(Elf32_Phdr) * elf_header.e_phnum;
    fread(program_headers, 1, sizeof(*program_headers), elf_file + elf_header.e_phoff);

    return program_headers;
}


int do_all(const char *filename, const struct function *funcs, int nfuncs) {
    //    FILE* elf_file = fopen(filename, "rb");
//
//    Elf32_Ehdr elf_header = get_elf_header(elf_file);
//
//    Elf32_Phdr *program_headers = get_program_headers(elf_file, elf_header);
//
//    fclose(elf_file);

    int core_fd = open(filename, O_RDONLY);

    // get ELF header
    Elf32_Ehdr elf_header;
    {
        ssize_t size = sizeof(Elf32_Ehdr);
        safe_read(core_fd, (void *)&elf_header, size);

        ASSERT_SAME(memcmp(elf_header.e_ident, ELFMAG, SELFMAG), 0, "Incorrect ELF: magic number")
        ASSERT_SAME(elf_header.e_type, ET_EXEC, "Incorrect ELF: not exec file type")
        ASSERT_SAME(elf_header.e_machine, EM_386, "Incorrect ELF: wrong architecture")
        ASSERT_SAME(elf_header.e_ident[EI_CLASS], ELFCLASS32, "Incorrect ELF: wrong bit architecture")
        ASSERT_SAME(elf_header.e_ident[EI_VERSION], EV_CURRENT, "Incorrect ELF: version")
        ASSERT_DIFFERENT(elf_header.e_phoff, 0, "Incorrect ELF: No program header table");
        ASSERT_DIFFERENT(elf_header.e_phnum, 0, "Incorrect ELF: No programs in ELF");
    }

    Elf32_Phdr *program_hdrs;
    {
        ssize_t size = sizeof(Elf32_Phdr) * elf_header.e_phnum;

        program_hdrs = static_alloc(size);
        safe_pread(core_fd, (void *)program_hdrs, size, elf_header.e_phoff);
    }

//    size_t size = 1024 * 1024;

    for(int i = 0; i < elf_header.e_phnum; ++i) {
        if(program_hdrs[i].p_type == PT_LOAD && program_hdrs[i].p_memsz > 0) {
            void *segment;

            // p_vaddr

            if ((segment = mmap(NULL, program_hdrs[i].p_memsz, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, 0, 0)) == MAP_FAILED) {
                printf("mmap failed!\n");
            }

//            if (segment != (void*)program_hdrs[i].p_vaddr) {
//
//            }

            safe_pread(core_fd, segment, program_hdrs[i].p_filesz, program_hdrs[i].p_offset);

            memset(segment + program_hdrs[i].p_memsz, 0, program_hdrs[i].p_memsz - program_hdrs[i].p_filesz);

            mprotect(segment, program_hdrs[i].p_memsz, PROT_EXEC);
        }
    }

//    printf("Hi!\n");
}



extern char trampoline_begin;
extern char trampoline_fun_ptr;
extern char trampoline_end;

__asm__ (
        "trampoline_begin:\n"
            "subl $8, %esp;\n"
            "movl $0x33, 4(%esp);\n"   // change to 64 bit
            "movl $0, %eax;\n"         // move function pointer to be invoked
        "trampoline_fun_ptr:\n"
            "movl %eax, (%esp);\n"
            "lret;\n"
        "trampoline_end:\n"
);


void* create_trampoline(void* invoker_function) {
    size_t codelen = &trampoline_end - &trampoline_begin;

    size_t fun_ptr_offset = (&trampoline_fun_ptr - &trampoline_begin) - 4;

    void *trampoline;

    if ((trampoline = mmap(NULL, codelen,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
                           -1, 0)) == MAP_FAILED) {
        printf("Map error for trampoline!\n");
    }

    memcpy(trampoline, &trampoline_begin, codelen);

    memcpy(trampoline + fun_ptr_offset, invoker_function, 4);

    if (mprotect(trampoline, codelen, PROT_READ | PROT_EXEC))
        perror("mprotect");

    return trampoline;
}

extern char arg_begin;
extern char arg32_0;
extern char arg32_1;
extern char arg32_2;
extern char arg32_3;
extern char arg32_4;
extern char arg32_5;
extern char arg32_more;
extern char arg32_after;
extern char arg64_0;
extern char arg64_1;
extern char arg64_2;
extern char arg64_3;
extern char arg64_4;
extern char arg64_5;
extern char arg64_more;
extern char arg64_after;
extern char arg_transfer;
extern char arg_transfer_after;
extern char arg_end;
extern char call_invoked;
extern char call_argument;
extern char call_end;
extern char comeback_begin;
extern char comeback_end;
extern char comeback_fun_ptr;
extern char just_ret;

__asm__ (
        "arg_begin:\n"
        "arg32_0:\n"
            "movl 256(%rsp), %edi;\n"
        "arg32_1:\n"
            "movl 256(%rsp), %esi;\n"
        "arg32_2:\n"
            "movl 256(%rsp), %edx;\n"
        "arg32_3:\n"
            "movl 256(%rsp), %ecx;\n"
        "arg32_4:\n"
            "movl 256(%rsp), %r8d;\n"
        "arg32_5:\n"
            "movl 256(%rsp), %r9d;\n"
        "arg32_more:\n"
            "movl 256(%rsp), %r10d;\n"
        "arg32_after:\n"

        "arg64_0:\n"
            "movq 256(%rsp), %rdi;\n"
        "arg64_1:\n"
            "movq 256(%rsp), %rsi;\n"
        "arg64_2:\n"
            "movq 256(%rsp), %rdx;\n"
        "arg64_3:\n"
            "movq 256(%rsp), %rcx;\n"
        "arg64_4:\n"
            "movq 256(%rsp), %r8;\n"
        "arg64_5:\n"
            "movq 256(%rsp), %r9;\n"
        "arg64_more:\n"
            "movq 256(%rsp), %r10;\n"
        "arg64_after:\n"

        "arg_transfer:\n"
            "movq %r10, 256(%rsp);\n"
        "arg_transfer_after:\n"
        "arg_end:\n"

        "call_invoked:\n"
            "subq $8, %rsp;\n"
            "movabs $0, %rax;\n"
        "call_argument:\n"
            "callq  *%rax;\n"
            "addq $8, %rsp;\n"
        "call_end:\n"

        // check that returned value is correct

        "comeback_begin:\n"
            "subq $8, %rsp;\n"
            "movq $0x23, 4(%rsp);\n"   // change to 32 bit
            "movq $0, %rax;\n"         // move function pointer to be invoked
        "comeback_fun_ptr:\n"
            "movq %rax, (%rsp);\n"
            "lret;\n"
        "comeback_end:\n"


//            "movl (%esp), %edi;\n"
//            "movl (%esp), %esi;\n"
//            "movl (%esp), %edx;\n"
//            "movl 16(%esp), %edx;\n"
//            "movl 256(%esp), %edx;\n"
//            "movl 4096(%esp), %edx;\n"
//            "movl 4(%esp), %edi;\n"
//            "movl 8(%esp), %esi;\n"
//            "movl 12(%esp), %edx;\n"
//            "movl 16(%esp), %ecx;\n"
//            "movl 20(%esp), %r8d;\n"
//            "movl 24(%esp), %r9d;\n"
//            "movl 28(%esp), %r10d;\n"
//            "movl %r10d, 8(%esp);\n"
);


__asm__ (
        "just_ret:\n"
            "ret;\n"
        "just_ret_after:"
);

int relocate_argument(void *invoker_position, char* arg, char* arg_next, int rsp_from_offset) {
    int length = arg_next - arg;
    memcpy(invoker_position, arg, length);
    memcpy(invoker_position + length - 4, &rsp_from_offset, 4);
    return length;
}


int put_argument_on_stack(void *invoker_position, int rsp_to_offset) {
    int length = &arg_transfer_after - &arg_transfer;
    memcpy(invoker_position, &arg_transfer, length);
    memcpy(invoker_position + length - 4, &rsp_to_offset, 4);
}


void* create_invoker(const struct function *to_invoke) {
    size_t codelen = 2 * 8 * (to_invoke->nargs) + (&comeback_end - &call_invoked);

    void* invoker;

    if ((invoker = mmap(NULL, codelen,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
                        -1, 0)) == MAP_FAILED) {
        printf("Map error for invoker!\n");
    }

    int rsp_from_offset = 8;
    int rsp_to_offset = 8;
    int invoker_offset = 0;

    char* arg32[] = {&arg32_0, &arg32_1, &arg32_2, &arg32_3, &arg32_4, &arg32_5, &arg32_more, &arg32_after};
    char* arg64[] = {&arg64_0, &arg64_1, &arg64_2, &arg64_3, &arg64_4, &arg64_5, &arg64_more, &arg64_after};

    int length;
    for (int i = 0; i < to_invoke->nargs; i++) {
        enum type arg_type = to_invoke->args[i];
        switch(arg_type) {
            case TYPE_VOID:
                printf("Void argument!\n");
                return NULL;
                break;
            case TYPE_INT:
            case TYPE_LONG:
            case TYPE_UNSIGNED_INT:
            case TYPE_UNSIGNED_LONG:
            case TYPE_PTR:
                if (i < 6) {
                    length = relocate_argument(invoker + invoker_offset, arg32[i], arg32[i+1], rsp_from_offset);
                } else {
                    length = relocate_argument(invoker + invoker_offset, &arg32_more, &arg32_after, rsp_from_offset);
                    length += put_argument_on_stack(invoker + invoker_offset + length, rsp_to_offset);
                    rsp_to_offset += 8;
                }
                rsp_from_offset += 4;
                invoker_offset += length;
                break;
            case TYPE_LONG_LONG:
            case TYPE_UNSIGNED_LONG_LONG:
                if (i < 6) {
                    length = relocate_argument(invoker + invoker_offset, arg64[i], arg64[i+1], rsp_from_offset);
                } else {
                    length = relocate_argument(invoker + invoker_offset, &arg64_more, &arg64_after, rsp_from_offset);
                    length += put_argument_on_stack(invoker + invoker_offset + length, rsp_to_offset);
                    rsp_to_offset += 8;
                }
                rsp_from_offset += 8;
                invoker_offset += length;
                break;

        }
    }

    length = &call_end - &call_invoked;
    memcpy(invoker + invoker_offset, &call_invoked, length);
    memcpy(invoker + invoker_offset + (&call_argument - &call_invoked) - 8, &(to_invoke->name), 8);
    invoker_offset += length;

    return invoker;
}


int crossld_start(const char *filename, const struct function *funcs, int nfuncs) {
    do_all(filename, funcs, nfuncs);

    void* trampolines_addresses[nfuncs];

    for (int i = 0; i < nfuncs; ++i) {

        void *invoker = create_invoker(&funcs[i]);

        trampolines_addresses[i] = create_trampoline(invoker);
    }

    void *stack;

    int stack_size = 4 * 1024;

    if ((stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0)) == MAP_FAILED)
        printf("stack map error\n");

    stack = (void*) (((uint64_t) stack) + 4096 - 4);


    return 0;
}