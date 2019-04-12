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


int do_all(const char *filename, const struct function *funcs, int nfuncs) {
    Elf32_Ehdr elf_header;
    {
        ssize_t size = sizeof(Elf32_Ehdr);

        ASSERT_SAME(memcmp(elf_header.e_ident, ELFMAG, SELFMAG), 0, "Incorrect ELF: magic number")
        ASSERT_SAME(elf_header.e_type, ET_EXEC, "Incorrect ELF: not exec file type")
        ASSERT_SAME(elf_header.e_machine, EM_386, "Incorrect ELF: wrong architecture")
        ASSERT_SAME(elf_header.e_ident[EI_CLASS], ELFCLASS32, "Incorrect ELF: wrong bit architecture")
        ASSERT_SAME(elf_header.e_ident[EI_VERSION], EV_CURRENT, "Incorrect ELF: version")
        ASSERT_DIFFERENT(elf_header.e_phoff, 0, "Incorrect ELF: No program header table");
        ASSERT_DIFFERENT(elf_header.e_phnum, 0, "Incorrect ELF: No programs in ELF");
    }
}


extern char switch_32;
extern char switch_32_ret;
extern char switch_32_end;
extern char just_ret;
extern char after_ret;

extern char switch_32_2;
extern char switch_32_end_2;


__asm__ (

        "switch_32:\n"
        ".code32\n"
            "pushl $0x2b\n"
            "popl %ds\n"
            "pushl $0x2b\n"
            "popl %es\n"
        "switch_32_ret:"
            "jmp *%ecx\n"

        ".code64\n"
        "switch_32_end:\n"
);

__asm__ (
        "just_ret:\n"
            "ret\n"
        "after_ret:\n"
);

__asm__ (

        "switch_32_2:\n"
        ".code32\n"
            "pushl $0x2b\n"
            "popl %ds\n"
            "pushl $0x2b\n"
            "popl %es\n"
            "addl $8, %ebp\n"

            "leave\n"
            "ret\n"

        ".code64\n"
        "switch_32_end_2:\n"
);


void* generate_switch() {
    void* switcher;

    int code_len = &switch_32_end - &switch_32;

    if ((switcher = mmap(NULL, code_len, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0)) == MAP_FAILED) {
        printf("bad switch mmap\n");
    }

    memcpy(switcher, &switch_32, code_len);

    mprotect(switcher, code_len, PROT_EXEC);

    return switcher;
}

void* switcher_64() {
    void* returner;

    int len_switch = &switch_32_end_2 - &switch_32_2;
    int len_ret = 0;
//    int len_ret = &after_ret - &just_ret;
    int code_len = len_switch + len_ret;

    if ((returner = mmap(NULL, code_len, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0)) == MAP_FAILED) {
        printf("bad switch mmap\n");
    }

    memcpy(returner, &switch_32_2, len_switch);
//    memcpy(returner + len_switch, &just_ret, len_ret);

    mprotect(returner, code_len, PROT_EXEC);

    return returner;
}


extern char trampoline_begin;
extern char trampoline_fun_ptr;
extern char trampoline_end;

__asm__ (
        "trampoline_begin:\n"
            ".code32\n"
            "subl $8, %esp\n"
            "movl $0x33, 4(%esp);\n"   // change to 64 bit
            "movl $0, %eax;\n"         // move function pointer to be invoked
        "trampoline_fun_ptr:\n"
            "movl %eax, (%esp);\n"
//            "movl $0, %ecx\n"
//            "jmp *%ecx\n"
            "lret;\n"
            ".code64\n"
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

    memcpy(trampoline + fun_ptr_offset, &invoker_function, 4);

    if (mprotect(trampoline, codelen, PROT_READ | PROT_EXEC))
        perror("mprotect");

    return trampoline;
}

extern char invoker_end;
extern char invoker_struct;
extern char invoker_handler;
extern char invoker_begin;

__asm__ (
    "invoker_begin:\n"
        "movabs $0, %rdi\n"
    "invoker_struct:\n"
        "movabs $0, %rsi\n"
    "invoker_args:\n"
        "movabs $0, %rax\n"
    "invoker_handler:\n"
        "jmp *%rax\n"
    "invoker_end:\n"
);

void real_invoker(const struct function *to_invoke) {
    void *args[to_invoke->nargs];

    void* switcher = switcher_64();

    size_t stack_position = 12;
    size_t args_offset = 8;

    void* arg_val = 0;


    for (int i = 0; i < to_invoke->nargs; i++) {
        enum type arg_type = to_invoke->args[i];
        switch (arg_type) {
            case TYPE_VOID:
                printf("Void argument!\n");
                return;
                break;
            case TYPE_INT:
            case TYPE_LONG:
            case TYPE_UNSIGNED_INT:
            case TYPE_UNSIGNED_LONG:
            case TYPE_PTR:
                __asm__ volatile (
                    "movq %1, %%rax\n"
                    "lea (%%rbp, %%rax, 1), %%rax\n"
                    "movl (%%rax), %%eax\n"
                    "movl %%eax, %0\n"
                    : "=m" (arg_val)
                    : "g" (stack_position)
                );
                stack_position += 4;
                break;
            case TYPE_LONG_LONG:
            case TYPE_UNSIGNED_LONG_LONG:
                __asm__ volatile (
                    "movq %1, %%rax\n"
                    "lea (%%rbp, %%rax, 1), %%rax\n"
                    "movq (%%rax), %%rax\n"
                    "movq %%rax, %0\n"
                    : "=m" (arg_val)
                    : "g" (stack_position)
                );
                stack_position += 8;
                break;
        }

        args[i] = arg_val;
    }

    for (int i = 0; i < to_invoke->nargs; i++) {
        switch(i) {
            case 0:
                __asm__ volatile (
                  "movq %0, %%rdi"
                  :: "g" (args[i])
                );
            case 1:
                __asm__ volatile (
                    "movq %0, %%rsi"
                :: "g" (args[i])
                );
            case 2:
                __asm__ volatile (
                    "movq %0, %%rdx"
                :: "g" (args[i])
                );
            case 3:
                __asm__ volatile (
                    "movq %0, %%rcx"
                :: "g" (args[i])
                );
            case 4:
                __asm__ volatile (
                    "movq %0, %%r8"
                :: "g" (args[i])
                );
            case 5:
                __asm__ volatile (
                    "movq %0, %%r9"
                :: "g" (args[i])
                );
            default:
                __asm__ volatile (
                    "movq %0, %%r10\n"
                    "movq %1, %%rax\n"
                    "lea (%%rsp, %%rax, 1), %%rax\n"
                    "movl %%r10d, (%%rax)\n"
                : "=m" (args[i])
                : "g" (args_offset)
                );

        }
    }

    __asm__ volatile (
        "call *%0\n"
        :: "g" (to_invoke->code)
    );
    __asm__ volatile (
        "subq $8, %%rsp\n"
        "movl $0x23, 4(%%rsp);\n"
        "movq %0, %%rcx;\n"
        "movl %%ecx, (%%rsp);\n"
        "lret\n"
        :
        : "g" (switcher)
    );

//    printf("%s\n", to_invoke->name);

}

//void* create_invoker(const struct function *to_invoke) {
void* create_invoker(const struct function* to_invoke) {
    size_t code_len = &invoker_end - &invoker_begin;
    size_t struct_offset = (&invoker_struct - &invoker_begin) - 8;
    size_t handler_offset = (&invoker_handler - &invoker_begin) - 8;

    void* invoker;

    if ((invoker = mmap(NULL, code_len,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
                        -1, 0)) == MAP_FAILED) {
        printf("Map error for invoker!\n");
    }

    long long address = (long long)&real_invoker;

    memcpy(invoker, &invoker_begin, code_len);
    memcpy(invoker + struct_offset, &to_invoke, 8);
    memcpy(invoker + handler_offset, &address, 8);

    mprotect(invoker, code_len, PROT_READ | PROT_EXEC);

    return invoker;
}


int is_image_valid(Elf32_Ehdr *hdr)
{
    return 1;
}


struct function default_exit_struct(void *exit_hook) {
    enum type exit_types[] = {TYPE_INT};
    struct function exit_struct = {"exit", exit_types, 1, TYPE_VOID, exit_hook};
    return exit_struct;
}

void relocate(Elf32_Shdr* shdr, const Elf32_Sym* syms, const char* strings, const char* src,
        const struct function *funcs, int nfuncs, const struct function* exit_struct)
{
    Elf32_Rel* rel = (Elf32_Rel*)(src + shdr->sh_offset);
    int j;
    void* invoker;
    void* trampoline;
    for(j = 0; j < shdr->sh_size / sizeof(Elf32_Rel); j += 1) {
        const char* sym = strings + syms[ELF32_R_SYM(rel[j].r_info)].st_name;

        switch(ELF32_R_TYPE(rel[j].r_info)) {
            case R_386_JMP_SLOT:
            case R_386_GLOB_DAT:
                invoker = 0;

                if (strcmp(sym, "exit") == 0) {
                    invoker = create_invoker(exit_struct);
                    } else {
                    for (int i = 0; i < nfuncs; i++) {
                        if (strcmp(sym, funcs[i].name) == 0) {
                            invoker = create_invoker(funcs + i);
                            break;
                        }
                    }
                }
                trampoline = create_trampoline(invoker);
                *(Elf32_Word *)(long long)rel[j].r_offset = (Elf32_Word) (long) trampoline;
                break;
            default:
                break;
        }
    }
}

void* find_sym(const char* name, Elf32_Shdr* shdr, const char* strings, const char* src)
{
    Elf32_Sym* syms = (Elf32_Sym*)(src + shdr->sh_offset);
    int i;
    for(i = 0; i < shdr->sh_size / sizeof(Elf32_Sym); i += 1) {
        if (strcmp(name, strings + syms[i].st_name) == 0) {
            return (void*)(long long)syms[i].st_value;
        }
    }
    return NULL;
}


void *image_load (char *elf_start, const struct function *funcs, int nfuncs)
{
    Elf32_Ehdr      *hdr     = NULL;
    Elf32_Phdr      *phdr    = NULL;
    Elf32_Shdr      *shdr    = NULL;
    Elf32_Sym       *syms    = NULL;
    char            *strings = NULL;
    char            *sym_str = NULL;
    char            *start   = NULL;
    char            *taddr   = NULL;
    void            *entry   = NULL;
    int i = 0;
    int j = 0;
    int k = 0;

    hdr = (Elf32_Ehdr *) elf_start;

    if(!is_image_valid(hdr)) {
        printf("image_load:: invalid ELF image\n");
        return 0;
    }

    phdr = (Elf32_Phdr *)(elf_start + hdr->e_phoff);

    Elf32_Dyn* dynamic_table = 0;

    Elf32_Sym* symbols_table = 0;

    Elf32_Rel* relocation_table = 0;

    shdr = (Elf32_Shdr *)(elf_start + hdr->e_shoff);

    Elf32_Rel rel_to_change;

    int sym_tab_size = 0;

    int pltrelsz = 0;

    for(i=0; i < hdr->e_shnum; ++i) {
        if (shdr[i].sh_type == SHT_DYNSYM) {
            syms = (Elf32_Sym*)(elf_start + shdr[i].sh_offset);
            strings = elf_start + shdr[shdr[i].sh_link].sh_offset;
//          strings can also be taken from _DYNAMIC

            sym_tab_size = shdr[i].sh_size;

        }
    }


    for(i=0; i < hdr->e_phnum; ++i) {

        if(phdr[i].p_type == PT_DYNAMIC) {

            dynamic_table = (Elf32_Dyn*)((void*)(long long)phdr[i].p_vaddr);

            for (j=0; j < phdr[i].p_filesz / sizeof(Elf32_Dyn); j++) {
                if(dynamic_table[j].d_tag == DT_SYMTAB) {
                    symbols_table = (Elf32_Sym*)((void*)(long long)dynamic_table[j].d_un.d_ptr);

                    for (k = 0; k < sym_tab_size / sizeof(Elf32_Sym); k++) {

                        if (strcmp("print", strings + symbols_table[k].st_name) == 0) {
                            *(Elf32_Word*)((void*)(long long)(dynamic_table[j].d_un.d_ptr + k * sizeof(Elf32_Sym) + 4)) = (Elf32_Word)0x99;
                        }
                        if (strcmp("exit", strings + symbols_table[k].st_name) == 0) {
                            symbols_table[k].st_value = (Elf32_Word)0x99;
                        }
                    }
                }

                if(dynamic_table[j].d_tag == DT_PLTRELSZ) {
                    pltrelsz = dynamic_table[j].d_un.d_val;
                }

                if(dynamic_table[j].d_tag == DT_JMPREL) {
                    relocation_table = (Elf32_Rel*)((void*)(long long)dynamic_table[j].d_un.d_ptr);

                    for (k = 0; k < pltrelsz / sizeof(Elf32_Rel); k++) {

                        rel_to_change = relocation_table[k];
                        rel_to_change.r_offset = 0x99;

                    }
                }
            }

            continue;
        }

        if(phdr[i].p_type != PT_LOAD) {
            continue;
        }

        if(phdr[i].p_filesz > phdr[i].p_memsz) {
            printf("image_load:: p_filesz > p_memsz\n");
//            munmap(exec);
            return 0;
        }
        if(!phdr[i].p_filesz) {
            continue;
        }

        // p_filesz can be smaller than p_memsz,
        // the difference is zeroe'd out.
        start = elf_start + phdr[i].p_offset;
        taddr = (void*)(long long)phdr[i].p_vaddr;

        char *aligned = (char*)(((long long)taddr >> 12) << 12);

        int ext_length = phdr[i].p_memsz + (taddr - aligned);

        mmap(aligned, ext_length, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

        memset(taddr, 0x0, ext_length);

        memmove(taddr,start,phdr[i].p_filesz);

    }


    for(i=0; i < hdr->e_phnum; ++i) {

        taddr = (void*)(long long)phdr[i].p_vaddr;

        if(phdr[i].p_type != PT_LOAD) {
            continue;
        }

        if (!(phdr[i].p_flags & PF_W)) {
            // Read-only.
            mprotect((unsigned char *) taddr,
                     phdr[i].p_memsz,
                     PROT_READ | PROT_WRITE);
        }

        if (phdr[i].p_flags & PF_X) {
            // Executable.
            mprotect((unsigned char *) taddr,
                     phdr[i].p_memsz,
                     PROT_EXEC | PROT_WRITE | PROT_READ);
        }
    }

    struct function exit_struct[1];

    exit_struct[0] = default_exit_struct(printf);

    for(i=0; i < hdr->e_shnum; ++i) {
        if (shdr[i].sh_type == SHT_REL) {
            relocate(shdr + i, syms, strings, elf_start, funcs, nfuncs, exit_struct);
        }
    }

    return (void*)((long long)hdr->e_entry);

}/* image_load */


void* create_stack() {
    void *stack;

    int stack_size = 4 * 1024;

    if ((stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0)) == MAP_FAILED) {
        printf("bad stack mmap\n");
    }

    stack = (void*) (((uint64_t) stack) + stack_size - 4);

    return stack;
}


void* program_entry(const char *filename, const struct function *funcs, int nfuncs) {
    static char buf[4 * 1024 * 1024];
    FILE* elf = fopen(filename, "rb");
    fread(buf, sizeof buf, 1, elf);

    return image_load(buf, funcs, nfuncs);
}

//extern char exit_custom;
//extern char exit_argument;
//extern char exit_custom_end;

//
//void generate_exit() {
//    void* real_exit;
//
//    void* status;
//
//    __asm__ volatile (
//        "exit_custom:\n"
//        ".code32\n"
//        "mov 4(%%esp), %0\n"
//        "pushl $0x33\n"
//        "pushl %1\n"
//        "lret\n"
//        ".code64\n"
//        "exit_custom_end:\n"
//        : "=m" (status)
//        : "g" (real_exit)
//        :
//    );
//}


int crossld_start(const char *filename, const struct function *funcs, int nfuncs) {
    void* stack = create_stack();
    void* entry = program_entry(filename, funcs, nfuncs);
    void* switcher = generate_switch();

    void* rbx = 0, *rbp = 0, *r12 = 0, *r13 = 0, *r14 = 0, *r15 = 0, *rsp = 0, *return_addr = 0, *res = 0;

    __asm__ volatile(
            "mov %%rbx, %0;\n"
            "mov %%rbp, %1;\n"
            "mov %%r12, %2;\n"
            "mov %%r13, %3;\n"
            "mov %%r14, %4;\n"
            "mov %%r15, %5;\n"
            "mov %%rsp, %6;\n"
            "movq %9, %%rsp;\n"
            "subq $8, %%rsp;\n"
            "movl $0x23, 4(%%rsp);\n"
            "mov %10, %%rax;\n"
            "movl %%eax, (%%rsp);\n"
            "mov %11, %%rcx;\n"
            "lea 8(%%rip), %%rax;\n" // lea go get next instruction after lret
            "mov %%rax, %7;\n"
            "lret;\n"
            "mov %0, %%rbx;\n"
            "mov %2, %%r12;\n"
            "mov %3, %%r13;\n"
            "mov %4, %%r14;\n"
            "mov %5, %%r15;\n"
            "mov %6, %%rsp;\n"
            "mov %%rax, %8;\n"
        : "=m" (rbx), "=m" (rbp), "=m" (r12), "=m" (r13),
                "=m" (r14), "=m" (r15), "=m" (rsp), "=m" (return_addr), "=m" (res)
        : "g" (stack), "g" (switcher), "g" (entry)
        : "cc", "memory", "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    );



    return *(int*)res;
}

// exit ma zly arg pointer