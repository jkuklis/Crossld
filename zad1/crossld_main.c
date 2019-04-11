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
            ".code32\n"
            "movl $0x33, 4(%esp);\n"   // change to 64 bit
            "movl $0, %eax;\n"         // move function pointer to be invoked
        "trampoline_fun_ptr:\n"
            "movl %eax, (%esp);\n"
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

//extern char arg_begin;
//extern char arg32_0;
//extern char arg32_1;
//extern char arg32_2;
//extern char arg32_3;
//extern char arg32_4;
//extern char arg32_5;
//extern char arg32_more;
//extern char arg32_after;
//extern char arg64_0;
//extern char arg64_1;
//extern char arg64_2;
//extern char arg64_3;
//extern char arg64_4;
//extern char arg64_5;
//extern char arg64_more;
//extern char arg64_after;
//extern char arg_transfer;
//extern char arg_transfer_after;
//extern char arg_end;
//extern char call_invoked;
//extern char call_argument;
//extern char call_end;
//extern char comeback_begin;
//extern char comeback_end;
//extern char comeback_fun_ptr;
//extern char just_ret;

//__asm__ (
//        "arg_begin:\n"
//        "arg32_0:\n"
//            ".code32\n"
//            "movl 256(%rsp), %edi;\n"
//        "arg32_1:\n"
//            "movl 256(%rsp), %esi;\n"
//        "arg32_2:\n"
//            "movl 256(%rsp), %edx;\n"
//        "arg32_3:\n"
//            "movl 256(%rsp), %ecx;\n"
//        "arg32_4:\n"
//            "movl 256(%rsp), %r8d;\n"
//        "arg32_5:\n"
//            "movl 256(%rsp), %r9d;\n"
//        "arg32_more:\n"
//            "movl 256(%rsp), %r10d;\n"
//        "arg32_after:\n"
//
//        "arg64_0:\n"
//            "movq 256(%rsp), %rdi;\n"
//        "arg64_1:\n"
//            "movq 256(%rsp), %rsi;\n"
//        "arg64_2:\n"
//            "movq 256(%rsp), %rdx;\n"
//        "arg64_3:\n"
//            "movq 256(%rsp), %rcx;\n"
//        "arg64_4:\n"
//            "movq 256(%rsp), %r8;\n"
//        "arg64_5:\n"
//            "movq 256(%rsp), %r9;\n"
//        "arg64_more:\n"
//            "movq 256(%rsp), %r10;\n"
//        "arg64_after:\n"
//
//        "arg_transfer:\n"
//            "movq %r10, 256(%rsp);\n"
//        "arg_transfer_after:\n"
//        "arg_end:\n"
//
//        "call_invoked:\n"
//            "subq $8, %rsp;\n"
//            "movabs $0, %rax;\n"
//        "call_argument:\n"
//            "callq  *%rax;\n"
//            "addq $8, %rsp;\n"
//        "call_end:\n"
//
//        // check that returned value is correct
//
//        "comeback_begin:\n"
//            "subq $8, %rsp;\n"
//            "movq $0x23, 4(%rsp);\n"   // change to 32 bit
//            "movq $0, %rax;\n"         // move function pointer to be invoked
//        "comeback_fun_ptr:\n"
//            "movq %rax, (%rsp);\n"
//            "lret;\n"
//            ".code64"
//        "comeback_end:\n"
//
//);


//__asm__ (
//        "just_ret:\n"
//            "ret;\n"
//        "just_ret_after:"
//);
//
//int relocate_argument(void *invoker_position, char* arg, char* arg_next, int rsp_from_offset) {
//    int length = arg_next - arg;
//    memcpy(invoker_position, arg, length);
//    memcpy(invoker_position + length - 4, &rsp_from_offset, 4);
//    return length;
//}


//int put_argument_on_stack(void *invoker_position, int rsp_to_offset) {
//    int length = &arg_transfer_after - &arg_transfer;
//    memcpy(invoker_position, &arg_transfer, length);
//    memcpy(invoker_position + length - 4, &rsp_to_offset, 4);
//}


extern char invoker_end;
extern char invoker_struct;
extern char invoker_handler;
extern char invoker_begin;

__asm__ (
    "invoker_begin:\n"
        "movabs $0, %rdi\n"
    "invoker_struct:\n"
        "movabs $0, %rax\n"
    "invoker_handler:\n"
        "jmp *%rax\n"
    "invoker_end:\n"
);

void real_invoker(const struct function *to_invoke) {
    printf("hehe\n");
}

void* create_invoker(const struct function *to_invoke) {
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



//void* create_invoker_faulty(const struct function *to_invoke) {
//    size_t codelen = 2 * 8 * (to_invoke->nargs) + (&comeback_end - &call_invoked);
//
//    void* invoker;
//
//    if ((invoker = mmap(NULL, codelen,
//                        PROT_READ | PROT_WRITE,
//                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
//                        -1, 0)) == MAP_FAILED) {
//        printf("Map error for invoker!\n");
//    }
//
//    int rsp_from_offset = 8;
//    int rsp_to_offset = 8;
//    int invoker_offset = 0;
//
//    char* arg32[] = {&arg32_0, &arg32_1, &arg32_2, &arg32_3, &arg32_4, &arg32_5, &arg32_more, &arg32_after};
//    char* arg64[] = {&arg64_0, &arg64_1, &arg64_2, &arg64_3, &arg64_4, &arg64_5, &arg64_more, &arg64_after};
//
//    int length;
//    for (int i = 0; i < to_invoke->nargs; i++) {
//        enum type arg_type = to_invoke->args[i];
//        switch(arg_type) {
//            case TYPE_VOID:
//                printf("Void argument!\n");
//                return NULL;
//                break;
//            case TYPE_INT:
//            case TYPE_LONG:
//            case TYPE_UNSIGNED_INT:
//            case TYPE_UNSIGNED_LONG:
//            case TYPE_PTR:
//                if (i < 6) {
//                    length = relocate_argument(invoker + invoker_offset, arg32[i], arg32[i+1], rsp_from_offset);
//                } else {
//                    length = relocate_argument(invoker + invoker_offset, &arg32_more, &arg32_after, rsp_from_offset);
//                    length += put_argument_on_stack(invoker + invoker_offset + length, rsp_to_offset);
//                    rsp_to_offset += 8;
//                }
//                rsp_from_offset += 4;
//                invoker_offset += length;
//                break;
//            case TYPE_LONG_LONG:
//            case TYPE_UNSIGNED_LONG_LONG:
//                if (i < 6) {
//                    length = relocate_argument(invoker + invoker_offset, arg64[i], arg64[i+1], rsp_from_offset);
//                } else {
//                    length = relocate_argument(invoker + invoker_offset, &arg64_more, &arg64_after, rsp_from_offset);
//                    length += put_argument_on_stack(invoker + invoker_offset + length, rsp_to_offset);
//                    rsp_to_offset += 8;
//                }
//                rsp_from_offset += 8;
//                invoker_offset += length;
//                break;
//
//        }
//    }
//
//    length = &call_end - &call_invoked;
//    memcpy(invoker + invoker_offset, &call_invoked, length);
//    memcpy(invoker + invoker_offset + (&call_argument - &call_invoked) - 8, &(to_invoke->name), 8);
//    invoker_offset += length;
//
//    return invoker;
//}


void make_trampolines(const struct function *funcs, int nfuncs, void** trampolines_addresses) {
    for (int i = 0; i < nfuncs; ++i) {

        void *invoker = create_invoker(&funcs[i]);

        trampolines_addresses[i] = create_trampoline(invoker);
    }
}



int is_image_valid(Elf32_Ehdr *hdr)
{
    return 1;
}


struct function default_exit_struct(void *exit_hook) {
    enum type exit_types[] = {TYPE_PTR};
    struct function exit_struct = {"print", exit_types, 1, TYPE_VOID, exit_hook};
    return exit_struct;
}


void relocate(Elf32_Shdr* shdr, const Elf32_Sym* syms, const char* strings, const char* src,
        const struct function *funcs, int nfuncs, struct function exit_struct)
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
                if (strcmp(sym, "exit")) {
                    invoker = create_invoker(&exit_struct);
                } else {
                    for (int i = 0; i < nfuncs; i++) {
                        if (strcmp(sym, funcs[i].name) == 0) {
                            invoker = create_invoker(&funcs[i]);
                            break;
                        }
                    }
                }
                trampoline = create_trampoline(invoker);
                *(Elf32_Word *) rel[j].r_offset = (Elf32_Word) (long) trampoline;
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
                        if (strcmp("exit_", strings + symbols_table[k].st_name) == 0) {
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

    struct function exit_struct;

    exit_struct = default_exit_struct(printf);

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

extern char switch_32;
extern char switch_32_end;

__asm__ (

        "switch_32:\n"
        ".code32\n"
        "pushl $0x2b\n"
        "popl %ds\n"
        "pushl $0x2b\n"
        "popl %es\n"
        "jmp *%ecx\n"

        ".code64\n"
        "switch_32_end:\n"
        ".code64\n"
);

void* generate_switch() {
    void* switcher;

    int codelen = &switch_32_end - &switch_32;

    if ((switcher = mmap(NULL, codelen, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0)) == MAP_FAILED) {
        printf("bad switch mmap\n");
    }

    memcpy(switcher, &switch_32, codelen);

    mprotect(switcher, codelen, PROT_EXEC);

    return switcher;
}

extern char exit_custom;
extern char exit_argument;
extern char exit_custom_end;

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