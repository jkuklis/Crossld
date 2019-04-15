#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>

#include "loader.h"
#include "common.h"
#include "asm.h"


int is_image_invalid(Elf32_Ehdr *hdr) {
    assert_msg(memcmp(hdr->e_ident, ELFMAG, SELFMAG) == 0, "Incorrect ELF: magic number");
    assert_msg(hdr->e_type == ET_EXEC, "Incorrect ELF: not exec file type");
    assert_msg(hdr->e_machine == EM_386, "Incorrect ELF: wrong architecture");
    assert_msg(hdr->e_ident[EI_CLASS] = ELFCLASS32, "Incorrect ELF: wrong bit architecture");
    assert_msg(hdr->e_ident[EI_VERSION] = EV_CURRENT, "Incorrect ELF: version");
    assert_msg(hdr->e_phoff != 0, "Incorrect ELF: No program header table");
    assert_msg(hdr->e_phnum != 0, "Incorrect ELF: No programs in ELF");
    return get_status();
}


void called_invoker(const struct function *to_invoke) {
//    void *args[to_invoke->nargs];
//
//    void* switcher = switcher_64();
//
//    size_t stack_position = 8;
//    size_t args_offset = 8;
//
//    void* arg_val = 0;
//
//    void* returned;
//
//    for (int i = 0; i < to_invoke->nargs; i++) {
//        enum type arg_type = to_invoke->args[i];
//        arg_val = 0;
//        switch (arg_type) {
//            case TYPE_VOID:
//                printf("Void argument!\n");
//                return;
//                // TODO
//                break;
//            case TYPE_INT:
//            case TYPE_LONG:
//            case TYPE_UNSIGNED_INT:
//            case TYPE_UNSIGNED_LONG:
//            case TYPE_PTR:
//                stack_position += 4;
//                __asm__ volatile (
//                "movq %1, %%rax\n"
//                "lea (%%rbp, %%rax, 1), %%rax\n"
//                "movl (%%rax), %%eax\n"
//                "movl %%eax, %0\n"
//                : "=m" (arg_val)
//                : "g" (stack_position)
//                );
//                break;
//            case TYPE_LONG_LONG:
//            case TYPE_UNSIGNED_LONG_LONG:
//                stack_position += 4;
//                __asm__ volatile (
//                "movq %1, %%rax\n"
//                "lea (%%rbp, %%rax, 1), %%rax\n"
//                "movq (%%rax), %%rax\n"
//                "movq %%rax, %0\n"
//                : "=m" (arg_val)
//                : "g" (stack_position)
//                );
//                stack_position += 4;
//                break;
//        }
//
//        args[i] = arg_val;
//    }
//
////    printf("%s\n", to_invoke->name);
//
//    for (int i = to_invoke->nargs; i > 5; i--) {
//        long long val = (long long)args[i];
//        __asm__ volatile (
//        "pushq %0\n"
//        :: "g" (val)
//        );
//    }
//
//    for (int i = 0; i < to_invoke->nargs && i < 6; i++) {
//        long long val = (long long)args[i];
//
//        switch(i) {
//            case 0:
//                __asm__ volatile (
//                "movq %0, %%rdi"
//                :: "g" (val)
//                );
//                break;
//            case 1:
//                __asm__ volatile (
//                "movq %0, %%rsi"
//                :: "g" (val)
//                );
//                break;
//            case 2:
//                __asm__ volatile (
//                "movq %0, %%rdx"
//                :: "g" (val)
//                );
//                break;
//            case 3:
//                __asm__ volatile (
//                "movq %0, %%rcx"
//                :: "g" (val)
//                );
//                break;
//            case 4:
//                __asm__ volatile (
//                "movq %0, %%r8"
//                :: "g" (val)
//                );
//                break;
//            case 5:
//                __asm__ volatile (
//                "movq %0, %%r9"
//                :: "g" (val)
//                );
//                break;
//        }
//    }
//
//    if (to_invoke->nargs >= 3) {
//        long long val = (long long)args[2];
//        __asm__ volatile (
//        "movq %0, %%rdx"
//        :: "g" (val)
//        );
//    }
//
//    __asm__ volatile (
//    "call *%1\n"
//    "movq %%rax, %0"
//    : "=m" (returned)
//    : "g" (to_invoke->code)
//    );
//
//    unsigned long long returned_val = (unsigned long long)returned;
//
//    switch(to_invoke->result) {
//        case TYPE_INT:
//        case TYPE_LONG:
//        case TYPE_UNSIGNED_INT:
//        case TYPE_UNSIGNED_LONG:
//        case TYPE_PTR:
//            if (returned_val > UINT32_MAX) {
//                // TODO
//                // put address of exit into global state?
//                abort();
//            } else {
//                __asm__ volatile (
//                "movq %0, %%rax\n"
//                :: "g" (returned)
//                );
//            }
//            break;
//
//        case TYPE_LONG_LONG:
//        case TYPE_UNSIGNED_LONG_LONG:
//            __asm__ volatile (
//            "movq %0, %%rcx\n"
//            "movl %%ecx, %%eax\n"
//            "sar $32, %%rcx\n"
//            "movl %%ecx, %%edx\n"
//            :: "g" (returned)
//            );
//            break;
//
//        default:
//            break;
//
//    }
//
//    __asm__ volatile (
//    "movq %%r12, %%rdi\n"
//    "movq %%r13, %%rsi\n"
//    "movl $0x23, 4(%%rsp);\n"
//    "movq %0, %%rcx;\n"
//    "movl %%ecx, (%%rsp);\n"
//    "lret\n"
//    :
//    : "g" (switcher)
//    );

}


void* create_invoker(const struct function* to_invoke) {
    size_t code_len = &invoker_end - &invoker_begin;
    size_t struct_offset = (&invoker_struct - &invoker_begin) - 8;
    size_t handler_offset = (&invoker_handler - &invoker_begin) - 8;

    void* invoker;

    invoker = mmap(NULL, code_len, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);

    if (assert_msg(invoker != MAP_FAILED, "Failed to create an invoker!")) {
        return 0;
    }

    long long address = (long long)&called_invoker;

    memcpy(invoker, &invoker_begin, code_len);
    memcpy(invoker + struct_offset, &to_invoke, 8);
    memcpy(invoker + handler_offset, &address, 8);

    mprotect(invoker, code_len, PROT_READ | PROT_EXEC);

    return invoker;
}


void* create_trampoline(void* invoker_function) {
    size_t code_len = &trampoline_end - &trampoline_begin;
    size_t fun_ptr_offset = (&trampoline_fun_ptr - &trampoline_begin) - 4;

    void *trampoline;

    trampoline = mmap(NULL, code_len, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);

    if (assert_msg(trampoline != MAP_FAILED, "Failed to create a trampoline!")) {
        return 0;
    }

    memcpy(trampoline, &trampoline_begin, code_len);
    memcpy(trampoline + fun_ptr_offset, &invoker_function, 4);

    mprotect(trampoline, code_len, PROT_READ | PROT_EXEC);

    return trampoline;
}


void relocate(Elf32_Shdr* shdr, const Elf32_Sym* syms, const char* strings, const char* src,
              const struct function* funcs, int nfuncs, void* exit_fun)
{
    Elf32_Rel* rel = (Elf32_Rel*)(src + shdr->sh_offset);
    void* invoker;
    void* trampoline;
    for(int j = 0; j < shdr->sh_size / sizeof(Elf32_Rel); j++) {
        const char* sym = strings + syms[ELF32_R_SYM(rel[j].r_info)].st_name;

        switch(ELF32_R_TYPE(rel[j].r_info)) {
            case R_386_JMP_SLOT:
            case R_386_GLOB_DAT:
                invoker = 0;

                if (strcmp(sym, "exit") == 0) {
                    enum type exit_types[] = {TYPE_INT};
                    struct function exit_struct = {"exit", exit_types, 1, TYPE_VOID, exit_fun};
                    invoker = create_invoker(&exit_struct);

                } else {
                    for (int i = 0; i < nfuncs; i++) {
                        if (strcmp(sym, funcs[i].name) == 0) {
                            invoker = create_invoker(funcs + i);
                            break;
                        }
                    }
                }
                assert_msg(invoker != 0, "Symbol not defined!");

                trampoline = create_trampoline(invoker);
                *(Elf32_Word *)(long long)rel[j].r_offset = (Elf32_Word) (long) trampoline;
        }
    }
}


void *image_load (char *elf_start, const struct function *funcs, int nfuncs, void* exit_fun) {

    Elf32_Ehdr  *hdr        = NULL;
    Elf32_Phdr  *phdr       = NULL;
    Elf32_Shdr  *shdr       = NULL;
    Elf32_Sym   *syms       = NULL;
    char        *strings    = NULL;

    char        *start      = NULL;
    char        *taddr      = NULL;
    int i = 0;
    int j = 0;
    int k = 0;

    hdr = (Elf32_Ehdr *) elf_start;

    if (is_image_invalid(hdr)) {
        return 0;
    }

    phdr = (Elf32_Phdr *)(elf_start + hdr->e_phoff);
    shdr = (Elf32_Shdr *)(elf_start + hdr->e_shoff);

    Elf32_Rel rel_to_change;

    for (i=0; i < hdr->e_shnum; ++i) {
        if (shdr[i].sh_type == SHT_DYNSYM) {
            syms = (Elf32_Sym*)(elf_start + shdr[i].sh_offset);
            strings = elf_start + shdr[shdr[i].sh_link].sh_offset;
            // can also be taken from _DYNAMIC
        }
    }

    for (i=0; i < hdr->e_phnum; ++i) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        if (assert_msg(phdr[i].p_filesz <= phdr[i].p_memsz, "File size bigger than memory size!")) {
            return 0;
        }
        if (!phdr[i].p_filesz) {
            continue;
        }

        start = elf_start + phdr[i].p_offset;
        taddr = (void*)(long long)phdr[i].p_vaddr;

        char *aligned = (char*)(((long long)taddr >> 12) << 12);

        int ext_length = phdr[i].p_memsz + (taddr - aligned);

        mmap(aligned, ext_length, PROT_READ | PROT_WRITE,
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
                     PROT_READ);
        }

        if (phdr[i].p_flags & PF_X) {
            // Executable.
            mprotect((unsigned char *) taddr,
                     phdr[i].p_memsz,
                     PROT_EXEC);
        }
    }

    for(i=0; i < hdr->e_shnum; ++i) {
        if (shdr[i].sh_type == SHT_REL) {
            relocate(shdr + i, syms, strings, elf_start, funcs, nfuncs, exit_fun);
        }
    }

    return (void*)((long long)hdr->e_entry);

} /* image_load */