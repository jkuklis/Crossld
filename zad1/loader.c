#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>

#include "loader.h"
#include "common.h"
#include "asm.h"
#include "called_invoker.h"


struct Elf {
    Elf32_Ehdr  *hdr;
    Elf32_Phdr  *phdr;
    Elf32_Shdr  *shdr;
    Elf32_Sym   *syms;
    Elf32_Shdr  *relhdr;
    Elf32_Rel   *rel;
    char        *strings;
};


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


void* make_invoker(const char* sym, const struct function* funcs, int nfuncs, void* exit_fun) {
    void *invoker;

    if (strcmp(sym, "exit") == 0) {
//        enum type exit_types[] = {TYPE_INT};
//        struct function exit_struct = {"exit", state.exit_types, 1, TYPE_VOID, exit_fun};
        invoker = create_invoker(&(state.exit_struct));

    } else {
        for (int i = 0; i < nfuncs; i++) {
            if (strcmp(sym, funcs[i].name) == 0) {
                invoker = create_invoker(funcs + i);
                break;
            }
        }
    }

    assert_msg(invoker != 0, "Symbol not defined!");

    return invoker;
}


void relocate(struct Elf* elf, const struct function* funcs, int nfuncs, void* exit_fun) {
    void* invoker;
    void* trampoline;
    for(int j = 0; j < elf->relhdr->sh_size / sizeof(Elf32_Rel); j++) {
        const char* sym = elf->strings + elf->syms[ELF32_R_SYM(elf->rel[j].r_info)].st_name;

        switch(ELF32_R_TYPE(elf->rel[j].r_info)) {
            case R_386_JMP_SLOT:
            case R_386_GLOB_DAT:
                invoker = make_invoker(sym, funcs, nfuncs, exit_fun);
                trampoline = create_trampoline(invoker);
                *(Elf32_Word *)(long long)elf->rel[j].r_offset = (Elf32_Word) (long) trampoline;
        }
    }
}


int prepare_elf_struct(char *elf_start, struct Elf* elf) {
    elf->hdr = (Elf32_Ehdr *) elf_start;

    if (is_image_invalid(elf->hdr)) {
        return 1;
    }

    elf->phdr = (Elf32_Phdr *)(elf_start + elf->hdr->e_phoff);
    elf->shdr = (Elf32_Shdr *)(elf_start + elf->hdr->e_shoff);

    for (int i = 0; i < elf->hdr->e_shnum; ++i) {
        if (elf->shdr[i].sh_type == SHT_DYNSYM) {
            elf->syms = (Elf32_Sym *) (elf_start + elf->shdr[i].sh_offset);
            elf->strings = elf_start + elf->shdr[elf->shdr[i].sh_link].sh_offset;
            // can also be taken from _DYNAMIC}
        }
        if (elf->shdr[i].sh_type == SHT_REL) {
            elf->relhdr = elf->shdr + i;
            elf->rel = (Elf32_Rel*)(elf_start + elf->relhdr->sh_offset);
        }
    }

    return 0;
}

int load_program(char *elf_start, struct Elf* elf) {
    for(int i = 0; i < elf->hdr->e_phnum; ++i) {

        Elf32_Phdr p = elf->phdr[i];

        if (p.p_type != PT_LOAD) {
            continue;
        }

        if (assert_msg(p.p_filesz <= p.p_memsz, "Filesz larger than memsz!")) {
            return 0;
        }

        if (!p.p_filesz) {
            continue;
        }

        char* start = elf_start + p.p_offset;
        char* taddr = (void*)(long long)p.p_vaddr;
        char *aligned = (char*)(((long long)taddr >> 12) << 12);

        int ext_length = p.p_memsz + (taddr - aligned);

        mmap(aligned, ext_length, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

        memset(taddr, 0x0, ext_length);
        memmove(taddr,start,p.p_filesz);
    }
}

void protect_memory(struct Elf* elf) {
    for (int i = 0; i < elf->hdr->e_phnum; ++i) {

        Elf32_Phdr p = elf->phdr[i];
        char* taddr = (void*)(long long)p.p_vaddr;

        if (p.p_type != PT_LOAD) {
            continue;
        }

        if (!(p.p_flags & PF_W)) {
            mprotect((unsigned char *) taddr,
                     p.p_memsz,
                     PROT_READ);
        }

        if (p.p_flags & PF_X) {
            mprotect((unsigned char *) taddr,
                     p.p_memsz,
                     PROT_EXEC);
        }
    }
}

void *image_load (char *elf_start, const struct function *funcs, int nfuncs, void* exit_fun) {
    struct Elf elf;

    if (prepare_elf_struct(elf_start, &elf)) {
        return 0;
    }

    load_program(elf_start, &elf);
    protect_memory(&elf);

    relocate(&elf, funcs, nfuncs, exit_fun);

    return (void *) ((long long) elf.hdr->e_entry);
}