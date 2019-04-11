#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <elf.h>
#include <unistd.h>

int is_image_valid(Elf32_Ehdr *hdr)
{
    return 1;
}

void *resolve(const char* sym)
{
    void* resolved;
    static void *handle = NULL;
    if (handle == NULL) {
        handle = dlopen("libc.so", RTLD_NOW);
    }
    resolved = dlsym(handle, sym);
    return resolved;
}

void relocate(Elf32_Shdr* shdr, const Elf32_Sym* syms, const char* strings, const char* src, char* dst)
{
//    return;
    Elf32_Rel* rel = (Elf32_Rel*)(src + shdr->sh_offset);
    int j;
    void* resolved;
    for(j = 0; j < shdr->sh_size / sizeof(Elf32_Rel); j += 1) {
        const char* sym = strings + syms[ELF32_R_SYM(rel[j].r_info)].st_name;
//        printf("%d\n", ELF32_R_TYPE(rel[j].r_info));
        switch(ELF32_R_TYPE(rel[j].r_info)) {
            case R_386_JMP_SLOT:
            case R_386_GLOB_DAT:
                resolved = resolve(sym);
                resolved = (void*)0x12345;
                Elf32_Word* toWhere = (Elf32_Word*)(dst + rel[j].r_offset);
//                resolved = rel[j].r_offset;
                *toWhere =  *(Elf32_Word*)resolved;
                break;
            default:
//                printf("%s\n", sym);
                break;
        }
    }
}

void* find_sym(const char* name, Elf32_Shdr* shdr, const char* strings, const char* src, char* dst)
{
    Elf32_Sym* syms = (Elf32_Sym*)(src + shdr->sh_offset);
    int i;
    for(i = 0; i < shdr->sh_size / sizeof(Elf32_Sym); i += 1) {
//        printf("%s :: %x\n", strings + syms[i].st_name, syms[i].st_value);
        if (strcmp(name, strings + syms[i].st_name) == 0) {
            return dst + syms[i].st_value;
        }
    }
    return NULL;
}

const int N = 0;

void *image_load (char *elf_start, unsigned int size)
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
    char *exec = NULL;

    hdr = (Elf32_Ehdr *) elf_start;

    if(!is_image_valid(hdr)) {
        printk("image_load:: invalid ELF image\n");
        return 0;
    }

//    exec = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
//                MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
//
//    if(!exec) {
//        printk("image_load:: error allocating memory\n");
//        return 0;
//    }
//
//    // Start with clean memory.
//    memset(exec,0x0,size);

    phdr = (Elf32_Phdr *)(elf_start + hdr->e_phoff);

    Elf32_Dyn* dynamic_table = 0;

    Elf32_Sym* symbols_table = 0;

    Elf32_Rel* relocation_table = 0;

    shdr = (Elf32_Shdr *)(elf_start + hdr->e_shoff);

    Elf32_Rel rel_to_change;

    int sym_tab_size = 0;

    int pltrelsz = 0;

    char* to_find[] = {"_start", "main"};

    for(i=0; i < hdr->e_shnum; ++i) {
        if (shdr[i].sh_type == SHT_DYNSYM) {
            syms = (Elf32_Sym*)(elf_start + shdr[i].sh_offset);
            strings = elf_start + shdr[shdr[i].sh_link].sh_offset;
//          strings can also be taken from _DYNAMIC

            sym_tab_size = shdr[i].sh_size;

        }
        if (shdr[i].sh_type == SHT_SYMTAB) {

            sym_str = elf_start + shdr[shdr[i].sh_link].sh_offset;
            entry = find_sym(to_find[N], shdr + i, sym_str, elf_start, exec);
        }
    }


    for(i=0; i < hdr->e_phnum; ++i) {

        if(phdr[i].p_type == PT_DYNAMIC) {

            dynamic_table = (Elf32_Dyn*)(phdr[i].p_vaddr + exec);

            for (j=0; j < phdr[i].p_filesz / sizeof(Elf32_Dyn); j++) {
//                printf("%d\n", dynamic_table[j].d_tag);
                if(dynamic_table[j].d_tag == DT_SYMTAB) {
                    symbols_table = (Elf32_Sym*)(dynamic_table[j].d_un.d_ptr + exec);

                    for (k = 0; k < sym_tab_size / sizeof(Elf32_Sym); k++) {

                        if (strcmp("print", strings + symbols_table[k].st_name) == 0) {
//                            symbols_table[k].st_value = (Elf32_Word)0x99;
                            *(Elf32_Word*)(exec + dynamic_table[j].d_un.d_ptr + k * sizeof(Elf32_Sym) + 4) = (Elf32_Word)0x99;
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
                    relocation_table = (Elf32_Rel*)(dynamic_table[j].d_un.d_ptr + exec);

                    for (k = 0; k < pltrelsz / sizeof(Elf32_Rel); k++) {
                        rel_to_change = relocation_table[k];
//                        printf("%d\n", ELF32_R_TYPE(rel_to_change.r_info));
//                        rel_to_change.r_offset = rel_to_change.r_offset + (Elf32_Word)exec;
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
//            printk("image_load:: p_filesz > p_memsz\n");
            munmap(exec, size);
            return 0;
        }
        if(!phdr[i].p_filesz) {
            continue;
        }

        // p_filesz can be smaller than p_memsz,
        // the difference is zeroe'd out.
        start = elf_start + phdr[i].p_offset;
        taddr = phdr[i].p_vaddr + exec;

//        static size_t pagesize;
//        if (!pagesize) {
//            pagesize = sysconf(_SC_PAGESIZE);
//            if (pagesize == (size_t) - 1) perror("getpagesize");
//        }
//
//        size_t rounded_codesize = ((phdr[i].p_memsz + 1 + pagesize - 1)
//                                   / pagesize) * pagesize;


        char *aligned = (char*)(((long)taddr >> 12) << 12);

        int ext_length = phdr[i].p_memsz + (taddr - aligned);

        mmap(aligned, ext_length, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

        memset(taddr, 0x0, ext_length);

        memmove(taddr,start,phdr[i].p_filesz);

    }


    for(i=0; i < hdr->e_phnum; ++i) {

        taddr = phdr[i].p_vaddr + exec;

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

    for(i=0; i < hdr->e_shnum; ++i) {
        if (shdr[i].sh_type == SHT_REL) {
            relocate(shdr + i, syms, strings, elf_start, exec);
        }
    }

//    return (void*)hdr->e_entry;

    return entry;

}/* image_load */

int main(int argc, char** argv, char** envp)
{
    int (*ptr)(int, char **, char**);
    static char buf[1024 * 1024 * 1024];
    FILE* elf = fopen(argv[N + 1], "rb");
    fread(buf, sizeof buf, 1, elf);
    ptr=image_load(buf, sizeof buf);
    return ptr(argc,argv,envp);
}