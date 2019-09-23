//
// Created by luisky on 13/10/18.
//

#include <err.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PROGRAM_NAME "dummy_v1"

#define PRINT_FMT "    %-20s 0x%jx"
#define PRINT_FIELD(N)                            \
    do                                            \
    {                                             \
        printf(PRINT_FMT, #N, (uintmax_t)phdr.N); \
    } while (0)
#define NL()          \
    do                \
    {                 \
        printf("\n"); \
    } while (0)
#define C(V)     \
    case PT_##V: \
        s = #V;  \
        break

void print_ptype(size_t pt)
{
    char *s;

    switch (pt)
    {
        //C(SUNWCAP); C(SUNDTRACE);   C(SUNW_UNWIND); // Those are not defined in elf.h apparently
        C(NULL);
        C(LOAD);
        C(DYNAMIC);
        C(INTERP);
        C(NOTE);
        C(SHLIB);
        C(PHDR);
        C(TLS);
        C(SUNWSTACK);
        C(SUNWBSS);
    default:
        s = "unknown";
        break;
    }

    printf("\"%s\"", s);
}

#undef C

int main(int argc, char **argv)
{
    int fd;
    Elf *e;
    char *k;
    char *id, bytes[5];
    size_t n;

    Elf_Kind ek;
    GElf_Phdr phdr;

    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(EXIT_FAILURE, "ELF library init failed: %s", elf_errmsg(-1));
    if ((fd = open(PROGRAM_NAME, O_RDONLY, 0)) < 0)
        err(EXIT_FAILURE, "open failed");
    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
        errx(EXIT_FAILURE, "elf_begin() failed %s", elf_errmsg(-1));

    ek = elf_kind(e);

    switch (ek)
    {
    case ELF_K_AR:
        k = "ar(1) archive";
        break;
    case ELF_K_ELF:
        k = "elf object";
        break;
    case ELF_K_NONE:
        k = "data";
        break;
    default:
        k = "unrecognised";
    }

    printf("%s: %s\n", PROGRAM_NAME, k);

    if (elf_getphdrnum(e, &n) != 0)
        errx(EXIT_FAILURE, "elf_getphdrnum() failed %s", elf_errmsg(-1));

    for (int i = 0; i < n; i++)
    {

        if (gelf_getphdr(e, i, &phdr) != &phdr)
            errx(EXIT_FAILURE, "getphdr() failed %s", elf_errmsg(-1));
        printf("PHDR %d : \n", i);

        PRINT_FIELD(p_type);
        print_ptype(phdr.p_type);
        NL();
        PRINT_FIELD(p_offset);
        NL();
        PRINT_FIELD(p_vaddr);
        NL();
        PRINT_FIELD(p_paddr);
        NL();
        PRINT_FIELD(p_filesz);
        NL();
        PRINT_FIELD(p_memsz);
        NL();
        PRINT_FIELD(p_flags);

        printf(" [");
        if (phdr.p_flags & PF_X)
            printf(" execute");
        if (phdr.p_flags & PF_R)
            printf(" read");
        if (phdr.p_flags & PF_W)
            printf(" write");
        printf(" ]");
        NL();
        PRINT_FIELD(p_align);
        NL();
    }

    elf_end(e);
    close(fd);

    return EXIT_SUCCESS;
}
