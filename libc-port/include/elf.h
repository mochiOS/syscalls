#ifndef _MOCHIOS_ELF_H
#define _MOCHIOS_ELF_H
#include <stdint.h>
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;
typedef uint64_t Elf64_Addr, Elf64_Off, Elf64_Xword;
typedef int64_t Elf64_Sxword;
typedef struct {
    Elf64_Word p_type, p_flags;
    Elf64_Off p_offset;
    Elf64_Addr p_vaddr, p_paddr;
    Elf64_Xword p_filesz, p_memsz, p_align;
} Elf64_Phdr;
typedef struct { Elf64_Word n_namesz, n_descsz, n_type; } Elf64_Nhdr;
#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_PHDR 6
#define PT_TLS 7
#define PF_X 1
#define PF_W 2
#define PF_R 4
#define NT_GNU_BUILD_ID 3
#endif
