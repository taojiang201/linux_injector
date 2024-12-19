#ifndef __osis_elf_H__
#define __osis_elf_H__
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include "osis_tools.h"
#include "osis_global.h"
#include "string"
namespace OSIS {
    struct elf64_section_info
    {
       int  sh_index;
       std::string str_sh_name;
       int sh_type;  
       long s_addr;
       long s_offset;
       long s_size;
       Elf64_Word sh_link;
       unsigned char *p_sec;
       unsigned char *p_sh;
    };
    struct elf64_section_info_s
    {
        struct elf64_section_info* pstru_sec_infos;
        int sh_num;
    };
    struct elf64_segments_info
    {
        int seg_index;
        int seg_flags;
        int seg_type;
        long seg_offset;
        long seg_vaddr;
        long seg_filesz;
        long seg_memsz;
        unsigned char*p_seg;
    };
    struct elf64_segments_info_s
    {
       struct elf64_segments_info *pstru_seg_infos;
       int seg_num;
    };
class Osis_elf{
    public:
    Osis_elf();
    ~Osis_elf();
    long load_from_Mem(unsigned char* pbuff,long file_size);
    unsigned char set_debug_flag(unsigned char ucflag);
    long find_section_dynamic();
    long find_STD_sections(); //find standard section .bss .text .data .rodata,.interp,.shstrtab
    long get_mpath(char* &p);
    long set_mpath(char *path,int size);
    long parse_elf64();

    long get_mp_elf64_eh(Elf64_Ehdr*&p);
    long get_mp_elf64_ph(Elf64_Phdr*&p);
    long get_mp_elf64_sh(Elf64_Shdr*&p);
    long get_m_elf_sec_infos(struct elf64_section_info_s &obj);
    long get_m_elf_seg_infos(struct elf64_segments_info_s &obj);
    long get_p_mem(unsigned char* &obj);
    long get_ml_mem_size(long &obj);
    long set_ml_mem_size(long obj);
    long find_secInfo_by_secname(char*name,int &index);
    long find_seginfo_by_SegtypeAndSecidx(int seg_type,int secindex,int &segindex);
    long find_firstsSeg_by_seg_type(int seg_type,int &segindex);
    long find_secInfo_by_vaddr(Elf64_Addr vaddr,int &index);
    long find_secidx_by_dtag(int64_t dtag,int &index);
    long find_firstsec_by_type(int sec_type,int &index);
    long find_relaentidx_by_symname(char*name,int &relasec_idx,int &ent_idx);
    long find_symvalue_by_syname(char *name, Elf64_Addr & value);

    private:
    int init_data();

    unsigned char* p_mem;
    long ml_mem_size;

    Elf64_Ehdr *mp_elf64_eh;
    Elf64_Half e_type;

    Elf64_Phdr *mp_elf64_ph;
    int m_phnum;

    Elf64_Shdr *mp_elf64_sh;
    int m_shnum;

    Elf64_Dyn *mp_elf64_sec_dyn;
    int sh_dyn_index;
    int sec_dyn_size;

    unsigned char* p_sec_bss;
    unsigned int   sec_bss_size;
    int sh_bss_index;

   // struct elf64_section_info *mp_sec_info;
    struct elf64_section_info_s m_elf_sec_infos;
    struct elf64_segments_info_s m_elf_seg_infos;

    char mpath[PATH_MAX];
    unsigned char m_debug_flag;
};
}

#endif