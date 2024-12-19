#include "osis_elf.h"
OSIS::Osis_elf::Osis_elf() { init_data(); }
OSIS::Osis_elf::~Osis_elf()
{
    if (m_elf_sec_infos.pstru_sec_infos) delete[] m_elf_sec_infos.pstru_sec_infos;
    if (m_elf_seg_infos.pstru_seg_infos) delete[] m_elf_seg_infos.pstru_seg_infos;
}
int OSIS::Osis_elf::init_data()
{
    p_mem = NULL;
    ml_mem_size = 0;
    mp_elf64_eh = NULL;
    mp_elf64_ph = NULL;
    mp_elf64_sh = NULL;

    m_debug_flag = 0;
    e_type = 0;

    mp_elf64_sec_dyn = NULL;
    sh_dyn_index = -1;
    sec_dyn_size = 0;

    m_phnum = 0;
    m_shnum = 0;
    memset(mpath, 0, PATH_MAX);

    p_sec_bss = NULL;
    sec_bss_size = 0;
    sh_bss_index = -1;

    m_elf_sec_infos.pstru_sec_infos = NULL;
    m_elf_sec_infos.sh_num = 0;

    m_elf_seg_infos.pstru_seg_infos = NULL;
    m_elf_seg_infos.seg_num = 0;

    return 0;
}

long OSIS::Osis_elf::load_from_Mem(unsigned char *pbuff, long file_size)
{
    if (!pbuff || file_size < 1) {
        if (m_debug_flag)
            output_debug_string(0, 1, "mpbuff is %d file_size %d (%s:%d)\n", pbuff, file_size, __FILE__, __LINE__);
        return -1;
    }
    mp_elf64_eh = (Elf64_Ehdr *)pbuff;
    p_mem = pbuff;
    ml_mem_size = file_size;
    if (mp_elf64_eh->e_ident[4] != 0x02) {
        output_debug_string(0, 1, "this file (%s) is not ELF64 EICLASS= %d  (%s:%d)\n", mpath, mp_elf64_eh->e_ident[4],
                            __FILE__, __LINE__);
        return -2;
    }
    m_phnum = mp_elf64_eh->e_phnum;
    m_shnum = mp_elf64_eh->e_shnum;
    e_type = mp_elf64_eh->e_type;
    if (mp_elf64_eh->e_phoff == 0 || mp_elf64_eh->e_phentsize == 0 || mp_elf64_eh->e_phnum == 0) {
        if (m_debug_flag)
            OSIS::output_debug_string(0, 0,
                                      "the file has not program headers ,"
                                      "the E_TYPE=%d,e_phoff=%d,e_phentsize=%d,"
                                      "e_phnum=%d (%s:%d)\n",
                                      mp_elf64_eh->e_type, mp_elf64_eh->e_phoff, mp_elf64_eh->e_phentsize,
                                      mp_elf64_eh->e_phnum, __FILE__, __LINE__);
        mp_elf64_ph = NULL;
        e_type = mp_elf64_eh->e_type;

    } else
        mp_elf64_ph = (Elf64_Phdr *)&pbuff[mp_elf64_eh->e_phoff];

    if (mp_elf64_eh->e_shentsize == 0 || mp_elf64_eh->e_shoff == 0 || mp_elf64_eh->e_shnum == 0) {
        if (m_debug_flag)
            OSIS::output_debug_string(0, 1,
                                      "the file has not section head,"
                                      "the E_TYPE=%d,e_shoff=%d,e_shentsize=%d,"
                                      "e_shnum=%d (%s:%d)\n",
                                      mp_elf64_eh->e_type, mp_elf64_eh->e_shoff, mp_elf64_eh->e_shentsize,
                                      mp_elf64_eh->e_shnum, __FILE__, __LINE__);
        mp_elf64_sh = NULL;
    } else
        mp_elf64_sh = (Elf64_Shdr *)&pbuff[mp_elf64_eh->e_shoff];
    return 0;
}
long OSIS::Osis_elf::find_section_dynamic()
{
    int find_flag = -1;
    if (!mp_elf64_sh) {
        if (m_debug_flag) output_debug_string(0, 1, "mp_elf64_sh is null (%s:%d)\n", __FILE__, __LINE__);
        return -1;
    }
    for (int i = 0; i < mp_elf64_eh->e_shnum; i++) {
        if (mp_elf64_sh[i].sh_type == 0x06) {
            mp_elf64_sec_dyn = (Elf64_Dyn *)(&p_mem[mp_elf64_sh[i].sh_offset]);
            sh_dyn_index = i;
            sec_dyn_size = mp_elf64_sh[i].sh_size;
            if (m_debug_flag)
                output_debug_string(0, 0,
                                    "find section Dynamic index=%d,sec_dyn_size=%d,"
                                    "mp_elf64_sec_dyn =%p(mp_elf64_eh(%p)+sh_offset(%p))"
                                    "(%s:%d)\n",
                                    sh_dyn_index, sec_dyn_size, mp_elf64_sec_dyn, mp_elf64_eh, mp_elf64_sh[i].sh_offset,
                                    __FILE__, __LINE__);
            find_flag = 0;
            return 0;
        }
    }
    return find_flag;
}
unsigned char OSIS::Osis_elf::set_debug_flag(unsigned char ucflag)
{
    m_debug_flag = ucflag;
    return 0;
}
long OSIS::Osis_elf::set_mpath(char *path, int size)
{
    if (path == NULL || size > PATH_MAX || size < 0) {
        if (m_debug_flag)
            output_debug_string(0, 1, "param check invalid! p(%d),size(%d) (%s:%d)\n", path, size, __FILE__, __LINE__);
        return -1;
    }
    snprintf(mpath, PATH_MAX, "%s", path);
    return 0;
}
long OSIS::Osis_elf::get_mpath(char *&p)
{
    p = mpath;
    return 0;
}
long OSIS::Osis_elf::find_STD_sections()
{
    int find_flag = -1;
    if (!mp_elf64_sh) {
        if (m_debug_flag) output_debug_string(0, 1, "mp_elf64_sh is null (%s:%d)\n", __FILE__, __LINE__);
        return -1;
    }

    return 0;
}
long OSIS::Osis_elf::parse_elf64()
{
    int find_flag = -1;
    if (!mp_elf64_sh) {
        if (m_debug_flag) output_debug_string(0, 1, "mp_elf64_sh is null (%s:%d)\n", __FILE__, __LINE__);
        return -1;
    }
    if (m_shnum < 0) {
        if (m_debug_flag) output_debug_string(0, 1, "m_shnum(%d) is invalid (%s:%d)\n", m_shnum, __FILE__, __LINE__);
        return -2;
    }
    if (!m_elf_sec_infos.pstru_sec_infos)
        m_elf_sec_infos.pstru_sec_infos = new elf64_section_info[m_shnum];
    else {
        if (m_elf_sec_infos.sh_num != m_shnum) return -1;
    }

    m_elf_sec_infos.sh_num = m_shnum;
    if (!m_elf_sec_infos.pstru_sec_infos) {
        if (m_debug_flag)
            output_debug_string(0, 1, "mp_sec_info(%d) is invalid (%s:%d)\n", m_elf_sec_infos.pstru_sec_infos, __FILE__,
                                __LINE__);
        return -3;
    }

    for (int i = 0; i < m_shnum; i++) {
        m_elf_sec_infos.pstru_sec_infos[i].sh_index = i;
        m_elf_sec_infos.pstru_sec_infos[i].sh_type = mp_elf64_sh[i].sh_type;
        // printf("111\n");
        //
        char *p = (char *)&p_mem[(mp_elf64_sh[mp_elf64_eh->e_shstrndx].sh_offset + mp_elf64_sh[i].sh_name)];
        m_elf_sec_infos.pstru_sec_infos[i].str_sh_name = p;
        m_elf_sec_infos.pstru_sec_infos[i].s_size = mp_elf64_sh[i].sh_size;
        m_elf_sec_infos.pstru_sec_infos[i].s_offset = mp_elf64_sh[i].sh_offset;
        m_elf_sec_infos.pstru_sec_infos[i].s_addr = mp_elf64_sh[i].sh_addr;
        m_elf_sec_infos.pstru_sec_infos[i].p_sec = p_mem + mp_elf64_sh[i].sh_offset;
        m_elf_sec_infos.pstru_sec_infos[i].p_sh = p_mem + mp_elf64_eh->e_shoff + i * (mp_elf64_eh->e_shentsize);
        m_elf_sec_infos.pstru_sec_infos[i].sh_link = mp_elf64_sh[i].sh_link;
        // printf("p_sec[%p],p_mem[%p],mp_elf64_sh[%d].sh_offset[%p],"\
               "p_sh[%p],p_mem[%p],mp_elf64_eh->e_shoff[%p]+i[%d]*mp_elf64_eh->e_shentsize[%p]\n",\
                m_elf_sec_infos.pstru_sec_infos[i].p_sec,p_mem,i,mp_elf64_sh[i].sh_offset,\
                m_elf_sec_infos.pstru_sec_infos[i].p_sh,p_mem,mp_elf64_eh->e_shoff,i,mp_elf64_eh->e_shentsize);
        if (m_debug_flag)
            output_debug_string(0, 0,
                                "section %d name:%s "
                                "type=%d"
                                "(%s:%d)\n",
                                m_elf_sec_infos.pstru_sec_infos[i].sh_index,
                                m_elf_sec_infos.pstru_sec_infos[i].str_sh_name.c_str(),
                                m_elf_sec_infos.pstru_sec_infos[i].sh_type, __FILE__, __LINE__);
    }

    if ((!mp_elf64_ph) || m_phnum < 1) {
        if (m_debug_flag)
            output_debug_string(0, 0, " the file[%s] has no programe head mp_elf64_ph[%d] m_phnum[%d] (%s:%d)\n", mpath,
                                mp_elf64_ph, m_phnum, __FILE__, __LINE__);
        return 0;
    }
    if (!m_elf_seg_infos.pstru_seg_infos)
        m_elf_seg_infos.pstru_seg_infos = new elf64_segments_info[m_phnum];
    else {
        if (m_elf_seg_infos.seg_num != m_phnum) return -1;
    }
    m_elf_seg_infos.seg_num = m_phnum;

    for (int i = 0; i < m_phnum; i++) {
        m_elf_seg_infos.pstru_seg_infos[i].seg_index = i;
        m_elf_seg_infos.pstru_seg_infos[i].seg_type = mp_elf64_ph[i].p_type;
        m_elf_seg_infos.pstru_seg_infos[i].seg_flags = mp_elf64_ph[i].p_flags;
        m_elf_seg_infos.pstru_seg_infos[i].seg_offset = mp_elf64_ph[i].p_offset;
        m_elf_seg_infos.pstru_seg_infos[i].seg_filesz = mp_elf64_ph[i].p_filesz;
        m_elf_seg_infos.pstru_seg_infos[i].seg_memsz = mp_elf64_ph[i].p_memsz;
        m_elf_seg_infos.pstru_seg_infos[i].seg_vaddr = mp_elf64_ph[i].p_vaddr;
        m_elf_seg_infos.pstru_seg_infos[i].p_seg = &p_mem[mp_elf64_eh->e_phoff + (i * mp_elf64_eh->e_phentsize)];
        if (m_debug_flag)
            output_debug_string(
                0, 0,
                "segment[%d] seg_type[%d] "
                "seg_flags[%d] seg_offset[%d] "
                "seg_filesz[%d] seg_memsz[%d] "
                "seg_vaddr=[%p] p_seg[%p] mp_elf64_eh[%p] "
                "(%s:%d)\n",
                m_elf_seg_infos.pstru_seg_infos[i].seg_index, m_elf_seg_infos.pstru_seg_infos[i].seg_type,
                m_elf_seg_infos.pstru_seg_infos[i].seg_flags, m_elf_seg_infos.pstru_seg_infos[i].seg_offset,
                m_elf_seg_infos.pstru_seg_infos[i].seg_filesz, m_elf_seg_infos.pstru_seg_infos[i].seg_memsz,
                m_elf_seg_infos.pstru_seg_infos[i].seg_vaddr, m_elf_seg_infos.pstru_seg_infos[i].p_seg, mp_elf64_eh,
                __FILE__, __LINE__);
    }

    return 0;
}

long OSIS::Osis_elf::get_mp_elf64_eh(Elf64_Ehdr *&p)
{
    p = mp_elf64_eh;
    return 0;
}

long OSIS::Osis_elf::get_mp_elf64_ph(Elf64_Phdr *&p)
{
    p = mp_elf64_ph;
    return 0;
}

long OSIS::Osis_elf::get_mp_elf64_sh(Elf64_Shdr *&p)
{
    p = mp_elf64_sh;
    return 0;
}

long OSIS::Osis_elf::get_m_elf_sec_infos(struct elf64_section_info_s &obj)
{
    obj = m_elf_sec_infos;
    return 0;
}
long OSIS::Osis_elf::get_m_elf_seg_infos(struct elf64_segments_info_s &obj)
{
    obj = m_elf_seg_infos;
    return 0;
}

long OSIS::Osis_elf::get_p_mem(unsigned char *&obj)
{
    obj = p_mem;
    return 0;
}
long OSIS::Osis_elf::get_ml_mem_size(long &obj)
{
    obj = ml_mem_size;
    return 0;
}
long OSIS::Osis_elf::set_ml_mem_size(long obj)
{
    ml_mem_size = obj;
    return 0;
}

long OSIS::Osis_elf::find_secInfo_by_secname(char *name, int &index)
{
    index = -1;
    if (!m_elf_sec_infos.pstru_sec_infos || m_elf_sec_infos.sh_num < 1 || name == NULL) {
        if (m_debug_flag)
            output_debug_string(0, 1, "param invalid pstru_sec_infos [%d] sh_num[%d] name[%d] (%s:%d)\n",
                                m_elf_sec_infos.pstru_sec_infos, m_elf_sec_infos.sh_num, name, __FILE__, __LINE__);
        return -1;
    }
    for (int i = 0; i < m_elf_sec_infos.sh_num; i++) {
        if (m_elf_sec_infos.pstru_sec_infos[i].str_sh_name.compare(name) == 0) {
            index = i;
            printf("find  %s sh_name[%s] index[%d]\n", name, m_elf_sec_infos.pstru_sec_infos[i].str_sh_name.c_str(),
                   index);
            return 0;
        }
    }
    return -1;
}

long OSIS::Osis_elf::find_seginfo_by_SegtypeAndSecidx(int seg_type, int secindex, int &segindex)
{
    segindex = -1;
    if (!m_elf_seg_infos.pstru_seg_infos || m_elf_seg_infos.seg_num < 1) {
        if (m_debug_flag)
            output_debug_string(0, 1,
                                "param invalid pstru_seg_infos [%d] seg_num[%d] "
                                "(%s:%d)\n",
                                m_elf_seg_infos.pstru_seg_infos, m_elf_seg_infos.seg_num, __FILE__, __LINE__);
        return -1;
    }
    if (!m_elf_sec_infos.pstru_sec_infos || (m_elf_sec_infos.sh_num - 1) < secindex) {
        if (m_debug_flag)
            output_debug_string(0, 1,
                                "param invalid pstru_sec_infos [%d] sh_num[%d] secindex[%d] "
                                "(%s:%d:%s)\n",
                                m_elf_sec_infos.pstru_sec_infos, m_elf_sec_infos.sh_num, secindex, __FILE__, __LINE__,
                                __func__);
        return -1;
    }
    uint64_t sec_offset = 0;
    sec_offset = m_elf_sec_infos.pstru_sec_infos[secindex].s_offset;
    for (int i = 0; i < m_elf_seg_infos.seg_num; i++) {
        if (m_elf_seg_infos.pstru_seg_infos[i].seg_type == seg_type) {
            uint64_t max_segoffset =
                m_elf_seg_infos.pstru_seg_infos[i].seg_offset + m_elf_seg_infos.pstru_seg_infos[i].seg_filesz;
            printf(" the segment index[%d] sec_offset [%p] seg_offset[%p] max_segoffset[%p]\n", i, sec_offset,
                   m_elf_seg_infos.pstru_seg_infos[i].seg_offset, max_segoffset);
            if (sec_offset >= m_elf_seg_infos.pstru_seg_infos[i].seg_offset && sec_offset < max_segoffset) {
                segindex = i;
                printf("find the segment index[%d]\n", segindex);
                return 0;
            }
        }
    }
    return -1;
}

long OSIS::Osis_elf::find_firstsSeg_by_seg_type(int seg_type, int &segindex)
{
    segindex = -1;
    if (!m_elf_seg_infos.pstru_seg_infos || m_elf_seg_infos.seg_num < 1) {
        if (m_debug_flag)
            output_debug_string(0, 1,
                                "param invalid pstru_seg_infos [%d] seg_num[%d] "
                                "(%s:%d)\n",
                                m_elf_seg_infos.pstru_seg_infos, m_elf_seg_infos.seg_num, __FILE__, __LINE__);
        return -1;
    }
    uint64_t sec_offset = 0;
    for (int i = 0; i < m_elf_seg_infos.seg_num; i++) {
        if (m_elf_seg_infos.pstru_seg_infos[i].seg_type == seg_type) {
            segindex = i;
            printf("find the segment index[%d]\n", segindex);
            return 0;
        }
    }
    return -1;
}

long OSIS::Osis_elf::find_secInfo_by_vaddr(Elf64_Addr vaddr, int &index)
{
    index = -1;
    if (!m_elf_sec_infos.pstru_sec_infos || m_elf_sec_infos.sh_num < 1) {
        if (m_debug_flag)
            output_debug_string(0, 1, "param invalid pstru_sec_infos [%d] sh_num[%d]  (%s:%d)\n",
                                m_elf_sec_infos.pstru_sec_infos, m_elf_sec_infos.sh_num, __FILE__, __LINE__);
        return -1;
    }
    for (int i = 0; i < m_elf_sec_infos.sh_num; i++) {
        Elf64_Addr b_addr = m_elf_sec_infos.pstru_sec_infos[i].s_addr;
        Elf64_Addr e_addr = b_addr + m_elf_sec_infos.pstru_sec_infos[i].s_size;
        if (vaddr >= b_addr && vaddr < e_addr) {
            index = i;
            printf("find vaddr[%p]  sh_name[%s] index[%d]\n", vaddr,
                   m_elf_sec_infos.pstru_sec_infos[i].str_sh_name.c_str(), index);
            return 0;
        }
    }
    return -1;
}
long OSIS::Osis_elf::find_secidx_by_dtag(int64_t dtag, int &index)
{
    int dynamic_idx = -1, i = 0;
    find_firstsec_by_type(SHT_DYNAMIC, dynamic_idx);
    if (dynamic_idx == -1) {
        if (m_debug_flag) output_debug_string(0, 1, " SHT_DYNAMIC NOT FOUND (%s:%d)\n", __FILE__, __LINE__);
        return -1;
    }
    Elf64_Dyn *dyn = (Elf64_Dyn *)(m_elf_sec_infos.pstru_sec_infos[dynamic_idx].p_sec);
    for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
        if (dyn[i].d_tag == dtag) {
            int t_tagsec_idx = -1;
            find_secInfo_by_vaddr(dyn[i].d_un.d_ptr, t_tagsec_idx);
            if (t_tagsec_idx == -1) {
                output_debug_string(0, 1, " dtag[%d] d_un.d_ptr[%p] section NOT FOUND (%s:%d)\n", dtag,
                                    dyn[i].d_un.d_ptr, __FILE__, __LINE__);
                break;
            }
            index = t_tagsec_idx;
            // printf("find first section sh_type[%d]  sh_name[%s] index[%d]\n",\
            sec_type, m_elf_sec_infos.pstru_sec_infos[i].str_sh_name.c_str(),index);
            output_debug_string(0, 1,
                                " find first section sh_type[%d]  sh_name[%s] "
                                "index[%d] (%s:%d)\n",
                                m_elf_sec_infos.pstru_sec_infos[index].sh_type,
                                m_elf_sec_infos.pstru_sec_infos[index].str_sh_name.c_str(), index, __FILE__, __LINE__);
            return 0;
        }
    }
    //  find_section_dynamic()
    return -1;
}

long OSIS::Osis_elf::find_firstsec_by_type(int sec_type, int &index)
{
    index = -1;
    if (!m_elf_sec_infos.pstru_sec_infos || m_elf_sec_infos.sh_num < 1) {
        if (m_debug_flag)
            output_debug_string(0, 1, "param invalid pstru_sec_infos [%d] sh_num[%d]  (%s:%d)\n",
                                m_elf_sec_infos.pstru_sec_infos, m_elf_sec_infos.sh_num, __FILE__, __LINE__);
        return -1;
    }
    for (int i = 0; i < m_elf_sec_infos.sh_num; i++) {
        if (m_elf_sec_infos.pstru_sec_infos[i].sh_type == sec_type) {
            index = i;
            printf("find first section sh_type[%d]  sh_name[%s] index[%d]\n", sec_type,
                   m_elf_sec_infos.pstru_sec_infos[i].str_sh_name.c_str(), index);
            return 0;
        }
    }
    return -1;
}

long OSIS::Osis_elf::find_relaentidx_by_symname(char *name, int &relasec_idx, int &ent_idx)
{
    if (!m_elf_sec_infos.pstru_sec_infos || m_elf_sec_infos.sh_num < 1 || name == NULL) {
        if (m_debug_flag)
            output_debug_string(0, 1, "param invalid pstru_sec_infos [%d] sh_num[%d] name[%d] (%s:%d)\n",
                                m_elf_sec_infos.pstru_sec_infos, m_elf_sec_infos.sh_num, name, __FILE__, __LINE__);
        return -1;
    }
    int dynamic_idx = -1, i = 0;
    int fist_loadseg_idx = -1;
    relasec_idx = -1;
    ent_idx = -1;
    Elf64_Sym *symtab;
    Elf64_Addr *pltgot = NULL;
    Elf64_Addr base_vaddr;
    int sec_got_idx = -1;
    int sec_pltgot_idx = -1;
    int dynstr_indx = -1;
    char *strtab = NULL;
    size_t strtab_size = -1;
    int sec_plt_rela_idx = -1;
    size_t jmprel_size = -1;
    Elf64_Rela *jmprel = NULL;
    int symindex = -1;
    find_firstsSeg_by_seg_type(PT_LOAD, fist_loadseg_idx);
    if (fist_loadseg_idx == -1) {
        printf("NOT FOUND PT_LOAD SEGMENT]\n");
        return -1;
    }
    base_vaddr = m_elf_seg_infos.pstru_seg_infos[fist_loadseg_idx].seg_vaddr;
    find_firstsec_by_type(SHT_DYNAMIC, dynamic_idx);
    if (dynamic_idx == -1) {
        if (m_debug_flag) output_debug_string(0, 1, " SHT_DYNAMIC NOT FOUND (%s:%d)\n", __FILE__, __LINE__);
        return -1;
    }
    Elf64_Dyn *dyn = (Elf64_Dyn *)(m_elf_sec_infos.pstru_sec_infos[dynamic_idx].p_sec);
    for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:  // relative to the text segment base
            // symtab = (Elf64_Sym *)&target->mem[dyn[i].d_un.d_ptr - target->textVaddr];
            symtab = (Elf64_Sym *)(p_mem + (dyn[i].d_un.d_ptr - base_vaddr));
            printf("[+] symtab: %p\n", symtab);
            printf("target_mem[%p]dyn[i].d_un.d_ptr[%p]base_vaddr[%p]\n", p_mem, dyn[i].d_un.d_ptr, base_vaddr);
            break;
        case DT_PLTGOT:  // relative to the data segment base

            find_secInfo_by_vaddr(dyn[i].d_un.d_ptr, sec_pltgot_idx);
            if (sec_pltgot_idx == -1) {
                printf("NOT FOUND pltgot]\n");
                break;
            }
            pltgot = (Elf64_Addr *)(m_elf_sec_infos.pstru_sec_infos[sec_pltgot_idx].p_sec);

            printf("[+] pltgot: %p\n", pltgot);
            break;
        case DT_STRTAB:  // relative to the text segment base
            find_secInfo_by_vaddr(dyn[i].d_un.d_ptr, dynstr_indx);
            if (dynstr_indx == -1) {
                printf("NOT FOUND dynstr_indx]\n");
                break;
            }
            strtab = (char *)(m_elf_sec_infos.pstru_sec_infos[dynstr_indx].p_sec);
            printf("[+] strtab: %p\n", strtab);
            break;
        case DT_STRSZ:
            strtab_size = (size_t)dyn[i].d_un.d_val;
            printf("[+] strtab_size: %d\n", strtab_size);
            break;
        case DT_JMPREL:
            find_secInfo_by_vaddr(dyn[i].d_un.d_ptr, sec_plt_rela_idx);
            if (sec_plt_rela_idx == -1) {
                printf("NOT FOUND sec_plt_rela_idx]\n");
                break;
            }
            jmprel = (Elf64_Rela *)(m_elf_sec_infos.pstru_sec_infos[sec_plt_rela_idx].p_sec);

            printf("[+] jmprel: %p\n", jmprel);
            // jmprel = (Elf64_Rela *)&target->mem[dyn[i].d_un.d_ptr - target->textVaddr];
            break;
        case DT_PLTRELSZ:
            jmprel_size = (size_t)dyn[i].d_un.d_val;
            printf("[+] jmprel_size: %d\n", jmprel_size);
            break;
        }
    }

    if (symtab == NULL || pltgot == NULL) {
        printf("[-] Unable to locate symtab or pltgot\n");
        return -1;
    }

    for (i = 0; symtab[i].st_name <= strtab_size; i++) {
        if (!strcmp(&strtab[symtab[i].st_name], name)) {
            printf("[+] %s symbol index: %d\n", name, i);
            symindex = i;
            break;
        }
    }

    for (i = 0; i < jmprel_size / sizeof(Elf64_Rela); i++) {
        int tmpindex = ELF64_R_SYM(jmprel[i].r_info);
        printf("symname: %s\n", &strtab[symtab[ELF64_R_SYM(jmprel[i].r_info)].st_name]);
        if (!strcmp(&strtab[symtab[ELF64_R_SYM(jmprel[i].r_info)].st_name], name)) {
            relasec_idx = sec_plt_rela_idx;
            ent_idx = i;
            if (m_debug_flag)
                output_debug_string(0, 0, "find name[%s] relasec_idx [%d] ent_idx[%d]  (%s:%d)\n", name, relasec_idx,
                                    ent_idx, __FILE__, __LINE__);
            break;
        }
    }

    return 0;
}
long OSIS::Osis_elf::find_symvalue_by_syname(char *name, Elf64_Addr & value)
{
    if (!m_elf_sec_infos.pstru_sec_infos || m_elf_sec_infos.sh_num < 1 || name == NULL) {
        if (m_debug_flag)
            output_debug_string(0, 1, "param invalid pstru_sec_infos [%d] sh_num[%d] name[%d] (%s:%d)\n",
                                m_elf_sec_infos.pstru_sec_infos, m_elf_sec_infos.sh_num, name, __FILE__, __LINE__);
        return -1;
    }
    if (!mp_elf64_sh) {
        if (m_debug_flag) output_debug_string(0, 1, "mp_elf64_sh is null (%s:%d)\n", __FILE__, __LINE__);
        return -1;
    }
    if (!mp_elf64_eh) {
        if (m_debug_flag) output_debug_string(0, 1, "mp_elf64_eh is null (%s:%d)\n", __FILE__, __LINE__);
        return -1;
    }
    int i = 0, j = 0, sym_idx = -1, dynsym_inx = -1;
    Elf64_Sym *symtab;
    char *SymStrTable;
    find_firstsec_by_type(SHT_SYMTAB, sym_idx);
    if (sym_idx == -1) {
        if (m_debug_flag) output_debug_string(0, 1, " SHT_SYMTAB NOT FOUND (%s:%d)\n", __FILE__, __LINE__);
        return -1;
    }
    // SymStrTable = (char *)get_section_index(shdr[i].sh_link, target);
    int tlink_idx = -1;
    tlink_idx = m_elf_sec_infos.pstru_sec_infos[sym_idx].sh_link;
    // m_elf_sec_infos.pstru_sec_infos[sym_idx].
    SymStrTable = (char *)(m_elf_sec_infos.pstru_sec_infos[tlink_idx].p_sec);
    symtab = (Elf64_Sym *)(m_elf_sec_infos.pstru_sec_infos[sym_idx].p_sec);
    for (j = 0; j < mp_elf64_sh[sym_idx].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
        if (strcmp(&SymStrTable[symtab->st_name], name) == 0) {
            value=symtab->st_value;
            //return (symtab->st_value);
            return 0;
        }
    }

    find_firstsec_by_type(SHT_DYNSYM, dynsym_inx);
    if (dynsym_inx == -1) {
        if (m_debug_flag) output_debug_string(0, 1, " SHT_DYNSYM NOT FOUND (%s:%d)\n", __FILE__, __LINE__);
        return -1;
    }
    tlink_idx = m_elf_sec_infos.pstru_sec_infos[dynsym_inx].sh_link;
    SymStrTable = (char *)(m_elf_sec_infos.pstru_sec_infos[tlink_idx].p_sec);
    symtab = (Elf64_Sym *)(m_elf_sec_infos.pstru_sec_infos[dynsym_inx].p_sec);
    for (j = 0; j < mp_elf64_sh[dynsym_inx].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
        if (strcmp(&SymStrTable[symtab->st_name], name) == 0) {
           // return (symtab->st_value);
            value=symtab->st_value;
            //return (symtab->st_value);
            return 0;
        }
    }

    return -1;
}