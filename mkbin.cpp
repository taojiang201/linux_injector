#include <elf.h>
#include <stdio.h>
#include <stdlib.h>

#include "osis_FileMmap.h"
#include "osis_elf.h"
#include "osis_tools.h"
long loadfile(OSIS::FileMmap &m_target_mmap, OSIS::Osis_elf &m_target_elf, char *path)
{
    long lresult = 0;
    m_target_mmap.set_debug_flag(1);
    lresult = m_target_mmap.init(path, O_RDWR, PROT_READ | PROT_WRITE, MAP_PRIVATE);
    if (lresult < 0) return lresult;
    m_target_elf.set_debug_flag(1);
    lresult = m_target_elf.set_mpath(path, strlen(path));
    if (lresult < 0) return lresult;
    uint8_t *p_mem_map = NULL;
    m_target_mmap.get_map_men(p_mem_map);
    long mem_size = 0;
    m_target_mmap.get_m_file_size(mem_size);
    lresult = m_target_elf.load_from_Mem(p_mem_map, mem_size);
    if (lresult < 0) return lresult;
    m_target_elf.find_section_dynamic();
    lresult = m_target_elf.parse_elf64();
    if (lresult < 0) return lresult;
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: %s filename \n", argv[0]);
        return -1;
    }
    char filename[256];
    memset(filename, 0, 256);
    snprintf(filename, 255, "%s", argv[1]);
    long lret = 0;
    OSIS::FileMmap m_target_mmap;
    OSIS::Osis_elf m_target_elf;
    loadfile(m_target_mmap, m_target_elf, filename);
    int idx = -1;
    lret = m_target_elf.find_secInfo_by_secname(".text", idx);
    if (lret == -1) {
        printf("find_secInfo_by_secname fail\n", argv[0]);
        return -1;
    }
    struct OSIS::elf64_section_info_s m_elf_sec_infos;
    m_target_elf.get_m_elf_sec_infos(m_elf_sec_infos);
    long offset = m_elf_sec_infos.pstru_sec_infos[idx].s_offset;
    long size = m_elf_sec_infos.pstru_sec_infos[idx].s_size;
    printf("offset=%d,size=%d\n",offset,size);
    size_t rem = size % 16;
    size_t quot = size/ 16;
    char cmd[1024];
    memset(cmd,0,1024);
    snprintf(cmd,1023,"dd if=%s of=%s.bin bs=1 skip=%d count=%d",filename,filename,offset,size);
    system(cmd);
    return 0;
}
