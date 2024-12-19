#ifndef __osis_FileMmap_H__
#define __osis_FileMmap_H__
#include<stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<string.h>
#include <errno.h>
#include "osis_tools.h"
#include "osis_global.h"
namespace OSIS 
{
    struct mmap_param
    {


    };
    class FileMmap
    {
        
        public:
        FileMmap();
        ~FileMmap();
        bool isInit();
        long init(char* path,int file_flags,int map_prots,int map_flags);//flags for open = (O_RDONLY or O_RDWR  ) |O_CREAT
        unsigned char set_debug_flag(unsigned char ucflag);
        long get_map_men(u_int8_t* &p);//
        long get_mpath(char* &p,int size);
        long get_m_file_size(long &filesize);

        private:
        bool m_init_flag;
        char m_path[PATH_MAX];
        OSIS::Osis_tools m_osis_tools;
        int m_fd;
        unsigned char m_debug_flag;
        long m_file_size;
        long output_debug_string(int debug_level,int info_level,const char* format, ...);
        u_int8_t *map_mem;
    };



}
#endif