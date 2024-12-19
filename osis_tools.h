#ifndef __osis_tools_H__
#define __osis_tools_H__
#include<stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h> 
#include "SCS.h"
#include<string.h>
#include <sys/time.h> 
#include <stdarg.h>
namespace OSIS {
    extern locker g_localtime_r_Locker;
    class Osis_tools{
        public:
        Osis_tools();
        ~Osis_tools();

        long is_valid_pointer(void *ptr);

    };
    long get_file_size(const char* path);
    long get_file_size_fd(int fd);
    void nolocks_localtime(struct tm* tmp, time_t t, time_t tz, int dst);
    int GblLogMsg(int debugLevel, const char* format, ...);
    int output_debug_string(int debug_level,int info_level,const char* format, ...);
    void print_hex(const unsigned char* buff, size_t size);
    //size_t GetCurrentExcutableFilePathName(pid_t pid, char* processdir, size_t dirLen, char* processname, size_t nameLen);
}
#endif