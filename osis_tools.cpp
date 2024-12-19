#include "osis_tools.h"
OSIS::Osis_tools::Osis_tools() {}

OSIS::Osis_tools::~Osis_tools() {}
locker OSIS::g_localtime_r_Locker;
long OSIS::Osis_tools::is_valid_pointer(void* ptr) { return 1; }
long OSIS::get_file_size(const char* path)
{
    long filesize = -1;
    struct stat statbuff;
    if (stat(path, &statbuff) < 0) {
        return filesize;
    } else {
        filesize = statbuff.st_size;
    }
    return filesize;
}
long OSIS::get_file_size_fd(int fd)
{
    long filesize = -1;
    struct stat statbuff;
    if (fstat(fd, &statbuff) < 0) {
        return filesize;
    } else {
        filesize = statbuff.st_size;
    }
    return filesize;
}
int OSIS::GblLogMsg(int debugLevel, const char* format, ...)
{
    // ilevel = 0;

    return 0;
}

int OSIS::output_debug_string(int debug_level, int info_level, const char* format, ...)
{
    char tmpbuf[128], day[256], LogTxt[8192];
    char arg_buffer[9216];
    memset(tmpbuf, 0, 128);
    memset(day, 0, 256);
    memset(LogTxt, 0, 8192);
    memset(arg_buffer, 0, 9216);
    va_list arglist;
    struct tm* p1 = NULL;
    struct timespec ts;
    struct tm tm_info;
    struct tm* p = &tm_info;
    // 获取当前时间
    clock_gettime(CLOCK_REALTIME, &ts);
    // 转换为tm结构体
    p1 = localtime_r(&ts.tv_sec, &tm_info);
    if (p1 == NULL) {
        printf("localtime_r fail!\n");
    }
    // 格式化时间为年月日时分秒
    // strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
    va_start(arglist, format);
    vsnprintf(LogTxt, 8192 - 1, format, arglist);
    va_end(arglist);
    sprintf(tmpbuf, "%d:%02d:%02d:%02d:%02d:%02d.%09.9d", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, p->tm_hour,
            p->tm_min, p->tm_sec, ts.tv_nsec);
    snprintf(arg_buffer, 9216 - 1, "%s--%s\n", tmpbuf, LogTxt);

    if (info_level == 0)
        fprintf(stdout, "%s%s", "[INFO]:", arg_buffer);
    else
        fprintf(stderr, "%s%s", "[ERR:]", arg_buffer);
    return 0;
}

void OSIS::nolocks_localtime(struct tm* tmp, time_t t, time_t tz, int dst) {}
void OSIS::print_hex(const unsigned char* buff, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        printf("0X%02X ", buff[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

