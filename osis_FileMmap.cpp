#include "osis_FileMmap.h"
OSIS::FileMmap::FileMmap(){
    m_init_flag=0;
    memset(m_path,0,PATH_MAX);
    m_fd=-1;
    m_debug_flag=0;
    m_file_size=-1;
    map_mem=NULL;
}
OSIS::FileMmap::~FileMmap()
{
    if(map_mem)
        munmap(map_mem, m_file_size);

}
bool OSIS::FileMmap::isInit(){
    return m_init_flag;
}

long OSIS::FileMmap::init(char* path,int file_flags,int map_prots,int map_flags){
    if(path==0) {
        if(m_debug_flag){
           output_debug_string(0,1,"path is null (%s:%d)\n",__FILE__,__LINE__);
        }
        return -1;
    }
    snprintf(m_path,PATH_MAX,"%s",path);
    m_fd = open(m_path, file_flags);
    if(m_fd<0) {
        if(m_debug_flag)
             output_debug_string(0,1,"Unable to open %s: %s (%s:%d)\n",path, strerror(errno),__FILE__,__LINE__);
        return -2;
    }
    m_file_size=OSIS::get_file_size_fd(m_fd);
    if(m_file_size<0) {
        if(m_debug_flag)
            output_debug_string(0,1,"filesize %d (%s:%d)\n",m_file_size,__FILE__,__LINE__) ;//fprintf(stderr,"filesize %d (%s:%d)\n",m_file_size,__FILE__,__LINE__);
        return -3;
    }
    map_mem= (unsigned char*)mmap(NULL, m_file_size, map_prots, map_flags, m_fd,0);
     if(map_mem==MAP_FAILED ){
        if(m_debug_flag)
             output_debug_string(0,1,"mmap fail %s: %s (%s:%d)\n",path, strerror(errno),__FILE__,__LINE__);
             return -4;
     }
    return 0;
}

unsigned char  OSIS::FileMmap::set_debug_flag(unsigned char ucflag){
    m_debug_flag=ucflag;
    return 0;
}
long OSIS::FileMmap::get_map_men(u_int8_t* &p)
{
    p=map_mem;
    return 0;
}
long OSIS::FileMmap::get_mpath(char* &p,int size)
{
    if(p==NULL||size <PATH_MAX) {
        if(m_debug_flag)
             output_debug_string(0,1,"param check invalid! p(%d),size(%d) (%s:%d)\n",\
             p,size, __FILE__,__LINE__);
        return -1;
    }
    snprintf(p,PATH_MAX,"%s",m_path);
    return 0;
}
long OSIS::FileMmap::get_m_file_size(long &filesize)
{
    filesize=this->m_file_size;
    return 0;
}

long OSIS::FileMmap::output_debug_string(int debug_level,int info_level,const char* format, ...)
{
    char tmpbuf[128], day[256], LogTxt[8192];
	char arg_buffer[9216];
	memset(tmpbuf, 0, 128);
	memset(day, 0, 256);
	memset(LogTxt, 0, 8192);
	memset(arg_buffer, 0, 9216);
	va_list arglist;
    struct tm*p1=NULL;
    struct timespec ts;
    struct tm tm_info;
    struct tm*p=&tm_info;
    // 获取当前时间
    clock_gettime(CLOCK_REALTIME, &ts);
    // 转换为tm结构体
     p1=localtime_r(&ts.tv_sec,&tm_info);
     if (p1==NULL){
        printf("localtime_r fail!\n");
     }   
    // 格式化时间为年月日时分秒
    //strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
    va_start(arglist, format);
	vsnprintf(LogTxt, 8192 - 1, format, arglist);
	va_end(arglist);
	sprintf(tmpbuf, "%d:%02d:%02d:%02d:%02d:%02d.%09.9d", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, ts.tv_nsec);
	snprintf(arg_buffer, 9216-1, "%s--%s\n", tmpbuf, LogTxt);
//	printf("%s",arg_buffer);
    if(info_level==0) 
         fprintf(stdout,"%s%s","INFO:",arg_buffer);
    else
         fprintf(stderr,"%s%s","ERR:",arg_buffer);
    return 0;
}





