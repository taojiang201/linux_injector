#ifndef __osis_ptrace_H__
#define __osis_ptrace_H__
#include <assert.h>
#include <cpuid.h>
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/kdev_t.h>
#include <dirent.h>
#include "osis_tools.h"
namespace OSIS
{
#define PROC_DIR "/proc"
#define PROC_MAPS "maps"
#define PROC_STATUS "status"
// XSAVE 特性标志位
#define XSAVE_FEATURE_FLAG 0x04000000
#define MAZ_PAYLOAD_FUNC_ARGS 0X10

#define VM_READ 0x00000001
#define VM_WRITE 0x00000002
#define VM_EXEC 0x00000004
#define VM_SHARED 0x00000008
#define VM_MAYSHARE 0x00000080
// 获取 XSTATE 大小和特性信息的结构
struct xsave_info {
    uint64_t features_supported;  // CPU 支持的特性掩码
    uint32_t size;                // 需要的总大小
    uint32_t user_size;           // 用户态可访问的大小
    uint32_t supervisor_size;     // 内核态可访问的大小
};
struct x86_64_all_reg {
    struct user_regs_struct regs;
    struct user_fpregs_struct fpregs;
    void *pxstate_buff;
    int xstateBuff_len;
};
typedef enum { _PT_FUNCTION = 0, _PT_SYSCALL = 1 } ptype_t;

struct payload_call_function {
    uint8_t *shellcode;
    void *args[MAZ_PAYLOAD_FUNC_ARGS];
    uint64_t target;
    uint64_t retval;
    size_t size;
    int argc;
    ptype_t ptype;
    struct user_regs_struct regs;
};
struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct proc_maps_entry {
    void *start;
    void *end;
    int flags;
    unsigned long long offset;
    dev_t device;
    unsigned long inode;
    char *name;

    struct list_head list;
};

long get_allreg(pid_t pid, struct x86_64_all_reg *pstru_x8664_all_reg);
long set_allreg(pid_t pid, struct x86_64_all_reg *pstru_x8664_all_reg);
long get_xsave_info(struct xsave_info *info);
void *allocate_xsave_area(size_t size);
int ptrace_attach(pid_t tid);
void print_supported_features(uint64_t features);
int ptrace_procfs_status_is_stopped(pid_t pid);
FILE *ptrace_procfs_status_open(pid_t pid);
FILE *ptrace_procfs_maps_open(pid_t pid);
FILE *fopen_no_EINTR(const char *path, const char *mode);
int fclose_no_EINTR(FILE *fp);
int ptrace_signal_send(pid_t pid, int signal);
int ptrace_wait_event(pid_t pid);
pid_t waitpid_no_EINTR(pid_t pid, int *status, int options);
int ptrace_continue_signal(pid_t pid, int signum);
int ptrace_x86_64_update_compat32_mode(pid_t pid);
int getMemoryBase(pid_t pid, Elf64_Addr &base_addr);
int ptrace_detach(pid_t pid);
int ptrace_getproc_status(pid_t pid, char *pcstatus, int bufferlen);
int ptrace_read(pid_t pid, void *dest, const void *src, size_t len);
int create_fn_shellcode(void (*)(), uint8_t *shcodebuff, size_t len);
int ptrace_write(pid_t pid, void *dest, const void *src, size_t len);
int ptrace_wait_breakpoint(pid_t pid);
int ptrace_wait_signal(pid_t pid, int signum);
void *ptrace_procfs_maps_find_exec(pid_t pid);
struct proc_maps_entry *ptrace_procfs_maps_read_entry(FILE *fp);
void ptrace_procfs_map_entry_destroy(struct proc_maps_entry *entry);
int ptrace_procfs_maps_close(FILE *fp);
int check_process_state(pid_t pid);
bool is_process_traced(pid_t pid) ;
bool is_traceable(pid_t pid);
bool check_process_state1(pid_t pid);
bool wait_for_process_ready(pid_t pid, int timeout_ms = 5000) ;
int safe_ptrace_attach(pid_t pid);
int pause_other_threads(pid_t pid);
int check_thread_state(pid_t pid,pid_t tid);
bool wait_for_thread_ready(pid_t pid, pid_t tid,int timeout_ms=5000);
int detach_all_threads(pid_t pid);
int get_libc_info(pid_t pid,char * path ,int size,unsigned long &addr);
 size_t GetCurrentExcutableFilePathName(pid_t pid, char* processdir, size_t dirLen, char* processname, size_t nameLen);
 long ptrace_memset(pid_t pid, void *dest, u_int8_t _Val, size_t len);
 long get_so_baseaddr(pid_t pid,char*soname,char * path ,int size,unsigned long &addr);
}  // namespace OSIS

#endif