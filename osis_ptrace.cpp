#include "osis_ptrace.h"

static int syscall_trap = SIGTRAP;
#if defined(__i386__)
typedef uint16_t ptrace_x86_seg_register_t;
typedef uint32_t ptrace_x86_register_t;
#elif defined(__x86_64__)
typedef uint16_t ptrace_x86_seg_register_t;
typedef uint64_t ptrace_x86_register_t;
#else
#error "libptrace is not usable with this architecture."
#endif
#define DEFINE_PTRACE_GET_REG(r)                                                        \
    int __ptrace_get_##r(pid_t pid, ptrace_x86_register_t *r)                           \
    {                                                                                   \
        long ret;                                                                       \
                                                                                        \
        errno = 0;                                                                      \
        ret = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user_regs_struct, r), NULL); \
                                                                                        \
        if (ret == -1 && errno != 0) {                                                  \
            return -1;                                                                  \
        }                                                                               \
                                                                                        \
        *r = (ptrace_x86_register_t)ret;                                                \
                                                                                        \
        return 0;                                                                       \
    }                                                                                   \
                                                                                        \
    ptrace_x86_register_t ptrace_get_##r(pid_t pid)                                     \
    {                                                                                   \
        ptrace_x86_register_t reg;                                                      \
                                                                                        \
        if (__ptrace_get_##r(pid, &reg) == -1) return -1;                               \
                                                                                        \
        return reg;                                                                     \
    }
#define DEFINE_PTRACE_GET_SEG_REG(r)                                                    \
    int __ptrace_get_##r(pid_t pid, ptrace_x86_seg_register_t *r)                       \
    {                                                                                   \
        long ret;                                                                       \
                                                                                        \
        errno = 0;                                                                      \
        ret = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user_regs_struct, r), NULL); \
                                                                                        \
        if (ret == -1 && errno != 0) {                                                  \
            return -1;                                                                  \
        }                                                                               \
                                                                                        \
        *r = (ptrace_x86_seg_register_t)ret;                                            \
                                                                                        \
        return 0;                                                                       \
    }                                                                                   \
                                                                                        \
    ptrace_x86_seg_register_t ptrace_get_##r(pid_t pid)                                 \
    {                                                                                   \
        ptrace_x86_seg_register_t reg;                                                  \
                                                                                        \
        if (__ptrace_get_##r(pid, &reg) == -1) return -1;                               \
                                                                                        \
        return reg;                                                                     \
    }
#if defined(__i386__)
DEFINE_PTRACE_GET_REG(eax)
DEFINE_PTRACE_GET_REG(ebx)
DEFINE_PTRACE_GET_REG(ecx)
DEFINE_PTRACE_GET_REG(edx)
DEFINE_PTRACE_GET_REG(esi)
DEFINE_PTRACE_GET_REG(edi)
DEFINE_PTRACE_GET_REG(esp)
DEFINE_PTRACE_GET_REG(ebp)
DEFINE_PTRACE_GET_REG(eip)
DEFINE_PTRACE_GET_REG(orig_eax)
DEFINE_PTRACE_GET_REG(eflags)

DEFINE_PTRACE_SET_REG(eax)
DEFINE_PTRACE_SET_REG(ebx)
DEFINE_PTRACE_SET_REG(ecx)
DEFINE_PTRACE_SET_REG(edx)
DEFINE_PTRACE_SET_REG(esi)
DEFINE_PTRACE_SET_REG(edi)
DEFINE_PTRACE_SET_REG(esp)
DEFINE_PTRACE_SET_REG(ebp)
DEFINE_PTRACE_SET_REG(eip)
DEFINE_PTRACE_SET_REG(orig_eax)
DEFINE_PTRACE_SET_REG(eflags)
#elif defined(__x86_64__)
DEFINE_PTRACE_GET_REG(rax)
DEFINE_PTRACE_GET_REG(rbx)
DEFINE_PTRACE_GET_REG(rcx)
DEFINE_PTRACE_GET_REG(rdx)
DEFINE_PTRACE_GET_REG(rsi)
DEFINE_PTRACE_GET_REG(rdi)
DEFINE_PTRACE_GET_REG(rsp)
DEFINE_PTRACE_GET_REG(rbp)
DEFINE_PTRACE_GET_REG(rip)
DEFINE_PTRACE_GET_REG(orig_rax)
DEFINE_PTRACE_GET_REG(eflags)

#endif

DEFINE_PTRACE_GET_SEG_REG(cs)
DEFINE_PTRACE_GET_SEG_REG(ds)
DEFINE_PTRACE_GET_SEG_REG(es)
DEFINE_PTRACE_GET_SEG_REG(fs)
DEFINE_PTRACE_GET_SEG_REG(gs)
DEFINE_PTRACE_GET_SEG_REG(ss)
int OSIS::ptrace_attach(pid_t tid)
{
    int signal;
    int ret;

    if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) {
        //	PTRACE_ERR_SET_EXTERNAL(p);
        if (errno == ESRCH) {
            printf("Process %d not found\n", tid);
            return -1;
        }
        if (errno == EPERM) {
            printf("Permission denied for pid %d\n", tid);
            return -1;
        }
        if (errno == EBUSY) {
            // 进程可能已经被跟踪
            printf("Process %d is already being traced\n", tid);
            return -1;
        }

        printf("Failed to attach to process %d: %s\n", tid, strerror(errno));
        return -1;
    }

    if ((ret = ptrace_procfs_status_is_stopped(tid)) == -1) goto out_detach_error;
    if (ret == 1) {
        if (ptrace_signal_send(tid, SIGCONT) == -1) goto out_detach_error;
        // p->flags |= PTRACE_FLAG_SUSPENDED;
    }

    do {
        switch (signal = ptrace_wait_event(tid)) {
        case -1:
            goto out_detach;
        case SIGCONT:
        case SIGSTOP:
            break;
        default:
            if (ptrace_continue_signal(tid, signal) == -1) goto out_detach;
        }
    } while (signal != SIGSTOP && signal != SIGCONT);
#ifdef PTRACE_O_TRACESYSGOOD
    /* ptrace singlestep/syscall etc. will now cause the child to signal
     * SIGTRAP orred with 0x80, to distinguish from real SIGTRAPs.
     */
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == 0) syscall_trap |= 0x80;
#endif
    if (ptrace(PTRACE_SETOPTIONS, tid, NULL, PTRACE_O_TRACESYSGOOD) == 0) syscall_trap |= 0x80;
#ifdef __x86_64__
    /* If on x86-64 we check whether the process is running native, or
     * in emulated 32-bit mode.
     * Error can only be internal and has been set by the function.
     */
    if (ptrace_x86_64_update_compat32_mode(tid) == -1) goto out_detach;
#endif
    return 0;
out_detach_error:
out_detach:
    /* Try to detach; if this fails it should be because of ESRCH
     * and we ignore the return value to make things less confusing.
     */
    ptrace(PTRACE_DETACH, tid, NULL, NULL);
    return -1;
}
FILE *OSIS::ptrace_procfs_maps_open(pid_t pid)
{
    char buf[128];

    snprintf(buf, sizeof(buf), PROC_DIR "/%u/" PROC_MAPS, pid);
    return fopen_no_EINTR(buf, "r");
}
FILE *OSIS::ptrace_procfs_status_open(pid_t pid)
{
    char buf[128];

    snprintf(buf, sizeof(buf), PROC_DIR "/%u/" PROC_STATUS, pid);
    return fopen_no_EINTR(buf, "r");
}
FILE *OSIS::fopen_no_EINTR(const char *path, const char *mode)
{
    FILE *ret;

    do {
        ret = fopen(path, mode);
    } while (ret == NULL && errno == EINTR);

    return ret;
}

int OSIS::fclose_no_EINTR(FILE *fp)
{
    int ret;

    do {
        ret = fclose(fp);
    } while (ret == -1 && errno == EINTR);

    return ret;
}
/* As taken from the gdb source code */
int OSIS::ptrace_procfs_status_is_stopped(pid_t pid)
{
    char buf[256];
    int ret = 0;
    FILE *fp;

    if ((fp = ptrace_procfs_status_open(pid)) == NULL) return -1;

    while (fgets(buf, sizeof(buf), fp) != 0)
        if (strncmp(buf, "State:", 6) == 0)
            if (strstr(buf, "T (stopped)") != NULL) ret = 1;

    fclose_no_EINTR(fp);
    return ret;
}
int OSIS::ptrace_signal_send(pid_t pid, int signal)
{
    if (syscall(__NR_tkill, pid, signal) == -1) {
        // PTRACE_ERR_SET_EXTERNAL(pctx);
        return -1;
    }

    return 0;
}
int OSIS::ptrace_wait_event(pid_t pid)
{
    int status;

    if (waitpid_no_EINTR(pid, &status, 0) == -1) {
        // PTRACE_ERR_SET_EXTERNAL(pctx);
        return -1;
    }

    /* Child terminated normally */
    if (WIFEXITED(status)) {
        // PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
        return -1;
    }

    /* Child was terminated by a signal */
    if (WIFSIGNALED(status)) {
        // PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
        return -1;
    }

    /* The child was stopped by a signal; this is what we
     * expected.  If it is not the signal we're looking for,
     * delegate it to the child and continue.
     */
    if (WIFSTOPPED(status)) return WSTOPSIG(status);

    return 0;
}
pid_t OSIS::waitpid_no_EINTR(pid_t pid, int *status, int options)
{
    pid_t ret;

    do {
        ret = waitpid(pid, status, options);
    } while (ret == -1 && errno == EINTR);

    return ret;
}
int OSIS::ptrace_continue_signal(pid_t pid, int signum)
{
    unsigned long __signum = (unsigned long)signum;

    if (ptrace(PTRACE_CONT, pid, NULL, (void *)__signum) == -1) {
        // PTRACE_ERR_SET_EXTERNAL(pctx);
        return -1;
    }

    return 0;
}
#ifdef __x86_64__
int OSIS::ptrace_x86_64_update_compat32_mode(pid_t pid)
{
    ptrace_x86_seg_register_t cs;

    if (__ptrace_get_cs(pid, &cs) == -1) return -1;

    switch (cs) {
    case 0x23:
        // p->flags |= X86_64_COMPAT32;
        break;
    case 0x33:
        // p->flags |= X86_64_NATIVE;
        break;
    default:
        // PTRACE_ERR_SET_INTERNAL(p, PTRACE_ERR_X86_64_COMPAT);
        return -1;
    }

    return 0;
}
#if (0)
int OSIS::getMemoryBase(pid_t pid, Elf64_Addr &base_addr)
{
    char path[40];
    void *vm_start, *vm_end;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("fopen");
        return -1;
    }

    char line[256];
    if (fscanf(file, "%llx-%llx", &vm_start, &vm_end) != 2) return -1;
    fclose(file);
    base_addr = (Elf64_Addr)vm_start;
    printf("the vm_start = % p\n", base_addr);
    return 0;
}
#endif
int OSIS::getMemoryBase(pid_t pid, Elf64_Addr &base_addr)
{
    void *vm_start, *vm_end;
    FILE *fp;
    if ((fp = ptrace_procfs_maps_open(pid)) == NULL) return -1;
    char line[256];
    if (fscanf(fp, "%llx-%llx", &vm_start, &vm_end) != 2) return -1;
    fclose_no_EINTR(fp);
    base_addr = (Elf64_Addr)vm_start;
    printf("the vm_start = % p\n", base_addr);
    return 0;
}
int OSIS::ptrace_detach(pid_t pid)
{
    void *data = NULL;

    /* If the process was suspended when we attached to it, we suspend
     * it again.
     *
     * XXX: handle the case where we get SIGCONT while libptrace is
     * attached.
     */
    char buff[256];
    memset(buff, 256, 0);
    int iret = OSIS::ptrace_getproc_status(pid, buff, 256);
    if (iret < 0) return -1;
    if (!strstr(buff, "stop")) {
        /* Before we can detach, the LWP should be stopped. */
        if (kill(pid, SIGSTOP) == -1) {
            // PTRACE_ERR_SET_EXTERNAL(p);
            return -1;
        }
        data = (void *)SIGSTOP;
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, data) == -1) {
        //	PTRACE_ERR_SET_EXTERNAL(p);
        return -1;
    }

    return 0;
}

int OSIS::ptrace_getproc_status(pid_t pid, char *pcstatus, int bufferlen)
{
    char buf[256];
    int ret = 0;
    FILE *fp;
    if (!pcstatus || bufferlen < 1) return -1;
    if ((fp = ptrace_procfs_status_open(pid)) == NULL) return -1;

    while (fgets(buf, sizeof(buf), fp) != 0)
        if (strncmp(buf, "State:", 6) == 0) {
            memset(pcstatus, bufferlen, 0);
            snprintf(pcstatus, bufferlen, "%s", buf + 6);
            pcstatus[bufferlen - 1] = 0;  //*(pcstatus+(bufferlen-1))=0;//*pcstatus[bufferlen-1]=0
            ret = 1;
            break;
        }

    fclose_no_EINTR(fp);
    return ret;
}

int OSIS::ptrace_read(pid_t pid, void *dest, const void *src, size_t len)
{
    long w;
    size_t rem = len % sizeof(void *);
    size_t quot = len / sizeof(void *);
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dest;

    assert(sizeof(void *) == sizeof(long));

    while (quot-- != 0) {
        w = ptrace(PTRACE_PEEKDATA, pid, s, NULL);
        if (w == -1 && errno != 0) goto out_error;

        *((long *)d) = w;

        s += sizeof(long);
        d += sizeof(long);
    }

    /* The remainder of data to read will be handled in a manner
     * analogous to ptrace_write().
     */
    if (rem != 0) {
        long w;
        unsigned char *wp = (unsigned char *)&w;

        w = ptrace(PTRACE_PEEKDATA, pid, s, NULL);
        if (w == -1 && errno != 0) {
            s -= sizeof(long) - rem;

            w = ptrace(PTRACE_PEEKDATA, pid, s, NULL);
            if (w == -1 && errno != 0) goto out_error;

            wp += sizeof(void *) - rem;
        }

        while (rem-- != 0) d[rem] = wp[rem];
    }

    return 0;

out_error:
    //	PTRACE_ERR_SET_EXTERNAL(p);
    return -1;
}
long OSIS::get_xsave_info(struct xsave_info *info)
{
    unsigned int eax, ebx, ecx, edx;

    // 检查 CPU 是否支持 XSAVE
    __cpuid(1, eax, ebx, ecx, edx);
    if (!(ecx & XSAVE_FEATURE_FLAG)) {
        printf("CPU does not support XSAVE\n");
        info->size = 0;
        return -1;
    }

    // 获取支持的特性掩码
    __cpuid_count(0xD, 0, eax, ebx, ecx, edx);
    info->features_supported = ((uint64_t)edx << 32) | eax;
    info->size = ebx;       // XSAVE 区域的总大小
    info->user_size = ecx;  // 用户态可访问部分的大小

    // 获取内核态大小
    __cpuid_count(0xD, 1, eax, ebx, ecx, edx);
    info->supervisor_size = ebx;
}

// 分配对齐的 XSAVE 区域
void *OSIS::allocate_xsave_area(size_t size)
{
    // XSAVE 区域需要 64 字节对齐
    void *ptr;
    int ret = posix_memalign(&ptr, 64, size);
    if (ret != 0) {
        return NULL;
    }
    return ptr;
}

// 打印特性支持信息
void OSIS::print_supported_features(uint64_t features)
{
    printf("Supported XSAVE features:\n");
    if (features & (1ULL << 0)) printf("- x87 FPU\n");
    if (features & (1ULL << 1)) printf("- SSE\n");
    if (features & (1ULL << 2)) printf("- AVX\n");
    if (features & (1ULL << 3)) printf("- MPX BNDREGS\n");
    if (features & (1ULL << 4)) printf("- MPX BNDCSR\n");
    if (features & (1ULL << 5)) printf("- AVX-512 opmask\n");
    if (features & (1ULL << 6)) printf("- AVX-512 ZMM_Hi256\n");
    if (features & (1ULL << 7)) printf("- AVX-512 Hi16_ZMM\n");
    if (features & (1ULL << 8)) printf("- PT\n");
    if (features & (1ULL << 9)) printf("- PKRU\n");
    if (features & (1ULL << 10)) printf("- PASID\n");
    // 可以继续添加更多特性...
}
long OSIS::get_allreg(pid_t pid, struct x86_64_all_reg *pstru_x8664_all_reg)
{
    if (pstru_x8664_all_reg == NULL) {
        printf("pstru_x8664_all_reg is null\n");
        return -1;
    }
    struct iovec iov;
    /*struct xsave_info info = { 0 };
    long lret=0;
    lret=get_xsave_info(&info);
    if(lret<0)
        return lret;

    printf("XSAVE area sizes:\n");
    printf("Total size: %u bytes\n", info.size);
    printf("User accessible size: %u bytes\n", info.user_size);
    printf("Supervisor size: %u bytes\n", info.supervisor_size);

    print_supported_features(info.features_supported);

    // 分配 XSAVE 区域
    void* xsave_area = allocate_xsave_area(info.size);
    if (!xsave_area) {
        printf("Failed to allocate XSAVE area\n");
        return -1;
    }
    pstru_x8664_all_reg->xstateBuff_len=info.size;
    pstru_x8664_all_reg->pxstate_buff=xsave_area;*/

    // 获取通用寄存器
    iov.iov_base = &(pstru_x8664_all_reg->regs);
    iov.iov_len = sizeof(pstru_x8664_all_reg->regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
        // free(pstru_x8664_all_reg->pxstate_buff);
        // pstru_x8664_all_reg->pxstate_buff=NULL;
        // pstru_x8664_all_reg->xstateBuff_len=0;
        printf("PTRACE_GETREGSET (NT_PRSTATUS) error -1\n");
        return -1;
    }
    printf("General Registers:\n");
    printf("RIP: %llx\n", (pstru_x8664_all_reg->regs.rip));

    // 获取浮点寄存器
    iov.iov_base = &pstru_x8664_all_reg->fpregs;
    iov.iov_len = sizeof(pstru_x8664_all_reg->fpregs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_FPREGSET, &iov) == -1) {
        // free(pstru_x8664_all_reg->pxstate_buff);
        // pstru_x8664_all_reg->pxstate_buff=NULL;
        // pstru_x8664_all_reg->xstateBuff_len=0;
        printf("PTRACE_GETREGSET (NT_FPREGSET) error -1\n");
        return -1;
    }
    printf("Floating Point Registers:\n");
    printf("MXCSR: %llx\n", pstru_x8664_all_reg->fpregs.mxcsr);

    // 获取扩展状态（包括 AVX、SSE等）
    if (pstru_x8664_all_reg->xstateBuff_len > 0 && pstru_x8664_all_reg->pxstate_buff) {
        iov.iov_base = pstru_x8664_all_reg->pxstate_buff;
        iov.iov_len = pstru_x8664_all_reg->xstateBuff_len;
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_X86_XSTATE, &iov) == -1) {
            //	free(pstru_x8664_all_reg->pxstate_buff);
            //	pstru_x8664_all_reg->pxstate_buff=NULL;
            //	pstru_x8664_all_reg->xstateBuff_len=0;
            printf("PTRACE_GETREGSET (NT_X86_XSTATE) error -1\n");
            return -1;
        }
        printf("Extended State Registers (XSTATE):\n");
        printf("XSTATE size: %zu bytes\n", iov.iov_len);
    }

    return 0;
}

long OSIS::set_allreg(pid_t pid, struct x86_64_all_reg *pstru_x8664_all_reg)
{
    if (pstru_x8664_all_reg == NULL) {
        printf("pstru_x8664_all_reg is null\n");
        return -1;
    }
    struct iovec iov;

    // 设置通用寄存器
    iov.iov_base = &(pstru_x8664_all_reg->regs);
    iov.iov_len = sizeof(pstru_x8664_all_reg->regs);
    // if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1)
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
        // free(pstru_x8664_all_reg->pxstate_buff);
        // pstru_x8664_all_reg->pxstate_buff=NULL;
        // pstru_x8664_all_reg->xstateBuff_len=0;
        printf("PTRACE_SETREGSET (NT_PRSTATUS) error -1\n");
        return -1;
    }
    printf("General Registers:\n");
    printf("RIP: %llx\n", (pstru_x8664_all_reg->regs.rip));

    // 设置浮点寄存器
    iov.iov_base = &pstru_x8664_all_reg->fpregs;
    iov.iov_len = sizeof(pstru_x8664_all_reg->fpregs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_FPREGSET, &iov) == -1) {
        // free(pstru_x8664_all_reg->pxstate_buff);
        // pstru_x8664_all_reg->pxstate_buff=NULL;
        // pstru_x8664_all_reg->xstateBuff_len=0;
        printf("PTRACE_GETREGSET (NT_FPREGSET) error -1\n");
        return -1;
    }
    printf("Floating Point Registers:\n");
    printf("MXCSR: %llx\n", pstru_x8664_all_reg->fpregs.mxcsr);

    // 设置扩展状态（包括 AVX、SSE等）
    if (pstru_x8664_all_reg->xstateBuff_len > 0 && pstru_x8664_all_reg->pxstate_buff) {
        iov.iov_base = pstru_x8664_all_reg->pxstate_buff;
        iov.iov_len = pstru_x8664_all_reg->xstateBuff_len;
        if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_X86_XSTATE, &iov) == -1) {
            //	free(pstru_x8664_all_reg->pxstate_buff);
            //	pstru_x8664_all_reg->pxstate_buff=NULL;
            //	pstru_x8664_all_reg->xstateBuff_len=0;
            printf("PTRACE_SETREGSET (NT_X86_XSTATE) error -1\n");
            return -1;
        }
        printf("Extended State Registers (XSTATE):\n");
        printf("XSTATE size: %zu bytes\n", iov.iov_len);
    }

    return 0;
}

int OSIS::create_fn_shellcode(void (*fn)(), uint8_t *shcodebuff, size_t len)
{
    /*(size_t i;
    uint8_t *shellcode = (uint8_t *)heapAlloc(len);
    uint8_t *p = (uint8_t *)fn;

    for (i = 0; i < len; i++)
        *(shellcode + i) = *p++;

    return shellcode;*/
    if (fn == NULL || shcodebuff == NULL) {
        output_debug_string(0, 1, "param check fail [fn,%p][shcodebuff,%p]  (%s:%d)\n",\ 
		fn,
                            shcodebuff, __FILE__, __LINE__);
        return -1;
        // OSIS::output_debug_string(1,1,)
    }
    uint8_t *p = (uint8_t *)fn;

    for (int i = 0; i < len; i++) *(shcodebuff + i) = *p++;
    return 0;
}

int OSIS::ptrace_write(pid_t pid, void *dest, const void *src, size_t len)
{
    size_t rem = len % sizeof(void *);
    size_t quot = len / sizeof(void *);
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dest;

    assert(sizeof(void *) == sizeof(long));

    while (quot-- != 0) {
        if (ptrace(PTRACE_POKEDATA, pid, d, *(void **)s) == -1) goto out_error;
        s += sizeof(void *);
        d += sizeof(void *);
    }

    /* We handle the last unpadded value here.
     *
     * Suppose we have the situation where we have written the string
     * "ABCD" to 'dest', still want to write to the byte at *, but have an
     * unadressable page at X. We'll find the ptrace write at 'X' returns
     * an error, and will need to start writing at 'B' to satisfy this
     * request.
     *
     * +---+---+---+---+---+---+
     * | A | B | C | D | * | X |
     * +---+---+---+---+---+---+
     *
     * This situation is handled in the code below, which is why it might
     * look confusing.
     */
    if (rem != 0) {
        long w;
        unsigned char *wp = (unsigned char *)&w;

        w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
        if (w == -1 && errno != 0) {
            d -= sizeof(void *) - rem;

            w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
            if (w == -1 && errno != 0) goto out_error;

            wp += sizeof(void *) - rem;
        }

        while (rem-- != 0) wp[rem] = s[rem];

        if (ptrace(PTRACE_POKEDATA, pid, d, w) == -1) goto out_error;
    }

    return 0;

out_error:
    // PTRACE_ERR_SET_EXTERNAL(p);
    return -1;
}
int OSIS::ptrace_wait_breakpoint(pid_t pid)
{
    return ptrace_wait_signal(pid, SIGTRAP);
    //	return 0;
}
int OSIS::ptrace_wait_signal(pid_t pid, int signum)
{
    int status;

    do {
        if (waitpid_no_EINTR(pid, &status, 0) == -1) {
            //	PTRACE_ERR_SET_EXTERNAL(pctx);
            return -1;
        }

        /* Child terminated normally */
        if (WIFEXITED(status)) {
            // PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
            return -1;
        }

        /* Child was terminated by a signal */
        if (WIFSIGNALED(status)) {
            //	PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
            return -1;
        }

        /* The child was stopped by a signal; this is what we
         * expected.  If it is not the signal we're looking for,
         * delegate it to the child and continue.
         */
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            // if (WSTOPSIG(status) == SIGCONT) {
            //	pctx->flags &= ~PTRACE_FLAG_SUSPENDED;
            // }
            if (sig == syscall_trap) {
                // 这是系统调用导致的停止
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);

                // 打印系统调用号
                printf("syscall: %lld\n", (long long)regs.orig_rax);
            } else if (sig == SIGTRAP) {
                // 这是断点或单步导致的停止
                printf("breakpoint or single-step\n");
            }

            if (WSTOPSIG(status) != signum && ptrace_continue_signal(pid, WSTOPSIG(status)) == -1) return -1;
        }
    } while (!WIFSTOPPED(status) || WSTOPSIG(status) != signum);

    return 0;
}
static inline void skip_ws(FILE *fp)
{
    while (!feof(fp)) {
        int ch = fgetc(fp);

        if (ch == EOF || (ch != '\t' && ch != ' ')) {
            if (ch != EOF) ungetc(ch, fp);
            break;
        }
    }
}

static inline size_t file_strlen(FILE *fp)
{
    register int ch;
    register size_t len = 0;
    long offset = ftell(fp);

    if (offset == -1) return -1;

    while ((ch = fgetc(fp)) != EOF && ch != 0 && ch != '\n') len++;

    if (fseek(fp, offset, SEEK_SET) == -1) return -1;

    return len;
}
static inline void list_init(struct OSIS::list_head *lh)
{
    lh->next = lh;
    lh->prev = lh;
}
void *OSIS::ptrace_procfs_maps_find_exec(pid_t pid)
{
    struct OSIS::proc_maps_entry *entry;
    long address;
    FILE *fp;

    /* errno already set here */
    if ((fp = ptrace_procfs_maps_open(pid)) == NULL) return (void *)-1;

    while ((entry = ptrace_procfs_maps_read_entry(fp)) != NULL) {
        if (entry->flags & VM_EXEC) {
            address = (long)entry->start;
            ptrace_procfs_map_entry_destroy(entry);
            ptrace_procfs_maps_close(fp);
            errno = 0;
            return (void *)address;
        }
        ptrace_procfs_map_entry_destroy(entry);
    }

    ptrace_procfs_maps_close(fp);
    errno = ENXIO; /* no such address */
    return (void *)-1;
}
int OSIS::ptrace_procfs_maps_close(FILE *fp) { return fclose_no_EINTR(fp); }
void OSIS::ptrace_procfs_map_entry_destroy(struct proc_maps_entry *entry)
{
    assert(entry != NULL);

    if (entry->name) free(entry->name);

    free(entry);
}
struct OSIS::proc_maps_entry *OSIS::ptrace_procfs_maps_read_entry(FILE *fp)
{
    struct OSIS::proc_maps_entry *entry;
    unsigned long long offset;
    void *vm_start, *vm_end;
    unsigned long inode;
    int major, minor;
    char flags[5];
    char *name;
    size_t len;
    int ch;

    /* read vma->vm_start and vma->vm_end */
    if (fscanf(fp, "%llx-%llx", &vm_start, &vm_end) != 2) return NULL;

    /* read flags */
    if (fscanf(fp, "%4s", flags) != 1) return NULL;

    /* read offset */
    if (fscanf(fp, "%llx", &offset) != 1) return NULL;

    /* read major and minor into dev_t */
    if (fscanf(fp, "%x:%x", &major, &minor) != 2) return NULL;

    /* read the inode */
    if (fscanf(fp, "%lu", &inode) != 1) return NULL;

    /* Finally we will read the filename, but this one is dynamic in
     * length, so we process the file twice.
     */
    skip_ws(fp);

    if ((len = file_strlen(fp)) == -1) return NULL;

    if ((name = (char *)malloc(len + 1)) == NULL) return NULL;

    if (len != 0 && fscanf(fp, "%s", name) != 1) {
        free(name);
        return NULL;
    }

    /* 0-terminate, in case len == 0 and we have an empty string. */
    name[len] = 0;
    if ((entry = (struct proc_maps_entry *)malloc(sizeof(*entry))) == NULL) {
        free(name);
        return NULL;
    }

    entry->flags = 0;
    if (flags[0] != '-') entry->flags |= VM_READ;
    if (flags[1] != '-') entry->flags |= VM_WRITE;
    if (flags[2] != '-') entry->flags |= VM_EXEC;
    if (flags[3] == 's') entry->flags |= VM_MAYSHARE;

    entry->start = vm_start;
    entry->end = vm_end;
    entry->offset = offset;
    entry->device = MKDEV(major, minor);
    entry->inode = inode;
    entry->name = name;
    list_init(&entry->list);

    return entry;
}
// 检查进程状态
int OSIS::check_process_state(pid_t pid)
{
    char path[32];
    char state;
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    f = fopen(path, "r");
    if (!f) return -1;

    // 读取进程状态
    fscanf(f, "%*d %*s %c", &state);
    fclose(f);

    // 检查是否在运行或停止状态
    return (state == 'R' || state == 'T') ? 1 : 0;
}
// 检查进程状态
int OSIS::check_thread_state(pid_t pid, pid_t tid)
{
    char path[32];
    char state;
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/task/%d/stat", pid, tid);
    f = fopen(path, "r");
    if (!f) return -1;

    // 读取进程状态
    fscanf(f, "%*d %*s %c", &state);
    fclose(f);

    // 检查是否在运行或停止状态
    return (state == 'R' || state == 'T') ? 1 : 0;
}
bool OSIS::is_process_traced(pid_t pid)
{
    char path[32];
    char state;
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    f = fopen(path, "r");
    if (!f) return false;

    // 跳过pid和comm字段
    fscanf(f, "%*d %*s %c", &state);
    fclose(f);

    return state == 't' || state == 'T';
}
bool OSIS::is_traceable(pid_t pid)
{
    // 检查/proc/sys/kernel/yama/ptrace_scope
    FILE *f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    if (f) {
        int scope;
        fscanf(f, "%d", &scope);
        fclose(f);

        // 根据不同的scope值检查权限
        switch (scope) {
        case 0:  // 经典ptrace权限
            return true;
        case 1:  // 只允许父进程ptrace
            return getppid() == pid;
        case 2:  // 只允许admin ptrace
            return geteuid() == 0;
        case 3:  // 禁止所有ptrace
            return false;
        }
    }
}
bool OSIS::check_process_state1(pid_t pid)
{
    char path[64];
    char state;
    FILE *f;

    // 读取进程状态
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    f = fopen(path, "r");
    if (!f) {
        return false;
    }

    // 读取状态字段 (第三个字段)
    fscanf(f, "%*d %*s %c", &state);
    fclose(f);

    // R: 运行
    // S: 可中断睡眠
    // D: 不可中断睡眠
    // T: 停止
    // t: 被调试器跟踪
    return (state == 'S' || state == 'R' || state == 'T' || state == 't');
}

bool OSIS::wait_for_process_ready(pid_t pid, int timeout_ms)
{
    int waited = 0;
    const int check_interval = 10;  // 每10ms检查一次

    while (waited < timeout_ms) {
        if (check_process_state(pid)) {
            return true;
        }

        // 短暂睡眠
        usleep(check_interval * 1000);
        waited += check_interval;
    }
    return false;
}

bool OSIS::wait_for_thread_ready(pid_t pid, pid_t tid, int timeout_ms)
{
    int waited = 0;
    const int check_interval = 10;  // 每10ms检查一次

    while (waited < timeout_ms) {
        if (check_thread_state(pid, tid)) {
            return true;
        }

        // 短暂睡眠
        usleep(check_interval * 1000);
        waited += check_interval;
    }
    return false;
}
int OSIS::safe_ptrace_attach(pid_t pid)
{
    int16_t ct_state = 0;
    int retry_count = 3;
    int status;

    // 1. 首先等待进程进入可调试状态
    if (!wait_for_process_ready(pid)) {
        printf("Process %d not in debuggable state\n", pid);
        return -1;
    }

    // 2. 尝试attach
    while (retry_count--) {
        // 检查进程是否存在
        if (kill(pid, 0) == -1) {
            printf("Process %d does not exist\n", pid);
            return -1;
        }

        // 尝试attach
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
            if (errno == ESRCH) {
                printf("Process %d not found\n", pid);
                return -1;
            }
            if (errno == EPERM) {
                printf("Permission denied for pid %d\n", pid);
                return -1;
            }
            if (errno == EBUSY) {
                // 进程可能已经被跟踪
                printf("Process %d is already being traced\n", pid);
                return -1;
            }

            if (retry_count > 0) {
                usleep(100000);  // 100ms
                continue;
            }
            printf("Failed to attach to process %d: %s\n", pid, strerror(errno));
            return -1;
        }
        break;
    }

    // 3. 等待进程停止
    if (waitpid(pid, &status, 0) == -1) {
        printf("waitpid failed: %s\n", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        printf("Process did not stop as expected\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    // 4. 设置ptrace选项
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC) == -1) {
        printf("Failed to set ptrace options: %s\n", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    return 0;
}

int OSIS::pause_other_threads(pid_t pid)
{
    char task_dir[256];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", pid);

    // 打开进程的 /task 目录
    DIR *dir = opendir(task_dir);
    if (dir == NULL) {
        perror("opendir");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // 跳过 "." 和 ".." 目录
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        pid_t tid = atoi(entry->d_name);

        // 如果是主线程，跳过
        if (tid == pid) {
            continue;
        }

        // 附加到该线程并暂停
        if (!OSIS::wait_for_thread_ready(pid, tid)) {
            printf("Process %d not in debuggable state\n", pid);
            continue;
        }
        if (OSIS::ptrace_attach(tid) == -1) {
            printf("ptrace_attach fail tid=%d", tid);
            continue;
        }
        //   if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) {
        //      perror("ptrace attach");
        //      continue;
        //  }
        // 等待线程暂停
    }

    closedir(dir);
}

int OSIS::detach_all_threads(pid_t pid)
{
    char task_dir[256];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", pid);

    // 打开进程的 /task 目录
    DIR *dir = opendir(task_dir);
    if (dir == NULL) {
        perror("opendir");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // 跳过 "." 和 ".." 目录
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        pid_t tid = atoi(entry->d_name);

        // 如果是主线程，跳过
        if (tid == pid) {
            continue;
        }
        if (OSIS::ptrace_detach(tid) == -1) {
            printf("ptrace_attach fail tid=%d", tid);
            continue;
        }
        // 恢复所有线程

        if (kill(tid, SIGCONT) == -1) {
            if (errno != ESRCH) {
                printf("Failed to continue thread %d: %s\n", tid, strerror(errno));
            }
        }
    }
}

int OSIS::get_libc_info(pid_t pid,char * path ,int size,unsigned long &addr)
{
    if(path==NULL||size >PATH_MAX) {
             output_debug_string(0,1,"param check invalid! psth(%d),size(%d) (%s:%d)\n",\
             path,size, __FILE__,__LINE__);
        return -1;
    }
    char filename[256];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open maps file");
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        // 查找包含 libc 的行
        if (strstr(line, "libc.") && strstr(line, ".so")) {
            // 查找路径部分
            char *libc_path = strchr(line, '/');
            if(!libc_path)
                return -1;
            char *p=strchr(libc_path, '\n');
            if(p)
            {
                *p='\0';
            }
            printf("libc path: %s", libc_path);
            snprintf(path,size-1,"%s",libc_path);
               
            
            // 获取 libc 的起始地址
            sscanf(line, "%lx", &addr);
            printf("libc base address: 0x%lx\n", addr);

            fclose(file);
            return 0;
        }
    }

    printf("libc not found in the maps\n");
    fclose(file);

}
size_t OSIS::GetCurrentExcutableFilePathName(pid_t pid, char* processdir, size_t dirLen, char* processname,\
                                             size_t nameLen)
{
    char* path_end;
    char filename[256];
    snprintf(filename, sizeof(filename), "/proc/%d/exe", pid);
    if (readlink(filename, processdir, dirLen) <= 0) return -1;

    path_end = strrchr(processdir, '/');

    if (path_end == NULL) return -1;

    ++path_end;

    // strcpy(processname, path_end);
    strncpy(processname, path_end, nameLen);
    *path_end = '\0';

    return (size_t)(path_end - processdir);
}
long OSIS::ptrace_memset(pid_t pid, void *dest, u_int8_t _Val, size_t len)
{
    long lret = 0;
    int nullp_len = sizeof(void *);
    int sz = len / nullp_len;
    int ys = len % nullp_len;
    void *s = alloca(nullp_len);
    memset(s, _Val, nullp_len);
    void *d=dest;
    while (sz-- != 0) {
        lret = OSIS::ptrace_write(pid, (void *)d, (void *)s, nullp_len);
        if (lret < 0) {
            printf("Failed to ptrace_write origin_code\n");
            return -1;
        }
        d+=nullp_len;
    }
    if(ys>0)
    {
        lret = OSIS::ptrace_write(pid, (void *)d, (void *)s, ys);
        if (lret < 0) {
            printf("Failed to ptrace_write origin_code\n");
            return -1;
        }
    }
    return 0;
}
long OSIS::get_so_baseaddr(pid_t pid,char*soname,char * path ,int size,unsigned long &addr)
{
     if(path==NULL||size >PATH_MAX||soname==NULL) {
             output_debug_string(0,1,"param check invalid!soname[%p] psth(%p),size(%d) (%s:%d)\n",\
             soname,path,size, __FILE__,__LINE__);
        return -1;
    }
    char filename[256];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open maps file");
        return -1;
    }

    char line[1024];
    char *p = 0, *basename = 0;
    if ((p = strrchr(soname, '/')) != NULL)
        basename = strdup(p + 1);
    else
        basename = strdup(soname);
    while (fgets(line, sizeof(line), file)) {
        // 查找包含 libc 的行
      //  if (strstr(line, "libc.") && strstr(line, ".so")) {
            // 查找路径部分
            if (strstr(line, basename)) {
            char *libc_path = strchr(line, '/');
            if(!libc_path)
            {
                goto to_exit;
            }
            char *p=strchr(libc_path, '\n');
            if(p)
            {
                *p='\0';
            }
            printf("libc path: %s", libc_path);
            snprintf(path,size-1,"%s",libc_path);
               
            
            // 获取 libc 的起始地址
            sscanf(line, "%lx", &addr);
            printf("libc base address: 0x%lx\n", addr);
            if(basename)
            {
                free(basename);
            }
            fclose(file);
            return 0;
        }
    }
to_exit:
    printf("libc not found in the maps\n");
    fclose(file);
    if (basename) {
        free(basename);
    }
    return -1;
}
#endif