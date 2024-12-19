#include <elf.h>
#include <stdio.h>
#include <stdlib.h>

#include "osis_FileMmap.h"
#include "osis_elf.h"
#include "osis_parasite.h"
#include "osis_tools.h"

struct {
    int inject_type;
    int isargs;
} opts;
struct arginfo {
    char *args[12];
    int argc;
} arginfo;
#define MAX_ARGNUM 12
#define __NR_clone 56
#define __NR_exit 60
#define __PAYLOAD_ATTRIBUTES__ __attribute__((aligned(8), __always_inline__))
#define __PAYLOAD_KEYWORDS__ static inline volatile
#define __BREAKPOINT__ __asm__ __volatile__("int3");
#define __RETURN_VALUE__(x) __asm__ __volatile__("mov %0, %%rax\n" ::"g"(x))
__PAYLOAD_KEYWORDS__ int create_thread(void (*)(void *), void *, unsigned long) __PAYLOAD_ATTRIBUTES__;

#define _PAGE_ALIGN(x) (x & ~(4096 - 1))

Elf64_Addr randomize_base(void)
{
    uint32_t v;
    uint32_t b;

    struct timeval tv;

    gettimeofday(&tv, NULL);
    srand(tv.tv_usec);

    b = rand() % 0xF;
    b <<= 24;

    gettimeofday(&tv, NULL);
    srand(tv.tv_usec);

    v = _PAGE_ALIGN(b + (rand() & 0x0000ffff));

    return (uint64_t)v;
}
int injectCode_dlopen(int pid)
{
    if (OSIS::ptrace_attach(pid) == -1) {
        printf("ptrace_attach fail pid=%d", pid);
        return -1;
    }
    return 0;
}
int main(int argc, char **argv)
{
    char **args, **pargs;
    int target_argc;
    int i;
    OSIS::Osis_Parasite parasite;
    if (argc < 3) {
        printf("Usage: %s [--b] <pid> <parasite> \n", argv[0]);
        exit(0);
    }
    opts.inject_type = 0;
    args = &argv[1];
    target_argc = argc - 2;
    if (!strcmp(argv[1], "--b")) {
        opts.inject_type = 1;
        args = &argv[2];
        target_argc = argc - 3;
    }
    arginfo.argc = target_argc;
    if (target_argc > MAX_ARGNUM) {
        OSIS::output_debug_string(0, 1, "the parasite args more than 12(%d) (%s:%d)\n", target_argc, __FILE__,
                                  __LINE__);
    }

    printf("Parasite command: ");
    for (i = 0, pargs = &args[1]; i < target_argc; i++) {
        arginfo.args[i] = strdup(pargs[i]);
        printf("%s ", arginfo.args[i]);
    }
    printf("\n");
    // parasite.tasks.pid = atoi(args[0]);
    // printf("[+] Target pid: %d\n", parasite.tasks.pid);
    pid_t pid;
    pid = atoi(args[0]);
    printf("[+] Target pid: %d\n", pid);

    printf("[+] parasite.load_parasite_file(%s)\n", args[1]);
    long lret = 0;

    // if(lret=)
    switch (opts.inject_type) {
    case 0:
        if ((lret = parasite.load_parasite_elffile(args[1])) < 0) {
            OSIS::output_debug_string(0, 1, "parasite.load_parasite_file(%s) ret(%d) (%s:%d)\n", args[1], lret,
                                      __FILE__, __LINE__);
            exit(-1);
        }
        if (lret = parasite.injectCode_dlopen_so(pid) < 0) {
            OSIS::output_debug_string(0, 1, "parasite.injectCode_dlopen(%d) ret(%d) (%s:%d)\n", pid, lret, __FILE__,
                                      __LINE__);
            exit(-1);
        }
        break;
    case 1:
        if ((lret = parasite.load_parasite_binfile(args[1])) < 0) {
            OSIS::output_debug_string(0, 1, "parasite.load_parasite_file(%s) ret(%d) (%s:%d)\n", args[1], lret,
                                      __FILE__, __LINE__);
            exit(-1);
        }
        if (lret = parasite.injectCode_dlopen_bin(pid) < 0) {
            OSIS::output_debug_string(0, 1, "parasite.injectCode_dlopen(%d) ret(%d) (%s:%d)\n", pid, lret, __FILE__,
                                      __LINE__);
            exit(-1);
        }
        break;
    default:
        break;
    }
    /*
     * Inject and execute bootstrap_code()
     */
    // run_bootstrap(&parasite);
    // int codesize=osis_get_o_c_em_size();
}