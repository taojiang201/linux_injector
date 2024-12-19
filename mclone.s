#include <sysdep.h>
#define _ERRNO_H	1
#include <bits/errno.h>
#include <asm-syntax.h>
#include <bp-sym.h>
#include <bp-asm.h>
.section .data
msg1:.asciz "This is clone msg\n"
msg1_end: .equ msg1_len,msg1_end-msg1
.equ EINVAL, 22
.equ CLONE,0x38 #56
.section .text
.type  osis_asm_clone_,@function
.globl osis_asm_clone_
osis_asm_clone_:
/* The userland implementation is:
   int clone (int (*fn)(void *arg), void *child_stack, int flags, void *arg),
   the kernel entry is:
   int clone (long flags, void *child_stack).

   The parameters are passed in register from userland:
   rdi: fn
   rsi: child_stack
   rdx:	flags
   rcx: arg

   The kernel expects:
   rax: system call number
   rdi: flags
   rsi: child_stack 
 */

   /* 首先检查传入的函数指针 (fn) 和子线程栈指针 (child_stack) 是否为 NULL。
	  如果为空，设置 errno 为 -EINVAL 并跳转到 SYSCALL_ERROR_LABEL 错误处理标签。
   	*/
   movq    $EINVAL, %rax
   testq   %rdi, %rdi          # 检查函数指针是否为 NULL
   jz      SYSCALL_ERROR_LABEL
   testq   %rsi, %rsi          # 检查子线程栈指针是否为 NULL
   jz      SYSCALL_ERROR_LABEL
   

   subq    $16, %rsi           # 调整栈指针，腾出空间
   movq    %rcx, 8(%rsi)       # 将 arg 放到新的栈空间中
   movq    %rdi, 0(%rsi)       # 将 fn 地址存到栈中
   

   movq    %rdx, %rdi          # 将 flags 移动到 rdi 中
   movq    $CLONE, %rax # 设置系统调用号
   syscall                      # 调用系统调用
   testq   %rax, %rax
   jl      SYSCALL_ERROR_LABEL # 如果小于 0，说明出错，跳转到错误处理
   jz      thread_start        # 如果结果为 0，跳转到子线程代码
	

    SYSCALL_ERROR_LABEL:
    int3
	  ret
   parent:
   int3
    ret

   thread_start:
    popq    %rax            # 弹出函数指针
    popq    %rdi            # 弹出函数参数
    call    *%rax           # 调用函数

  movq    %rax, %rdi      # 函数返回值传递给 exit
	movq %rax, %rdi       # 将返回值作为参数传递给 sys_exit
	movq $60, %rax        # 系统调用号 60 是 sys_exit
	syscall               # 执行系统调用退出当前线程

.align 16
.L4:
.type osis_get_o_a_c_size,@function
.globl osis_get_o_a_c_size
osis_get_o_a_c_size:
push %rbp
mov %rsp,%rbp
lea .L4-osis_asm_clone_,%rax
mov %rbp,%rsp
pop %rbp
ret
.align 16


