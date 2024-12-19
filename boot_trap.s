.section .data
.section .text
.type osis_osisasm_create_exemem_align,@function
.globl osis_osisasm_create_exemem_align 
osis_osisasm_create_exemem_align:
/*
%rdi= code seg code segment size 
%rsi=executable segment size
%rdx= stack segmeng size
%rcx=
%r8
%r9

*/
/*
 * Create a code segment  to sloading code.
 */
push %rbp
mov %rsp,%rbp
sub $0x60,%rsp
mov %rdi,-0x08(%rbp)
mov %rsi,-0x10(%rbp)
mov %rdx,-0x18(%rbp)
mov %rcx,-0x50(%rbp)
mov %r8,-0x58(%rbp)
mov %r9,-0x60(%rbp)

mov %rdi,%rax
and $0xfffffffffffff000,%rax #_PAGE_ALIGN(x) (x & ~(4096 - 1)) 低12位清0
lea 0x1000(%rax),%rsi   # + 4096
mov %rsi,-0x38(%rbp)
xor %rdi,%rdi #0
mov $0x07,%rdx   #PROT_READ|PROT_WRITE|PROT_EXEC
mov $0x22,%r10  #MAP_ANONYMOUS|MAP_PRIVATE
movq $0xffffffffffffffff,%r8 #-1
xor  %r9,%r9  #0
mov $0x09,%rax
syscall
mov %rax,-0x20(%rbp)
#lea .L4-osisasm_create_exemem_align,%rdi

/*
    * Create executable segment for ephemeral storage
    * of code for custom procedure calls done through
    * ptrace. These include syscalls ()
    * and other simple functions that we want to execute
    * within the remote process.
*/
xor %rdi,%rdi
mov -0x10(%rbp),%rsi
mov %rsi,%rax
and $0xfffffffffffff000,%rax #_PAGE_ALIGN(x) (x & ~(4096 - 1)) 低12位清0
lea 0x1000(%rax),%rsi   # + 4096
mov %rsi,-0x40(%rbp)
mov $0x07,%rdx   #PROT_READ|PROT_WRITE|PROT_EXEC
mov $0x22,%r10  #MAP_ANONYMOUS|MAP_PRIVATE
movq $0xffffffffffffffff,%r8 #-1
xor  %r9,%r9  #0
mov $0x09,%rax
syscall
mov %rax,-0x28(%rbp)

/*
	 * Create stack segment that will be used by the parasite
	 * thread.
 */
xor %rdi,%rdi
mov -0x18(%rbp),%rsi
mov %rsi,%rax
and $0xfffffffffffff000,%rax #_PAGE_ALIGN(x) (x & ~(4096 - 1)) 低12位清0
lea 0x1000(%rax),%rsi   # + 4096
mov %rsi,-0x48(%rbp)
mov $0x03,%rdx   #PROT_READ|PROT_WRITE
mov $0x122,%r10  #MAP_ANONYMOUS|MAP_PRIVATE|MAP_GROWSDOWN
movq $0xffffffffffffffff,%r8 #-1
xor  %r9,%r9  #0
mov $0x09,%rax
syscall
mov %rax,-0x30(%rbp)



#################test

movq $1,%rax
movq $1,%rdi
#movq $output2,%rsi
lea output2(%rip), %rsi
movq  $len2,%rdx
syscall
####################
mov -0x20(%rbp),%rdi
mov -0x28(%rbp),%rsi
mov -0x30(%rbp),%rdx
mov -0x38(%rbp),%r10
mov -0x40(%rbp),%r8
mov -0x48(%rbp),%r9


movq -0x50(%rbp),%r11
test %r11,%r11
je .s1
movq %rdi,(%r11)
.s1:
movq -0x58(%rbp),%r11
test %r11,%r11
je .s2
movq %rsi,(%r11)
.s2:
movq -0x60(%rbp),%r11
test %r11,%r11
je .s3
movq %rdx,(%r11)
.s3:

int3
mov %rbp,%rsp
pop %rbp
ret
output2:.ascii "This is a test message by osisasm_create_exemem_align.\n"
output2_end:
.equ len2,output2_end-output2
.align 16
.L4:
.type osis_get_o_c_em_a_size,@function
.globl osis_get_o_c_em_a_size
osis_get_o_c_em_a_size:
push %rbp
mov %rsp,%rbp
lea .L4-osis_osisasm_create_exemem_align,%rax
mov %rbp,%rsp
pop %rbp
ret
.align 16

