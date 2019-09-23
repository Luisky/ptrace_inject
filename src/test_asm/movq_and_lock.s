# gcc -c movq_and_lock.s
# ld -o movq_and_lock movq_and_lock.o
.data
hello:
    .string "hello, world\n"
var:
    .long   0

.text
.globl _start

_start:
    mov $1, %rax;
    mov $1, %rdi;
    mov $hello, %rsi;
    mov $13, %rdx;
    syscall
    movq %rsp, %rax;
    lock incq (%rax);
    mov $60, %rax;
    mov $0, %rdi;
    syscall
