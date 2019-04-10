# A program to be called from a C program
# Declaring data that doesn't change
.section .data
    string: .ascii  "Hello from assembler\n"
    length: .quad   . - string

	a:	.ascii	"A\n"
    lenA:	.quad	. - a
    b:	.ascii	"B\n"
	lenB:	.quad	. - b


# The actual code
.section .text
.global print
.type print, @function              #<-Important

print:
    mov     $0x1,%rax               # Move 1(write) into rax
    mov     $0x1,%rdi               # Move 1(fd stdOut) into rdi.
    mov     $string,%rsi            # Move the _location_ of the string into rsi
    mov     length,%rdx             # Move the _length_ of the string into rdx
    syscall                         # Call the kernel

    mov     %rax,%rdi               # Move the number of bytes written to rdi
    mov     $0x3c,%rax              # Move 60(sys_exit) into rax
    syscall                         # Call the kernel


.global writeA
.type writeA, @function

writeA:
	mov	    $0x1, %rax
	mov	    $0x1, %rdi
	mov	    $a, %rsi
	mov	    $2, %rdx
	syscall

    ret


.global writeB
.type writeB, @function

writeB:
	mov	    $0x1, %rax
	mov	    $0x1, %rdi
	mov	    $b, %rsi
	mov	    $2, %rdx
	syscall

    ret


.global exitSuccess
.type exitSuccess, @function

exitSuccess:
    mov     $60, %rax
    mov     $0x0, %rdi
    syscall


.global waitPid
.type waitPid, @function

waitPid:
    mov     $247, %rax
    syscall

    ret
