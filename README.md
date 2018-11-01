# SEL_TP

how to use:

echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

launch: ./DECOY
then: ps -aux | grep DECOY
finally: ./SEL [pid] [func_name]

for now writing int3 (or 0xCC) causes a SIGTRAP:
- followed by a SIGSEGV if sigaction is activated (with sigaction())
- if not it produces this: "Trappe pour point d'arrêt et de trace (core dumped)"

Doc on ELF:
https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
this command allows to see the file header (and the rest obviously): hexdump -C executable
Doc on libelf:
ftp://ftp2.uk.freebsd.org/sites/downloads.sourceforge.net/e/el/elftoolchain/Documentation/libelf-by-example/20120308/libelf-by-example.pdf
compile with the -lelf flag / cmake: add_executable(TARGET files) and target_link_libraries(TARGET elf)


-considering using aligned_alloc() instead of posix_memalign() because of the compatibility with C11 standard, CMake doesn't support C17/C18 as of now.
-there is no symbol named aligned_alloc() in libc the function used is __libc_memalign, aligned_alloc() is a weak alias in sources.
-with that in mind I'll try both

(this repo host gnu-libc implementation)
in https://github.com/lattera/glibc/blob/master/malloc/malloc.c line 3313
/* For ISO C11.  */
weak_alias (__libc_memalign, aligned_alloc)
libc_hidden_def (__libc_memalign)

the whole thing above about weak_alias is irrelevant if objdump is used with -T option

another thing to consider is that objdump with -d will give byte address in file (we checked it against hexdump on the same file)
which means that we can basically copy a chunk of the executable file of our tracing program and copy it inside the traced process
memory !


callq:
e8 xx xx xx xx -> need to be converted (INT32 - Little Endian (DCBA)) : https://www.scadacore.com/tools/programming-calculators/online-hex-converter/
after that take the line number in objdump after the callq instruction plus the converted number (it's always a negative number that points to .plt section)

https://stackoverflow.com/questions/46752964/what-is-callq-instruction
https://stackoverflow.com/questions/5469274/what-does-plt-mean-here

to fix the callq problem when copying code from an executable to a process memory we have to disassemble it
then figure out what function it is calling in its .plt section, find the same in the target process

https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html