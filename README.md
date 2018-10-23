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
