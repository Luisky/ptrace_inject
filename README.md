# SEL_TP

how to use:

echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

launch: ./DECOY
then: ps -aux | grep DECOY
finally: ./SEL [pid] [func_name]

for now writing int3 (or 0xCC) causes a SIGTRAP:
- followed by a SIGSEGV if sigaction is activated (with sigaction())
- if not it produces this: "Trappe pour point d'arrêt et de trace (core dumped)"
