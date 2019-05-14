# SEL_TP

how to use:

echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

launch: ./DECOY_C4 or ./DECOY_C5
then: ./C4 DECOY_C4 add_int
or:   ./C5 DECOY_C5 increment

This program cannot be used on stripped executable, without the symbol table other mechanisms
have to be used (knowing the code of the function to be replaced we could pattern matching).

Doc on ELF:
https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
this command allows to see the file header (and the rest obviously): hexdump -C executable
Doc on libelf:
ftp://ftp2.uk.freebsd.org/sites/downloads.sourceforge.net/e/el/elftoolchain/Documentation/libelf-by-example/20120308/libelf-by-example.pdf
compile with the -lelf flag / cmake: add_executable(TARGET files) and target_link_libraries(TARGET elf)


-considering using aligned_alloc() instead of posix_memalign() because of the compatibility with C11 standard, CMake doesn't support C17/C18 as of now.
-there are no symbols named aligned_alloc() in libc the function used is __libc_memalign, aligned_alloc() is a weak alias in sources.

(this repository host gnu-libc implementation)
in https://github.com/lattera/glibc/blob/master/malloc/malloc.c line 3313
/* For ISO C11.  */
weak_alias (__libc_memalign, aligned_alloc)
libc_hidden_def (__libc_memalign)

the whole thing above about weak_alias is irrelevant if objdump is used with -T option (and now objdump is irrelevant too see at the end of this file)

callq:
e8 xx xx xx xx -> need to be converted (INT32 - Little Endian (DCBA)) : https://www.scadacore.com/tools/programming-calculators/online-hex-converter/
after that take the line number in objdump after the callq instruction plus the converted number (it's always a negative number that points to .plt section)

https://stackoverflow.com/questions/46752964/what-is-callq-instruction
https://stackoverflow.com/questions/5469274/what-does-plt-mean-here

to fix the callq problem when copying code from an executable to a process memory we have to disassemble it
then figure out what function it is calling in its .plt section, find the same in the target process

https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html

using qemu-kvm to test with 18.04 server
on the host those 2 commands can be used to get the ip address of the VM (for SSH, don't forget to install openssh-server on the VM)
sudo virsh list
sudo virsh domifaddr [number_from_the_first_command]

https://en.wikipedia.org/wiki/X86_instruction_listings
LOCK is 0xF0

22:26 Saturday 24th, November 2018 : Ok, en essayant de libérer la memoire dans le tas avec un appel a free() je me suis rendu compte
que cela ne faisait ... rien ! je me suis demandé si cela ne venait pas de mprotect, puis je suis tombé sur un thread SO disant que mmap
permettait de faire la meme chose que aligned_alloc/posix_memalign et mprotect, puis je me suis dit, tient au lieu de parser la sortie
de objdump pourquoi pas directement faire un appel systeme, quitte a écrire de l'assembleur autant directement parler avec le noyau !
du coup au boulot, je vais essayer d'appeler mmap en utilisant l'instruction syscall/0x0F 0x05 (https://www.felixcloutier.com/x86/SYSCALL.html)
au lieu d'utiliser 0xFF 0xD0. Et liberer la memoire avec unmap !

syscalls list : https://filippo.io/linux-syscall-table/

23:24 Saturday 24th, November 2018: (Luis) Testé et validé, ça fonctionne, mmap et munmap ont les effets désirés, le code est du coup plus court.
en théorie il devrait etre plus rapide puisqu'il y a un seul appel systeme au lieu de 2 appels de fonctions.

utilisation de nm et nm -D a la place d'objdump
movq -> q pour quadword (word = 16 bit, 16 * 4 = 64) 
