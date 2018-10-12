#include "hotpatchor.h"


pid_t get_pid_from_argv(char *argv_pid)
{
    pid_t pid;
    char *endptr;
    errno = 0; // to differentiate between success and failure after strtol() has been called

    pid = (pid_t)strtol(argv_pid, &endptr, BASE_10);

    if ( (errno == ERANGE && ((long)pid == LONG_MAX || (long)pid == LONG_MIN)) || (errno != 0 && pid == 0) ) {
        perror("strtol");
        exit(EXIT_FAILURE);
    }

    if (endptr == argv_pid) {
        fprintf(stderr, "Aucun chiffre trouvé\n");
        exit(EXIT_FAILURE);
    }

    return pid;
}

void init_hotpatchor(pid_t pid, char *func_name, char *path_mem, long long int *func_addr)
{
    sprintf(path_mem, "/proc/%d/mem", (int)pid);
    *func_addr = get_func_addr((int)pid, func_name);

    return;
}

void init_ptrace_attach(pid_t pid)
{
    int wstatus;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        fprintf(stderr, "Ptrace failed\n"); //TODO: check errno
        exit(EXIT_FAILURE);
    }

    waitpid((int)pid, &wstatus, 0); // first wait beceause PTRACE_ATTACH sends SIGSTOP, if this works
    if (WIFSTOPPED(wstatus)) printf("process was traced, stopped by signal number %d\n", WSTOPSIG(wstatus));

    return;
}

void write_trap_at_addr(pid_t pid, char *path_mem, long long int func_addr, char *char_read_in_mem)
{
    FILE *fp;
    int wstatus;
    size_t br;
    uint8_t int3 = (char)0xCC;

    //process must be stopped in order to be able to read mem so:
    kill((int)pid, SIGSTOP); // we send another SIGSTOP to be able to write in /proc/[pid]/mem

    waitpid((int)pid, &wstatus, WNOHANG); // this time we don't hang otherwise both process will stop forever
    if (WIFSTOPPED(wstatus)) printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));

    fp = fopen(path_mem, "r+");
    fseek(fp, func_addr, SEEK_SET);

    fread(char_read_in_mem, 1, 1, fp);
    fseek(fp, func_addr, SEEK_SET);

    br = fwrite(&int3, 1, 1, fp);
    if (br == 0) perror("fwrite");
    fclose(fp); // this seals the deal and should send SIGTRAP after we send SIGCONT
    printf("%ld byte(s) written at address %llx\n", br, func_addr);

    //kill((int)pid, SIGCONT);
    ptrace(PTRACE_CONT, pid, 0, 0);

    waitpid((int)pid, &wstatus, 0); // this stops the process
    if (WIFSTOPPED(wstatus)) printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));

    return;
}

void get_regs(pid_t pid, struct user_regs_struct * user_regs, long long int func_addr, unsigned long long int *opti_func_addr, char * path_mem, char* char_read_in_mem)
{
    FILE *fp;
    int wstatus;
    size_t br;
    uint8_t buf[3] = { (char)0xFF, (char)0xD0, (char)0xCC};
    uint8_t buf_r[3];

    waitpid((int)pid, &wstatus, WNOHANG); // this stops the process
    if (WIFSTOPPED(wstatus)) printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));

    ptrace(PTRACE_GETREGS, pid, NULL, user_regs);
    printf("REGS:\n rax: 0x%llx\n rip: 0x%llx \n\n", user_regs->rax, user_regs->rip);

    // this is necessary for restoring the original state of the process
    unsigned long long int old_rax = user_regs->rax;
    unsigned long long int old_rdi = user_regs->rdi;
    unsigned long long int old_rsi = user_regs->rsi;

    user_regs->rax = *opti_func_addr;
    user_regs->rsi = 0;
    user_regs->rdi = 1;


    printf("REGS:\n rax: 0x%llx\n rip: 0x%llx \n\n", user_regs->rax, user_regs->rip);
    ptrace(PTRACE_SETREGS, pid, NULL, user_regs);

    fp = fopen(path_mem, "r+");
    fseek(fp, user_regs->rip, SEEK_SET); // SUPER IMPORTANT

    fread(buf_r, 1, 3, fp);

    fseek(fp, user_regs->rip, SEEK_SET);

    br = fwrite(buf, 1, 3, fp);
    if (br == 0) perror("fwrite");
    fclose(fp);
    printf("%ld byte(s) written at address %llx\n", br, user_regs->rip);


    //kill((int)pid, SIGCONT);
    ptrace(PTRACE_CONT, pid, 0, 0);

    waitpid((int)pid, &wstatus, 0); // this stops the process
    if (WIFSTOPPED(wstatus)) printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));

    waitpid((int)pid, &wstatus, WNOHANG); // this stops the process
    if (WIFSTOPPED(wstatus)) printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));

    printf("SECOND TRAP\n"); //TODO: continue from here

    // restoring everything RIGHT HERE RIGHT NOW !
    user_regs->rax = old_rax;
    user_regs->rdi = old_rdi;
    user_regs->rsi = old_rsi;
    ptrace(PTRACE_SETREGS, pid, NULL, user_regs);

    fp = fopen(path_mem, "r+");

    fseek(fp, func_addr, SEEK_SET);
    br = fwrite(char_read_in_mem, 1, 1, fp);
    printf("%ld byte(s) written\n", br);
    printf("char: %x \n", *char_read_in_mem);

    fseek(fp, user_regs->rip, SEEK_SET);
    br = fwrite(buf_r, 1, 3, fp);
    printf("%ld byte(s) written\n", br);
    printf("char: %x %x %x\n", buf_r[0], buf_r[1], buf_r[2]);


    fclose(fp);

    //kill((int)pid, SIGCONT);
    ptrace(PTRACE_CONT, pid, 0, 0);

    waitpid((int)pid, &wstatus, WNOHANG); // this stops the process
    if (WIFSTOPPED(wstatus)) printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));

    return;
}

long get_maps_addr(pid_t pid)
{
    char path_maps[64];
    char buf[12];
    long addr;

	sprintf(path_maps,"/proc/%d/maps", (int)pid);

	int fd = open(path_maps,O_RDONLY);
	if ( fd < 0 ) {
	    perror("open");
		return -1;
	}

	read(fd,buf,12);
	close(fd);

    addr = strtoll(buf,NULL,16);
	printf("addr in vm 0x%llx\n", (long long unsigned int)addr);

	return addr;
}

long get_offset_func(char* proc_name,char* func_name)
{
	FILE* fp;
	char exec[128];
    char read_val[17];
    long offset;

	sprintf(exec, "/usr/bin/objdump -d %s | grep %s | cut -f 1 -d \" \"", proc_name, func_name);

	fp = popen(exec,"r");

	if ( fp == NULL ) {
	    perror("popen");
		return -1;
	}

	fread(read_val, sizeof(char), 16, fp);
	fclose(fp);

    offset = strtol(read_val, NULL, 16);
	printf("offset of the function %s 0x%llx\n", func_name, (long long unsigned int)offset);

	return offset;
}

char* get_proc_name(pid_t pid)
{
	int fd;
	char cmd [26];
	static char proc_name[128];

	sprintf(cmd, "/proc/%d/cmdline", pid);

	fd = open(cmd, O_RDONLY);
	read(fd, proc_name, 128);
	close(fd);
	memcpy(proc_name, proc_name+2, strlen(proc_name));

	return proc_name;
}

long long int get_func_addr(pid_t pid, char* func_name)
{
	return get_maps_addr(pid) + get_offset_func(get_proc_name(pid),func_name);
}