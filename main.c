#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <wait.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>

#include <libelf.h>


/*
 * Could use AS2_TP5 (multithreaded matrix calculations) /home/luisky/CLionProjects/L3_CDA_C/AS2_TP5
 * or a small decoy program which calls a function (maybe better at first)
 *
 */

#define BASE 10

int main(int argc, char **argv) {

    char *str, *endptr;
    long pid;
    char* func_name;
    void *addr = NULL;
    void *data = NULL;
    int wstatus;

    if (argc != 3) {
        exit(EXIT_FAILURE);
    }

    //int pid = atoi(argv[1]); // CLion told me to use strtol() insted so I did, the code below is from: man 3 strtol

    str = argv[1];
    errno = 0; // to differentiate between success and failure after strtol() has been called
    pid = strtol(str, &endptr, BASE);

    if ((errno == ERANGE && (pid == LONG_MAX || pid == LONG_MIN))
        || (errno != 0 && pid == 0)) {
        perror("strtol");
        exit(EXIT_FAILURE);
    }

    if (endptr == str) {
        fprintf(stderr, "Aucun chiffre trouvé\n");
        exit(EXIT_FAILURE);
    }

    func_name = argv[2];

    if ( ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        fprintf(stderr, "Ptrace failed\n"); //TODO: check errno
        exit(EXIT_FAILURE);
    }
    waitpid((int)pid, &wstatus, 0);

    if (WIFSTOPPED(wstatus)) printf("process was traced, stopped by signal number %d\n", WSTOPSIG(wstatus));

    int sigstop = 19; // kill -l or https://elixir.bootlin.com/linux/v4.4/source/arch/x86/include/uapi/asm/signal.h#L41 or https://elixir.bootlin.com/linux/v4.5/source/include/uapi/asm-generic/signal.h
    kill((int)pid, SIGSTOP);

    //ptrace(PTRACE_CONT, pid, 0, &sigstop);
    //ptrace(PTRACE_CONT, pid, 0, 0);

    waitpid((int)pid, &wstatus, WNOHANG); // this stops the process
    if (WIFSTOPPED(wstatus)) printf("process was traced, stopped by signal number %d\n", WSTOPSIG(wstatus));

    sleep(1);

    kill((int)pid, SIGCONT);

    printf("should be good\n");

    //libelf
    FILE *fp;
    char path_maps[256] = {0};
    char content_maps[4096]; //should be enough
    sprintf(path_maps, "/proc/%d/maps", (int)pid);

    fp = fopen(path_maps, "r");
    size_t br = fread(content_maps, 1, 4096, fp);

    fclose(fp);

    printf("%s\n", content_maps);
    printf("%ld byte(s) read\n", br);

    ////////////////////

    char path_mem[256] = {0};
    char content_mem[4096];
    sprintf(path_mem, "/proc/%d/mem", (int)pid);

    //parsing for address
    char *token;
    const char deli[2]="-";
    token = strtok(content_maps, deli);

    long offset = strtol(token, &endptr, 16);

    //process must be stopped in order to be able to read mem so:
    kill((int)pid, SIGSTOP);
    waitpid((int)pid, &wstatus, WNOHANG); // this stops the process
    if (WIFSTOPPED(wstatus)) printf("process was traced, stopped by signal number %d\n", WSTOPSIG(wstatus));

    fp = fopen(path_mem, "r");

    fseek(fp, offset, SEEK_SET);

    br = fread(content_mem, 1, 4096, fp);

    fclose(fp);

    //printf("%s\n", content_mem);

    int j = 0;
    for (int i = 0; i < 4096; ++i) {
        printf("%x", content_mem[i]);
        j++;
        if (j == 80) {
            j = 0;
            printf("\n");
        }
    } printf("\n");

    printf("%ld byte(s) read\n", br);

    kill((int)pid, SIGCONT);

    __asm__("int3"); //0xCC

    return EXIT_SUCCESS;
}