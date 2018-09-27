#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

long long int get_func_addr(pid_t pid,char* proc_name, char* func_name);
long get_offset_func(char* proc_name,char* func_name);
long get_maps_addr(pid_t pid);


