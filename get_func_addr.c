
#include "get_func_addr.h"

long get_maps_addr(pid_t pid)
{
	char proc[]="/proc/";
	char maps[]="/maps";
	char pid_c[6];
	char tab [56];
	char buf[12];
	strcpy(tab,proc);
	sprintf(pid_c,"%d",pid);
	strcat(tab,pid_c);
	strcat(tab,maps);


	int fd = open(tab,O_RDONLY);
	if(fd<0){
		printf("error on open aborting\n");
		return -1;
	}
	read(fd,buf,12);
	printf("addr in vm 0x%s\n",buf);
	return strtoll(buf,NULL,16);

}

long get_offset_func(char* proc_name,char* func_name)
{
	FILE* r;
	char cmd[] = "/usr/bin/objdump -d ";
	char grep[]=" | grep ";
	char cut[] =" | cut -f 1 -d \" \""; 
	char exec[128];
	char read[17];
	strcpy(exec,cmd);
	strcat(exec,proc_name);
	strcat(exec,grep);
	strcat(exec,func_name);
	strcat(exec,cut);
	r = popen(exec,"r");
	if(r == NULL){
		printf("error on popen\n");
		return -1;
	}
	fread(read,sizeof(char),16,r);
	printf("offset of the function %s 0x%s\n",func_name,read);
	return strtol(read,NULL,16);
}

char* get_proc_name(pid_t pid)
{
	int fd;
	char pid_c[6];
	char cmd [26];
	static char proc_name[128];
	sprintf(pid_c,"%d",pid);
	strcpy(cmd,"/proc/");
	strcat(cmd,pid_c);
	strcat(cmd,"/cmdline");

	fd = open(cmd,O_RDONLY);
	read(fd,proc_name,128);
	memcpy(proc_name,proc_name+2,strlen(proc_name));
	return proc_name;


}

long long int get_func_addr(pid_t pid, char* func_name)
{
	return get_maps_addr(pid) + get_offset_func(get_proc_name(pid),func_name);
}
