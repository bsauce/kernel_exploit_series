/**
*	This file includes the relevant methods and objects to trigger the 
*	use after free vulnerability. The available methods to userland applications
*	allow a uaf_object with a function pointer to be allocated, a trash object
*	with 256 bytes of data to be allocated, the uaf_obj to be freed, and the uaf_obj
*	to be used.
*/

#ifndef _USE_AFTER_FREE_
	#define _USE_AFTER_FREE_

	typedef struct uaf_obj
	{
		char uaf_first_buff[56];
		long arg;
		void (*fn)(long);

		char uaf_second_buff[12];

	}uaf_obj;

	typedef struct k_object
	{
		char kobj_buff[96];
	}k_object;

	/* this is our global uaf object that will eventually be freed and used */
	uaf_obj *global_uaf_obj = NULL;

	/**
	* A simple callback function
	*/
	static void uaf_callback(long num)
	{
		printk(KERN_WARNING "[-] Hit callback [-]\n");
	}

	/**
	* Allocate a use after free object on the kernel heap.
	* This objects buffer is then filled with A's, and the 
	* global uaf pointer is set to it.
	*/
	static int alloc_uaf_obj(long __user arg)
	{
		struct uaf_obj *target;

		target = kmalloc(sizeof(uaf_obj), GFP_KERNEL);

		if(!target) {
			printk(KERN_WARNING "[-] Error no memory [-]\n");
			return -ENOMEM;
		}

		target->arg = arg;
		target->fn = uaf_callback;
		memset(target->uaf_first_buff, 0x41, sizeof(target->uaf_first_buff));

		global_uaf_obj = target;

		printk(KERN_WARNING "[x] Allocated uaf object [x]\n");

		return 0;
	}

	/**
	* Here we allow the userspace program the ability
	* to tell the kernel to free the global uaf_object.
	*/
	static void free_uaf_obj(void)
	{
		kfree(global_uaf_obj);

		//if we wanted to make this more secure, we would
		//do global_uaf_obj = NULL after freeing it.

		printk(KERN_WARNING "[x] uaf object freed [x]");
	}

	/**
	* Use the function pointer callback as long as its not null.
	*/
	static void use_uaf_obj(void)
	{
		if(global_uaf_obj->fn)
		{
			//debug info
			printk(KERN_WARNING "[x] Calling 0x%p(%lu)[x]\n", global_uaf_obj->fn, global_uaf_obj->arg);

			global_uaf_obj->fn(global_uaf_obj->arg);
		}
	}

	static int alloc_k_obj(k_object *user_kobj)
	{
		k_object *trash_object = kmalloc(sizeof(k_object), GFP_KERNEL);
		int ret;

		if(!trash_object) {
			printk(KERN_WARNING "[x] Error allocating k_object memory [-]\n");
			return -ENOMEM;
		}

		ret = copy_from_user(trash_object, user_kobj, sizeof(k_object));
		printk(KERN_WARNING "[x] Allocated k_object [x]\n");
		return 0;
	}

#endif
