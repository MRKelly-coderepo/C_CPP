#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/semaphore.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/unistd.h>

//For the msleep/kthread stuff
#include <linux/delay.h>
#include <linux/kthread.h>

#define DRIVER_AUTHOR "Matt"
#define DRIVER_DESC   "ExecveTest"

MODULE_LICENSE("GPL");           // Get rid of taint message by declaring code as GPL.

/*  Or with defines, like this: */
MODULE_AUTHOR(DRIVER_AUTHOR);    // Who wrote this module?
MODULE_DESCRIPTION(DRIVER_DESC); // What does this module do?

int init(void);
void cleanup(void);

int set_page_rw(long unsigned long _addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(_addr, &level);
	if(pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
	return 0;
}

static int *disp_ptr;
/* Global task structure */
struct task_struct *ts;
struct task_struct *task;
struct task_struct *task_child; /* Structure needed to iterate through task children */
struct list_head *list; /* Structure needed to iterate through the list in each task->children struct */


asmlinkage long (*original_call) (void *, void *, void *);


const struct cred *cred;

int iterate_init(void) /* iterate Module */
{

		task = current;

		if(!(strcmp(task->comm,"sudo")))
		{

		 printk(KERN_INFO "AFTER: %d/%d\n",cred->uid,cred->euid);
		 printk(KERN_INFO "     PID: %d PROCESS: %s\n",task->pid, task->comm);/* log parent id/executable name/state */
		 printk(KERN_INFO "     UID: %d",cred->uid);
		 printk(KERN_INFO "    EUID: %d",cred->euid);
		 printk(KERN_INFO "--------------------------------------\n");
		}

	return 0;
}

asmlinkage long my_execve(void *arg0, void *arg1, void *arg2)
{
   char buf[128];
   if(strncpy_from_user(buf, (char *) arg0, sizeof(buf)-1) > 0)
   {
	   buf[sizeof(buf) - 1] = '\0';
	   cred = current_cred();
	   iterate_init();
//printk("execve(\"%s\", ...)\n", buf);

   }

   return original_call(arg0,arg1,arg2);
}

int init_module()
{

    disp_ptr = (int *) (0xffffffff816b8f73 +1);
    original_call = (void *)((char *) disp_ptr +4 + *disp_ptr);
//    printk("original_call: %p\n", original_call);

    set_page_rw((unsigned long) disp_ptr);

    *disp_ptr = (long)my_execve - ((long)disp_ptr +4);
//    printk("new disp: %x\n", *disp_ptr);


    return 0;
}

void cleanup_module()
{
   *disp_ptr = (long)original_call - ((long)disp_ptr +4);
}