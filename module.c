/*
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <asm/unistd.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kmsg_dump.h>
#include <linux/reboot.h>

int panic_on_oops = 1;

void kmsg_dump(enum kmsg_dump_reason reason)
{
	void (*real_kmsg_dump)(char reason);

	real_kmsg_dump = (void*)kallsyms_lookup_name("kmsg_dump");
	if (!real_kmsg_dump) {
		printk(KERN_ERR "Could not find kmsg_dump\n");
		return;
	}

	real_kmsg_dump(reason);
}

void machine_shutdown(void)
{
	void (*real_machine_shutdown)(void);

	real_machine_shutdown = (void*)kallsyms_lookup_name("machine_shutdown");
	if (!real_machine_shutdown) {
		printk(KERN_ERR "Could not find machine_shutdown\n");
		return;
	}

	real_machine_shutdown();
}

/*
 * In order to soft-boot, we need to insert a 1:1 mapping in place of
 * the user-mode pages.  This will then ensure that we have predictable
 * results when turning the mmu off
 */
void setup_mm_for_reboot(char mode)
{
	void (*real_setup_mm_for_reboot)(char mode);

	real_setup_mm_for_reboot = (void*)kallsyms_lookup_name("setup_mm_for_reboot");
	if (!real_setup_mm_for_reboot) {
		printk(KERN_ERR "Could not find setup_mm_for_reboot\n");
		return;
	}

	real_setup_mm_for_reboot(mode);
}

void kernel_restart_prepare(char *cmd)
{
	void (*real_kernel_restart_prepare)(char *cmd);

	real_kernel_restart_prepare = (void*)kallsyms_lookup_name("kernel_restart_prepare");
	if (!real_kernel_restart_prepare) {
		printk(KERN_ERR "Could not find kernel_restart_prepare\n");
		return;
	}
	real_kernel_restart_prepare(cmd);
}

static DEFINE_MUTEX(reboot_mutex);
asmlinkage long (*real_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);

static asmlinkage long
_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	int ret = 0;

	/* We only trust the superuser with rebooting the system. */
	if (!capable(CAP_SYS_BOOT))
		return -EPERM;

	/* For safety, we require "magic" arguments. */
	if (magic1 != LINUX_REBOOT_MAGIC1 ||
	    (magic2 != LINUX_REBOOT_MAGIC2 &&
	                magic2 != LINUX_REBOOT_MAGIC2A &&
			magic2 != LINUX_REBOOT_MAGIC2B &&
	                magic2 != LINUX_REBOOT_MAGIC2C))
		return -EINVAL;

	mutex_lock(&reboot_mutex);
	if (cmd == LINUX_REBOOT_CMD_KEXEC) {
		ret = kernel_kexec();
	} else {
		ret = real_reboot(magic1, magic2, cmd, arg);
	}
	mutex_unlock(&reboot_mutex);

	return ret;
}

static void **sys_call_table;

static int setup(void)
{
	sys_call_table = (void**)kallsyms_lookup_name("sys_call_table");
	if (!sys_call_table) {
		printk(KERN_ERR "Could not find sys_call_table\n");
		return -1;
	}

	sys_call_table[__NR_kexec_load] = sys_kexec_load;

	real_reboot = sys_call_table[__NR_reboot];
	sys_call_table[__NR_reboot] = _reboot;

	printk(KERN_INFO "kexec module loaded.\n");

	return 0;
}

static int __init kexec_module_init(void)
{
	return setup();
}

static void __exit kexec_module_exit(void)
{
	if (sys_call_table && real_reboot) {
		sys_call_table[__NR_reboot] = real_reboot;
	}
}

module_init(kexec_module_init);
module_exit(kexec_module_exit);
MODULE_AUTHOR("Hiroyuki Ikezoe");
MODULE_DESCRIPTION("KEXEC module");
MODULE_LICENSE("GPL v2");
