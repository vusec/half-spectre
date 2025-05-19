#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/pgtable.h>
#include<linux/proc_fs.h>
#include <linux/random.h>

MODULE_AUTHOR("hammertux");
MODULE_DESCRIPTION("kernel module for PRELOAD+TIME testing");
MODULE_LICENSE("GPL");

static void *user_addr;

static size_t u64_from_user(u64 *value, const char *buf, size_t *len, loff_t *off)
{
	char kbuf[32];
	memset(kbuf, 0, 32);

	*len = min(*len, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, *len))
		return -1;
	if (sscanf(kbuf, "%llx", value) != 1)
		return -1;

	*off += *len;
	return 0;
}

static size_t u64_to_user(char __user *buf, size_t len, loff_t *off, u64 value)
{
	char kbuf[18];

	if (*off > 0)
		return 0;

	len = min(len, 18UL);
	snprintf(kbuf, len, "%16llx\n", value);
	if (copy_to_user(buf, kbuf, len))
		return -EFAULT;

	*off += len;
	return len;
}

#define ANNOTATE_INTRA_FUNCTION_CALL				\
	"999:\n\t"							\
	".pushsection .discard.intra_function_calls;\n\t"		\
	".long 999b;\n\t"						\
	".popsection;\n\t"


static void transiently_load(u64 addr)
{
	asm volatile (
			ANNOTATE_INTRA_FUNCTION_CALL
			"call overwrite_arch_return_addr\n\t"
		"spec_return:\n\t"
			"movq (%0), %%rax\n\t"
		"infinite_loop:\n\t"
			"pause\n\t"
			"jmp infinite_loop\n\t"
		"overwrite_arch_return_addr:\n\t"
			"movq $arch_return, (%%rsp)\n\t"
			"clflush (%%rsp)\n\t"
			"xor %%rax, %%rax\n\t"
			"cpuid\n\t"
			ANNOTATE_RETPOLINE_SAFE
			"ret\n\t"
		"arch_return:\n\t"
		:
		: "r" (addr)
		: "%rax", "%rbx", "%rcx", "%rdx"
	);
}

static void invlpg(u64 addr)
{
	asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

static int page_table_walk(void *addr, pgd_t **pgd, p4d_t **p4d, pud_t **pud, pmd_t **pmd, pte_t **pte)
{
	unsigned long va = (unsigned long)addr;
	*pgd = NULL;
	*p4d = NULL;
	*pud = NULL;
	*pmd = NULL;
	*pte = NULL;

	*pgd = pgd_offset(current->mm, va);
	if (pgd_none(**pgd) || pgd_bad(**pgd))
		return -1;
	//pr_info("pgd = %lx\n", pgd_val(**pgd));

	*p4d = p4d_offset(*pgd, va);
	if (p4d_none(**p4d) || p4d_bad(**p4d))
		return -1;
	//pr_info(" p4d = %lx\n", p4d_val(**p4d));

	*pud = pud_offset(*p4d, va);
	if (pud_trans_huge(**pud)) {
		pr_info("  pud = %lx (superpage)\n", pud_val(**pud));
		return 0;
	}
	if (pud_none(**pud) || pud_bad(**pud))
		return -1;
	//pr_info("  pud = %lx\n", pud_val(**pud));

	*pmd = pmd_offset(*pud, va);
	if (pmd_none(**pmd) || pmd_bad(**pmd))
		return -1;
	if (pmd_trans_huge(**pmd)) {
		pr_info("   pmd = %lx (hugepage)\n", pmd_val(**pmd));
		return 0;
	}
	//pr_info("   pmd = %lx\n", pmd_val(**pmd));

	*pte = pte_offset_kernel(*pmd, va);
	if (pte_none(**pte))
		return -1;
	//pr_info("    pte = %lx\n", pte_val(**pte));
	return 0;
}

static unsigned long phys_addr(void *addr)
{
	#define HUGEPAGE_SIZE (1ULL << 21)
	#define SUPERPAGE_SIZE (1ULL << 30)

	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
	unsigned long va = (unsigned long)addr;

	if (page_table_walk(addr, &pgd, &p4d, &pud, &pmd, &pte) < 0)
		return -1;

	if (pte)
		return pte_pfn(*pte)*PAGE_SIZE + va % PAGE_SIZE;
	if (pmd)
		return pmd_pfn(*pmd)*PAGE_SIZE + va % HUGEPAGE_SIZE;
	if (pud)
		return pud_pfn(*pud)*PAGE_SIZE + va % SUPERPAGE_SIZE;

	return -1;
}

static void sim_bitflip(u64 phys_addr)
{
	uint64_t *pte_p;
	unsigned max_bit;
	uint64_t rand_pos;
	uint64_t rand_bit_flip;

	max_bit = 22;

	rand_pos = get_random_u64() % max_bit;

	rand_bit_flip = (1 << rand_pos) << PAGE_SHIFT;

	pte_p = (uint64_t *) (page_offset_base + phys_addr);

	pr_info("About to flip bit %llu in PTE val 0x%llx\n", rand_pos + 12, *pte_p);
	*pte_p ^= rand_bit_flip;
	pr_info("New PTE val = 0x%llx\n", *pte_p);
}

static ssize_t gadget_base_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	return u64_to_user(buf, len, off, (u64)current->signal->rlim);
}

static ssize_t direct_map_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	return u64_to_user(buf, len, off, page_offset_base);
}

static ssize_t user_addr_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	u64 addr;
	if (u64_from_user(&addr, buf, &len, off))
		return -EFAULT;
	user_addr = (void *)addr;
	return len;
}

static ssize_t phys_addr_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	return u64_to_user(buf, len, off, phys_addr(user_addr));
}

static ssize_t pte_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
	if (page_table_walk(user_addr, &pgd, &p4d, &pud, &pmd, &pte) < 0)
		pte = NULL;
	return u64_to_user(buf, len, off, (u64)pte);
}

static ssize_t pmd_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
	if (page_table_walk(user_addr, &pgd, &p4d, &pud, &pmd, &pte) < 0)
		pmd = NULL;
	return u64_to_user(buf, len, off, (u64)pmd);
}

static ssize_t pud_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
	if (page_table_walk(user_addr, &pgd, &p4d, &pud, &pmd, &pte) < 0)
		pud = NULL;
	return u64_to_user(buf, len, off, (u64)pud);
}

static ssize_t clflush_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	u64 addr;
	if (u64_from_user(&addr, buf, &len, off))
		return -EFAULT;
	clflush((void *)addr);
	return len;
}

static ssize_t invlpg_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	u64 addr;
	if (u64_from_user(&addr, buf, &len, off))
		return -EFAULT;
	invlpg(addr);
	return len;
}

static ssize_t transiently_load_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	u64 addr;
	if (u64_from_user(&addr, buf, &len, off))
		return -EFAULT;
	transiently_load(addr);
	return len;
}

static ssize_t sim_hammer(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	u64 physaddr;
	if (u64_from_user(&physaddr, buf, &len, off))
		return -EFAULT;
	sim_bitflip(physaddr);
	return len;
}

static struct proc_ops gadget_base_fops = {
	.proc_read = gadget_base_read,
};
static struct proc_ops direct_map_fops = {
	.proc_read = direct_map_read,
};
static struct proc_ops phys_addr_fops = {
	.proc_write = user_addr_write,
	.proc_read = phys_addr_read,
};
static struct proc_ops pte_fops = {
	.proc_write = user_addr_write,
	.proc_read = pte_read,
};
static struct proc_ops pmd_fops = {
	.proc_write = user_addr_write,
	.proc_read = pmd_read,
};
static struct proc_ops pud_fops = {
	.proc_write = user_addr_write,
	.proc_read = pud_read,
};
static struct proc_ops clflush_fops = {
	.proc_write = clflush_write,
};
static struct proc_ops invlpg_fops = {
	.proc_write = invlpg_write,
};
static struct proc_ops transiently_load_fops = {
	.proc_write = transiently_load_write,
};
static struct proc_ops sim_hammer_fops = {
	.proc_write = sim_hammer,
};

static struct proc_dir_entry *proc_dir;

static int __init preload_time_init(void)
{
	pr_info("Initializing PRELOAD+TIME kernel module\n");
	
	proc_dir = proc_mkdir("preload_time", NULL);

	proc_create("gadget_base", 0444, proc_dir, &gadget_base_fops);
	proc_create("direct_map", 0444, proc_dir, &direct_map_fops);

	proc_create("phys_addr", 0666, proc_dir, &phys_addr_fops);
	proc_create("pte", 0666, proc_dir, &pte_fops);
	proc_create("pmd", 0666, proc_dir, &pmd_fops);
	proc_create("pud", 0666, proc_dir, &pud_fops);


	proc_create("clflush", 0222, proc_dir, &clflush_fops);
	proc_create("invlpg", 0222, proc_dir, &invlpg_fops);
	proc_create("transiently_load", 0222, proc_dir, &transiently_load_fops);
	proc_create("sim_hammer", 0222, proc_dir, &sim_hammer_fops);

	return 0;
}

static void __exit preload_time_exit(void)
{
	pr_info("Cleanup PRELOAD+TIME kernel module\n");
	proc_remove(proc_dir);
}

module_init(preload_time_init);
module_exit(preload_time_exit);
