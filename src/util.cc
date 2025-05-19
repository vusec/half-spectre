#include "util.h"
#include "asm.h"
#include "prlimit.h"
#include "kaslr_break.h"
#include "evict.h"
#include <sys/stat.h>

uint64_t dist(uint64_t a, uint64_t b)
{
    return a < b ? b - a : a - b;
}

int cmp_uint64_t(const void *a, const void *b) 
{
    uint64_t x = *(uint64_t *)a;
    uint64_t y = *(uint64_t *)b;
    if (x > y) return  1;
    if (x < y) return -1;
    return 0;
}

void sort(uint64_t A[], unsigned size)
{
    qsort(A, size, sizeof(uint64_t), cmp_uint64_t);
}

uint64_t median_sort(uint64_t A[], unsigned size)
{
    sort(A, size);
    return A[size/2];
}

uint64_t minimum_sort(uint64_t A[], unsigned size)
{
    sort(A, size);
    return A[0];
}

int unique_above(uint64_t A[], unsigned size, uint64_t thres)
{
    int found = 0, at = -1;
    for (unsigned i = 0; i < size; i++) {
        if (A[i] > thres) {
            if (found)
                return -1; // Not unique.
            found = 1;
            at = i;
        }
    }
    return at;
}

int occurrences_in(int A[], unsigned size, int val)
{
    int count = 0;
    for (uint i = 0; i < size; i++)
        if (A[i] == val)
            count++;
    return count;
}

int count_between(uint64_t A[], uint size, uint64_t low, uint64_t high)
{
    int count = 0;
    for (uint i = 0; i < size; i++)
        if (low <= A[i] && A[i] < high)
            count++;
    return count;
}

void set_cpu_affinity(int cpu_id) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_id, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        pr_err("Error setting CPU affinity of process with PID %d to %d: %s\n",
                getpid(), cpu_id, strerror(errno));                                                                                                                                                             
        exit(EXIT_FAILURE);
    }   
}

int get_sibling(int cpu_id)
{
        int brother, sister;
        char fname[64];
        snprintf(fname, 64, "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu_id);
        FILE *f = fopen(fname, "r");
        if (!f) {
                perror("could not open sysfs thread_siblings_list file");
                exit(EXIT_FAILURE);
        }
        assert(fscanf(f, "%d", &brother) == 1);
        fgetc(f);
        assert(fscanf(f, "%d", &sister) == 1);
        assert(fclose(f) == 0);
        if (brother == cpu_id)
                return sister;
        if (sister == cpu_id)
                return brother;
        pr_err("Could not find cpu id %d in file %s\n", cpu_id, fname);
        exit(EXIT_FAILURE);
}

uint64_t lrand(void)
{
	return ((uint64_t)rand() << 32) | rand();
}

/* Evict the Invalid Page Cache. Cf. definition of IPC_SIZE.
 */
void evict_ipc(void)
{
    for (size_t i = 0; i < EVSET_SIZE_IPC; i++) {
        uint64_t addr =  0xffffffff + (rand() & 0xffffffff);
        prefetcht0((uint8_t *)addr);
    }   
}

static uint64_t get_pfn(uint64_t entry) {
    return ((entry) & 0x3fffffffffffff);
}

uint64_t get_phys_addr(uint64_t v_addr)
{
    uint64_t entry; 
    uint64_t offset = (v_addr/4096) * sizeof(entry);
    uint64_t pfn; 
    int fd = open("/proc/self/pagemap", O_RDONLY);
    assert(fd >= 0);
    int bytes_read = pread(fd, &entry, sizeof(entry), offset);
    close(fd);
    assert(bytes_read == 8);
    assert(entry & (1ULL << 63));
    pfn = get_pfn(entry);
    assert(pfn != 0);
    return (pfn*4096) | (v_addr & 4095); 
}

uint8_t *alloc_zero_page_fixed(const void *addr, int fd)
{
    uint8_t *buf;
#ifdef SANITY
    vaddr_t v_addr; 
    v_addr.va = (uint64_t) addr;
    assert(v_addr.addr.pte_offset == TARGET_PTE_OFFSET_CACHELINE); //sanity check
#endif // SANITY
    buf = (uint8_t *) mmap((void *) addr, ALLOC_SIZE_VMA_MERGE, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_NORESERVE, fd, 0);
    if(buf == MAP_FAILED) {
        pr_err("Could not alloc new fixed zero page at addr %lx\n", (uint64_t) addr);
        perror("");
        return NULL;
    }
    madvise(buf, ALLOC_SIZE_VMA_MERGE, MADV_NOHUGEPAGE);
    return buf;
}

uint64_t mem_available(void)
{
    char *meminfo = file_read_all("/proc/meminfo");
    uint64_t avmem_kb = strtoull(meminfo+70,  NULL, 10);
    free(meminfo);
    return avmem_kb * KB;
}

char *file_read_all(const char *filename)
{
    char *buf = (char *)malloc(1023);
    int fd = open(filename, O_RDONLY); if (fd < 0) pr_info("error %s", filename); check(fd);
    int rv = read(fd, buf, 1023); check(rv);
    buf[rv] = '\0';
    int cv = close(fd); check(cv);
    return buf;
}

uint64_t file_read_lx(const char *filename)
{
    char buf[32];
    int fd = open(filename, O_RDONLY); if (fd < 0) pr_info("error %s", filename); check(fd);
    int rv = read(fd, buf, 32); check(rv);
    int cv = close(fd); check(cv);
    return strtoull(buf, NULL, 16);
}

static uint64_t file_write_lx(const char *filename, uint64_t uaddr)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%lx\n", uaddr);
    int fd = open(filename, O_WRONLY); if (fd < 0) pr_info("error %s", filename); check(fd);
    int rv = write(fd, buf, 32); check(rv);
    int cv = close(fd); check(cv);
    return 0;
}

kva_t procfs_read_gadget_base(void)
{
    return file_read_lx("/proc/preload_time/gadget_base");
}

physaddr_t procfs_get_physaddr(uint8_t *uaddr)
{
    file_write_lx("/proc/preload_time/phys_addr", (uint64_t) uaddr);
    return file_read_lx("/proc/preload_time/phys_addr");
}

kva_t procfs_get_pud(uint8_t *uaddr)
{
    file_write_lx("/proc/preload_time/pud", (uint64_t) uaddr);
    return file_read_lx("/proc/preload_time/pud");
}

kva_t procfs_get_pmd(uint8_t *uaddr)
{
    file_write_lx("/proc/preload_time/pmd", (uint64_t) uaddr);
    return file_read_lx("/proc/preload_time/pmd");
}

kva_t procfs_get_pte(uint8_t *uaddr)
{
    file_write_lx("/proc/preload_time/pte", (uint64_t) uaddr);
    return file_read_lx("/proc/preload_time/pte");
}

physaddr_t procfs_pte_pa(vaddr_t uaddr)
{
    return procfs_get_pte(uaddr.get_ptr()) - direct_map();
}

void procfs_preload_pte(uint8_t *uaddr)
{
    kva_t pte = procfs_get_pte(uaddr);
    file_write_lx("/proc/preload_time/transiently_load", pte);
}

void procfs_invlpg(uint8_t *uaddr)
{
    file_write_lx("/proc/preload_time/invlpg", (uint64_t)uaddr);
}

void procfs_clflush_pte(uint8_t *uaddr)
{
    kva_t pte = procfs_get_pte(uaddr);
    file_write_lx("/proc/preload_time/clflush", pte);
}

void procfs_sim_hammer(physaddr_t pte_pa)
{
    file_write_lx("/proc/preload_time/sim_hammer", pte_pa);
}

void dump_meminfo() {
    char buffer[256];
    FILE* fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        perror("Failed to open /proc/meminfo");
        exit(EXIT_FAILURE);
    }
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }
    fclose(fp);
}
void dump_maps()
{
    char buffer[256];
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        perror("Failed to open /proc/self/maps");
        exit(EXIT_FAILURE);
    }
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }
    fclose(fp);
}

void transiently_load(void *p)
{
	asm volatile (
            "call next\n\t"
		"arch_return:\n\t"
            "jmp quit\n\t"
        "barrier:"
			"pause\n\t"
			"jmp barrier\n\t"
        "next:\n\t"
            "call rm_ra\n\t"
        "spec_return:\n\t"
			"movq (%0), %%rax\n\t"
		"infinite_loop:\n\t"
			"pause\n\t"
			"jmp infinite_loop\n\t"
        "rm_ra:"
            "add $8, %%rsp\n\t"
			"clflush (%%rsp)\n\t"
			"xor %%rax, %%rax\n\t"
			"cpuid\n\t"
			"ret\n\t"
		"quit:\n\t"
		:
		: "r" (p)
		: "%rax", "%rbx", "%rcx", "%rdx"
	);
}

uint64_t time_empty(void)
{
	unsigned start_low, start_high, end_low, end_high;
	uint64_t start, end, duration;

	asm volatile (
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		"rdtsc\n\t"
		"mov %%edx, %0\n\t"
		"mov %%eax, %1\n\t"
		"rdtscp\n\t"
		"mov %%edx, %2\n\t"
		"mov %%eax, %3\n\t"
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		: "=&r" (start_high), "=&r" (start_low), "=r" (end_high), "=r" (end_low)
		:
		: "%rax", "%rbx", "%rcx", "%rdx"
	);

	start = ((uint64_t)start_high << 32) | (uint64_t)start_low;
	end = ((uint64_t)end_high << 32) | (uint64_t)end_low;
	duration = end - start;

    return duration;
}

uint64_t time_access(void *addr)
{
	unsigned start_low, start_high, end_low, end_high;
	uint64_t start, end, duration, overhead;

	asm volatile (
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		"rdtsc\n\t"
		"mov %%edx, %0\n\t"
		"mov %%eax, %1\n\t"
		"mov (%4), %%rcx\n\t"
		"rdtscp\n\t"
		"mov %%edx, %2\n\t"
		"mov %%eax, %3\n\t"
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		: "=&r" (start_high), "=&r" (start_low), "=r" (end_high), "=r" (end_low)
		: "r" (addr)
		: "%rax", "%rbx", "%rcx", "%rdx"
	);

	start = ((uint64_t)start_high << 32) | (uint64_t)start_low;
	end = ((uint64_t)end_high << 32) | (uint64_t)end_low;
	duration = end - start;

    overhead = time_empty();

	return overhead < duration ? duration - overhead : 0;
}

#define fail(name) exit(1)

/* (void *)mmap a readable and writable 4KB page at @addr and populate it.
 *
 * Return 0 on success, -1 on failure.
 */
int mmap_at(void *addr)
{
	void *p;
	int err;
	
	p = (void *)mmap(addr, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_POPULATE, -1, 0);
	if (p == (void *)-1) {
		pr_err("(void *)mmap: %s\n", strerror(errno));
		return -1;
	}
	if (p != addr) {
		pr_err("(void *)mmap_at: got %p instead of %p\n", p, addr);
		err = munmap(p, PAGE_SIZE);
		if (err)
			pr_err("munmap: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* Return the RSS (ie the physical memory mapped) under this virtual address
 * range.
 */
static int rss(void *base_addr)
{
	FILE *smaps;
	uint64_t base;
	char line[256];
	char addr[32];
	int rss = -1;

	smaps = fopen("/proc/self/smaps", "r");
	if (!smaps)
		fail("failed to open /proc/self/smaps");
	// Look up the correct address range.
	base = (uint64_t)base_addr;
	snprintf(addr, 32, "%lx-", base);
	while (fgets(line, 256, smaps)) {
		if (strstr(line, addr))
			break;
	}
	// Extract the RSS in KBs.
	assert(fscanf(smaps, "Size: 2048 kB KernelPageSize: 4 kB MMUPageSize: 4 kB Rss: %d kB", &rss) == 1);
	fclose(smaps);
	return rss*KB;
}

/* Allocate a hugepage worth of physical contiguous memory and (void *)mmap it into
 * the virtual address space (optionally at @addr). If @split, then split it up
 * into 4kb pages; the last page is read-only, the rest read+write.
 */
void *alloc_contiguous_pages(void *addr, int split)
{
	char *p;
	uint64_t base;

	if (!addr) {
		// Find a suitable hugepage aligned address for our eviction buffer. 
		p = (char *)mmap(NULL, 2*HUGE_PAGE_SZ, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		if (p == (void *)-1) {
			pr_err("mmap: %s\n", strerror(errno));
			fail("alloc_contiguous_pages alignment mmap failed");
		}
		if (munmap(p, 2*HUGE_PAGE_SZ) < 0) {
			pr_err("munmap: %s\n", strerror(errno));
			fail("alloc_contiguous_pages munmap failed");
		}
		base = (uint64_t)p;
		while (base % HUGE_PAGE_SZ)
			base += PAGE_SIZE;
		addr = (void *)base;
	}

	assert((uint64_t)addr % HUGE_PAGE_SZ == 0);

	// mmap the virtual memory at the chosen address.
	p = (char *)mmap(addr, HUGE_PAGE_SZ, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (p == (void *)-1) {
		pr_err("mmap: %s\n", strerror(errno));
		fail("alloc_contiguous_pages buf mmap failed");
	}
	if (p != addr)
		fail("alloc_contiguous_pages cant mmap that exact address");
	
	// Turn it into a hugepage.
	if (madvise(p, HUGE_PAGE_SZ, MADV_HUGEPAGE) < 0) {
		pr_err("madvise: %s\n", strerror(errno));
		fail("alloc_contiguous_pages madvise failed");
	}

	// Populate the hugepage, and check it is indeed huge.
	assert(rss(p) == 0);
	*p = '\0';
	assert(rss(p) == HUGE_PAGE_SZ); // hugeness check

	if (split) {
		// Split the huge page table into 512 small page tables.
		if (mprotect(p + HUGE_PAGE_SZ - PAGE_SIZE, PAGE_SIZE, PROT_READ) < 0) {
			pr_err("mprotect: %s\n", strerror(errno));
			fail("alloc_contiguous_pages mprotect failed");
		}
	}

	return p;
}

uint64_t timestamp;

uint64_t clock_read()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}


void step_start()
{
	timestamp = clock_read();
}

void step_end()
{
	float duration = (float)(clock_read() - timestamp) / 1000000000.0;
	pr_info("Step took %.4f seconds.\n", duration);
}

#define TSC_RESOLUTION 2
void print_histogram_header(unsigned int indent)
{
    constexpr unsigned int MAX_T = 70;
    for (unsigned int i = 0; i < indent; i++)
        pr_info("_");
    for (unsigned int j = 0; j < MAX_T; j += TSC_RESOLUTION)
        pr_info("_%3u", j);
    pr_info("\n");
}

void print_histogram(uint64_t *t, unsigned int n)
{
    constexpr unsigned int MAX_T = 70;

    uint64_t hist[MAX_T];
    memset(hist, 0, sizeof(hist));
    for (unsigned int i = 0; i < n; i++) {
        assert(t[i] % TSC_RESOLUTION == 0);
        if (t[i] >= MAX_T) t[i] = MAX_T - 1;
        hist[t[i]]++;
    }
    for (unsigned int j = 0; j < MAX_T; j += TSC_RESOLUTION)
        pr_info(" %3lu", hist[j]);
    pr_info("\n");
}

