#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/domain.h>
#include <asm/asm-offsets.h>
#include <asm/hwcap.h>
#include <asm/pgtable-hwdef.h>
#include <asm/pgtable.h>

ENTRY(cpu_v7_proc_fin)
	mrc	p15, 0, r0, c1, c0, 0		@ ctrl register
	bic	r0, r0, #0x1000			@ ...i............
	bic	r0, r0, #0x0006			@ .............ca.
	mcr	p15, 0, r0, c1, c0, 0		@ disable caches
	mov	pc, lr
ENDPROC(cpu_v7_proc_fin)

/*
 *	cpu_v7_reset(loc)
 *
 *	Perform a soft reset of the system.  Put the CPU into the
 *	same state as it would be if it had been reset, and branch
 *	to what would be the reset vector.
 *
 *	- loc   - location to jump to for soft reset
 */
	.align	5
ENTRY(cpu_v7_reset)
	mrc     p15, 0, r1, c1, c0, 0           @ ctrl register
	bic     r1, r1, #0x0001                 @ ...............m
        mcr     p15, 0, r1, c1, c0, 0           @ Turn off MMU
        mcr     p15, 0, ip, c8, c7, 0           @ invalidate I & D,flush TLB
        mcr     p15, 0, ip, c7, c5, 6           @ flush BTC
        dsb
        isb
	mov     pc,r0
ENDPROC(cpu_v7_reset)
