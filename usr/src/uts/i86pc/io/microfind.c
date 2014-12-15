/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2014 Joyent, Inc.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/dl.h>
#include <sys/param.h>
#include <sys/pit.h>
#include <sys/inline.h>
#include <sys/machlock.h>
#include <sys/avintr.h>
#include <sys/smp_impldefs.h>
#include <sys/archsystm.h>
#include <sys/systm.h>
#include <sys/machsystm.h>
#include <sys/x86_archext.h>

/*
 * Loop count for 10 microsecond wait.  MUST be initialized for those who
 * insist on calling "tenmicrosec" before the clock has been initialized.
 */
unsigned int microdata = 50;

static void
microfind_pit_reprogram_for_bios(void)
{
	/*
	 * Restore PIT counter 0 for BIOS use in mode 3 -- "Square Wave
	 * Generator".
	 */
	outb(PITCTL_PORT, PIT_C0 | PIT_LOADMODE | PIT_SQUAREMODE);

	/*
	 * Load an initial counter value of zero.
	 */
	outb(PITCTR0_PORT, 0);
	outb(PITCTR0_PORT, 0);
}

/*
 * Measure the run time of tenmicrosec() using the Intel 8254 Programmable
 * Interval Timer.  The timer operates at 1.193182 Mhz, so each timer tick
 * represents 0.8381 microseconds of wall time.  This function returns the
 * number of such ticks that passed while tenmicrosec() was running, or
 * -1 if the delay was too long to measure with the PIT.
 */
static int
microfind_pit_delta(void)
{
	unsigned char status;
	int count;

	/*
	 * Configure PIT counter 0 in mode 0 -- "Interrupt On Terminal Count".
	 * In this mode, the PIT will count down from the loaded value and
	 * set its output bit high once it reaches zero.  The PIT will pause
	 * until we write the low byte and then the high byte to the counter
	 * port.
	 */
	outb(PITCTL_PORT, PIT_LOADMODE);

	/*
	 * Load the maximum counter value, 0xffff, into the counter port.
	 */
	outb(PITCTR0_PORT, 0xff);
	outb(PITCTR0_PORT, 0xff);

	/*
	 * Run the delay function.
	 */
	tenmicrosec();

	/*
	 * Latch the counter value and status for counter 0 with the read
	 * back command.
	 */
	outb(PITCTL_PORT, PIT_READBACK | PIT_READBACKC0);

	/*
	 * In read back mode, three values are read from the counter port
	 * in order: the status byte, followed by the low byte and high
	 * byte of the counter value.
	 */
	status = inb(PITCTR0_PORT);
	count = inb(PITCTR0_PORT);
	count |= inb(PITCTR0_PORT) << 8;

	/*
	 * Verify that the counter started counting down.  The null count
	 * flag in the status byte is set when we load a value, and cleared
	 * when counting operation begins.
	 */
	if (status & (1 << PITSTAT_NULLCNT)) {
		/*
		 * The counter did not begin.  This means the loop count
		 * used by tenmicrosec is too small for this CPU.  We return
		 * a zero count to represent that the delay was too small
		 * to measure.
		 */
		return (0);
	}

	/*
	 * Verify that the counter did not wrap around.  The output pin is
	 * reset when we load a new counter value, and set once the counter
	 * reaches zero.
	 */
	if (status & (1 << PITSTAT_OUTPUT)) {
		/*
		 * The counter reached zero before we were able to read the
		 * value.  This means the loop count used by tenmicrosec is too
		 * large for this CPU.
		 */
		return (-1);
	}

	/*
	 * The PIT counts from our initial load value of 0xffff down to zero.
	 * Return the number of timer ticks that passed while tenmicrosec was
	 * running.
	 */
	VERIFY(count <= 0xffff);
	return (0xffff - count);
}

static int
microfind_pit_delta_avg(int trials, int allowed_failures)
{
	int tc = 0;
	int failures = 0;
	long long int total = 0;

	while (tc < trials) {
		int d;

		if ((d = microfind_pit_delta()) < 0) {
			/*
			 * If the counter wrapped, we cannot use this
			 * data point in the average.  Record the failure
			 * and try again.
			 */
			if (++failures > allowed_failures) {
				/*
				 * Too many failures.
				 */
				return (-1);
			}
			continue;
		}

		total += d;
		tc++;

		tenmicrosec();
	}

	return (total / tc);
}

void
microfind(void)
{
	int ticks = -1;
	ulong_t s;

	/*
	 * Disable interrupts while we measure the speed of the CPU.
	 */
	s = clear_int_flag();

	/*
	 * Start at the smallest loop count, i.e. 1, and keep doubling
	 * until a delay of ~10ms can be measured.
	 */
	microdata = 1;
	for (;;) {
		int ticksprev = ticks;

		/*
		 * We use a trial count of 15 to attempt to smooth out jitter
		 * caused by the scheduling of virtual machines.  We only allow
		 * three failures, as each failure represents a wrapped counter
		 * and an expired wall time of at least ~55ms.
		 */
		if ((ticks = microfind_pit_delta_avg(15, 3)) < 0) {
			/*
			 * The counter wrapped.  Half the counter, restore the
			 * previous ticks count and break out of the loop.
			 */
			VERIFY(microdata > 1);
			microdata = microdata >> 1;
			ticks = ticksprev;
			break;
		}

		if (ticks > 0x3000) {
			/*
			 * The counter has passed ~10ms.
			 */
			break;
		} else if (microdata > (INT_MAX >> 1)) {
			/*
			 * Doubling again would cause an overflow.  Use
			 * what we have.
			 */
			break;
		} else {
			/*
			 * Double and try again.
			 */
			microdata = microdata << 1;
		}
	}

	/*
	 * If the counter always wrapped then we have some serious problems.
	 */
	if (ticks < 0) {
		panic("microfind: pit counter always wrapped");
	}

	/*
	 * Calculate the loop cound based on the final PIT tick count and the
	 * loop count.  Each PIT tick represents a duration of ~0.8381us, so we
	 * want to adjust microdata to represent a duration of 12 ticks, or
	 * ~10us.
	 */
	microdata = (long long)microdata * 12LL / (long long)ticks;

	/*
	 * Try and leave things as we found them.
	 */
	microfind_pit_reprogram_for_bios();

	/*
	 * Restore previous interrupt state.
	 */
	restore_int_flag(s);
}
