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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2015 Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/fstyp.h>
#include <sys/fsid.h>
#include <sys/systm.h>
#include <sys/auxv.h>
#include <sys/frame.h>
#include <zone.h>
#include <sys/brand.h>
#include <sys/epoll.h>
#include <sys/stack.h>

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <synch.h>
#include <libelf.h>
#include <libgen.h>
#include <pthread.h>
#include <utime.h>
#include <dirent.h>
#include <ucontext.h>
#include <libintl.h>
#include <locale.h>

#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_brand.h>
#include <sys/lx_types.h>
#include <sys/lx_stat.h>
#include <sys/lx_statfs.h>
#include <sys/lx_signal.h>
#include <sys/lx_syscall.h>
#include <sys/lx_thread.h>
#include <sys/lx_thunk_server.h>
#include <sys/lx_aio.h>

/*
 * There is a block comment in "uts/common/brand/lx/os/lx_brand.c" that
 * describes the functioning of the LX brand in some detail.
 *
 * *** Setting errno
 *
 * This emulation library is loaded onto a seperate link map from the
 * application whose address space we're running in. The Linux libc errno is
 * independent of our native libc errno. To pass back an error the emulation
 * function should return -errno back to the Linux caller.
 */

/*
 * Map Illumos errno to the Linux equivalent.
 */
static int stol_errno[] = LX_STOL_ERRNO_INIT;

char lx_release[LX_VERS_MAX];
char lx_cmd_name[MAXNAMLEN];

/*
 * Map a linux locale ending string to the solaris equivalent.
 */
struct lx_locale_ending {
	const char	*linux_end;	/* linux ending string */
	const char	*solaris_end;	/* to transform with this string */
	int		le_size;	/* linux ending string length */
	int		se_size;	/* solaris ending string length */
};

#define	l2s_locale(lname, sname) \
	{(lname), (sname), sizeof ((lname)) - 1, sizeof ((sname)) - 1}

#define	MAXLOCALENAMELEN	30
#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

/*
 * Most syscalls return an int but some return something else, typically a
 * ssize_t. This can be either an int or a long, depending on if we're compiled
 * for 32-bit or 64-bit. To correctly propagate the -errno return code in the
 * 64-bit case, we declare all emulation wrappers will return a long. Thus,
 * when we save the return value into the %eax or %rax register and return to
 * Linux, we will have the right size value in both the 32 and 64 bit cases.
 */

typedef long (*lx_syscall_handler_t)();

static lx_syscall_handler_t lx_handlers[LX_NSYSCALLS + 1];

static uintptr_t stack_bottom;

#if defined(_LP64)
long lx_fsb;
long lx_fs;
#endif
int lx_install = 0;		/* install mode enabled if non-zero */
boolean_t lx_is_rpm = B_FALSE;
int lx_rpm_delay = 1;
int lx_strict = 0;		/* "strict" mode enabled if non-zero */
int lx_verbose = 0;		/* verbose mode enabled if non-zero */
int lx_debug_enabled = 0;	/* debugging output enabled if non-zero */

pid_t zoneinit_pid;		/* zone init PID */

thread_key_t lx_tsd_key;

int
lx_errno(int err)
{
	if (err >= sizeof (stol_errno) / sizeof (stol_errno[0])) {
		lx_debug("invalid errno %d\n", err);
		assert(0);
	}

	return (stol_errno[err]);
}

int
uucopy_unsafe(const void *src, void *dst, size_t n)
{
	bcopy(src, dst, n);
	return (0);
}

int
uucopystr_unsafe(const void *src, void *dst, size_t n)
{
	(void) strncpy((char *)src, dst, n);
	return (0);
}

static void
i_lx_msg(int fd, char *msg, va_list ap)
{
	int	i;
	char	buf[LX_MSG_MAXLEN];

	/* LINTED [possible expansion issues] */
	i = vsnprintf(buf, sizeof (buf), msg, ap);
	buf[LX_MSG_MAXLEN - 1] = '\0';
	if (i == -1)
		return;

	/* if debugging is enabled, send this message to debug output */
	if (LX_DEBUG_ISENABLED)
		lx_debug(buf);

	if (fd == 2) {
		/*
		 * We let the user choose whether or not to see these
		 * messages on the console.
		 */
		if (lx_verbose == 0)
			return;
	}

	/* we retry in case of EINTR */
	do {
		i = write(fd, buf, strlen(buf));
	} while ((i == -1) && (errno == EINTR));
}

/*PRINTFLIKE1*/
void
lx_err(char *msg, ...)
{
	va_list	ap;

	assert(msg != NULL);

	va_start(ap, msg);
	i_lx_msg(STDERR_FILENO, msg, ap);
	va_end(ap);
}

/*
 * This is just a non-zero exit value which also isn't one that would allow
 * us to easily detect if a branded process exited because of a recursive
 * fatal error.
 */
#define	LX_ERR_FATAL	42

/*
 * Our own custom version of abort(), this routine will be used in place
 * of the one located in libc.  The primary difference is that this version
 * will first reset the signal handler for SIGABRT to SIG_DFL, ensuring the
 * SIGABRT sent causes us to dump core and is not caught by a user program.
 */
void
abort(void)
{
	static int aborting = 0;

	struct sigaction sa;
	sigset_t sigmask;

	/* watch out for recursive calls to this function */
	if (aborting != 0)
		exit(LX_ERR_FATAL);

	aborting = 1;

	/*
	 * Block all signals here to avoid taking any signals while exiting
	 * in an effort to avoid any strange user interaction with our death.
	 */
	(void) sigfillset(&sigmask);
	(void) sigprocmask(SIG_BLOCK, &sigmask, NULL);

	/*
	 * Our own version of abort(3C) that we know will never call
	 * a user-installed SIGABRT handler first.  We WANT to die.
	 *
	 * Do this by resetting the handler to SIG_DFL, and releasing any
	 * held SIGABRTs.
	 *
	 * If no SIGABRTs are pending, send ourselves one.
	 *
	 * The while loop is a bit of overkill, but abort(3C) does it to
	 * assure it never returns so we will as well.
	 */
	(void) sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = SIG_DFL;
	sa.sa_flags = 0;

	for (;;) {
		(void) sigaction(SIGABRT, &sa, NULL);
		(void) sigrelse(SIGABRT);
		(void) thr_kill(thr_self(), SIGABRT);
	}

	/*NOTREACHED*/
}

/*PRINTFLIKE1*/
void
lx_msg(char *msg, ...)
{
	va_list	ap;

	assert(msg != NULL);
	va_start(ap, msg);
	i_lx_msg(STDOUT_FILENO, msg, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
lx_err_fatal(char *msg, ...)
{
	va_list	ap;

	assert(msg != NULL);

	va_start(ap, msg);
	i_lx_msg(STDERR_FILENO, msg, ap);
	va_end(ap);
	abort();
}

/*
 * See if it is safe to alloca() sz bytes.  Return 1 for yes, 0 for no.
 */
int
lx_check_alloca(size_t sz)
{
	uintptr_t sp = (uintptr_t)&sz;
	uintptr_t end = sp - sz;

	return ((end < sp) && (end >= stack_bottom));
}

/*PRINTFLIKE1*/
void
lx_unsupported(char *msg, ...)
{
	va_list	ap;
	char dmsg[256];
	int lastc;

	assert(msg != NULL);

	/* make a brand call so we can easily dtrace unsupported actions */
	va_start(ap, msg);
	/* LINTED [possible expansion issues] */
	(void) vsnprintf(dmsg, sizeof (dmsg), msg, ap);
	dmsg[255] = '\0';
	lastc = strlen(dmsg) - 1;
	if (dmsg[lastc] == '\n')
		dmsg[lastc] = '\0';
	(void) syscall(SYS_brand, B_UNSUPPORTED, dmsg);
	va_end(ap);

	/* send the msg to the error stream */
	va_start(ap, msg);
	i_lx_msg(STDERR_FILENO, msg, ap);
	va_end(ap);

	/*
	 * If the user doesn't trust the application to responsibly
	 * handle ENOTSUP, we kill the application.
	 */
	if (lx_strict)
		(void) kill(getpid(), SIGSYS);
}

int lx_init(int argc, char *argv[], char *envp[]);

lx_tsd_t *
lx_get_tsd(void)
{
	int ret;
	lx_tsd_t *lx_tsd;

	if ((ret = thr_getspecific(lx_tsd_key, (void **)&lx_tsd)) != 0) {
		lx_err_fatal("lx_get_tsd: unable to read "
		    "thread-specific data: %s", strerror(ret));
	}

	assert(lx_tsd != 0);

	return (lx_tsd);
}

/*
 * This function is called from the kernel like a signal handler.  Each
 * function call is a request to provide emulation for a system call that, on
 * illumos, is implemented in userland.  The system call number selection and
 * argument parsing have already been done by the kernel.
 */
void
lx_emulate(ucontext_t *ucp, int syscall_num, uintptr_t *args)
{
	long emu_ret;
	int emu_errno = 0;

	LX_EMULATE_ENTER(ucp, syscall_num, args);
	lx_debug("lx_emulate(%p, %d, [%p, %p, %p, %p, %p, %p])\n",
	    ucp, syscall_num, args[0], args[1], args[2], args[3], args[4],
	    args[5]);

	/*
	 * The kernel should have saved us a context that will not restore the
	 * previous signal mask.  Some emulated system calls alter the signal
	 * mask; restoring it after the emulation would cancel that out.
	 */
	assert(!(ucp->uc_flags & UC_SIGMASK));

	/*
	 * The kernel ensures that the syscall_num is sane; Use it as is.
	 */
	assert(syscall_num >= 0);
	assert(syscall_num < (sizeof (lx_handlers) / sizeof (lx_handlers[0])));
	if (lx_handlers[syscall_num] == NULL) {
		lx_err_fatal("lx_emulate: kernel sent us a call we cannot "
		    "emulate (%d)", syscall_num);
	}

	/*
	 * Call our handler function:
	 */
	emu_ret = lx_handlers[syscall_num](args[0], args[1], args[2], args[3],
	    args[4], args[5]);

	/*
	 * If the return value is between -1 and -4095 then it's an errno.
	 * The kernel will translate it to the Linux equivalent for us.
	 */
	if (emu_ret < 0 && emu_ret > -4096) {
		emu_errno = (int)-emu_ret;
	}

	/*
	 * Return to the context we were passed
	 */
	LX_EMULATE_RETURN(ucp, syscall_num, emu_ret, emu_errno);
	lx_debug("\tlx_emulate(%d) done (ret %ld / 0x%p ; errno %d)",
	    syscall_num, emu_ret, emu_ret, emu_errno);
	(void) syscall(SYS_brand, B_EMULATION_DONE, ucp, syscall_num, emu_ret,
	    emu_errno);

	assert(!"cannot be returned here");
}

static void
lx_close_fh(FILE *file)
{
	int fd, fd_new;

	if (file == NULL)
		return;

	if ((fd = fileno(file)) < 0)
		return;

	fd_new = dup(fd);
	if (fd_new == -1)
		return;

	(void) fclose(file);
	(void) dup2(fd_new, fd);
	(void) close(fd_new);
}


extern int set_l10n_alternate_root(char *path);

#if defined(_LP64)
static void *
map_vdso()
{
	int fd;
	mmapobj_result_t	mpp[10]; /* we know the size of our lib */
	mmapobj_result_t	*smpp = mpp;
	uint_t			mapnum = 10;

	if ((fd = open("/native/usr/lib/brand/lx/amd64/lx_vdso.so.1",
	    O_RDONLY)) == -1)
		lx_err_fatal("couldn't open lx_vdso.so.1");

	if (mmapobj(fd, MMOBJ_INTERPRET, smpp, &mapnum, NULL) == -1)
		lx_err_fatal("couldn't mmapobj lx_vdso.so.1");

	(void) close(fd);

	/* assume first segment is the base of the mapping */
	return (smpp->mr_addr);
}
#endif

/*
 * Initialize the thread specific data for this thread.
 */
void
lx_init_tsd(lx_tsd_t *lxtsd)
{
	int err;

	bzero(lxtsd, sizeof (*lxtsd));
	lxtsd->lxtsd_exit = LX_ET_NONE;

	/*
	 * The Linux alternate signal stack is initially disabled:
	 */
	lxtsd->lxtsd_sigaltstack.ss_flags = LX_SS_DISABLE;

	/*
	 * Create a per-thread exit context from the current register and
	 * native/brand stack state.  Replace the saved program counter value
	 * with the address of lx_exit_common(); we wish to revector there when
	 * the thread or process is exiting.
	 */
	if (getcontext(&lxtsd->lxtsd_exit_context) != 0) {
		lx_err_fatal("Unable to initialize thread-specific exit "
		    "context: %s", strerror(errno));
	}
	LX_REG(&lxtsd->lxtsd_exit_context, REG_PC) = (uintptr_t)lx_exit_common;

	/*
	 * Align the stack pointer and clear the frame pointer.
	 */
	LX_REG(&lxtsd->lxtsd_exit_context, REG_FP) = 0;
	LX_REG(&lxtsd->lxtsd_exit_context, REG_SP) &= ~(STACK_ALIGN - 1UL);
#if defined(_LP64)
#if (STACK_ENTRY_ALIGN != 8) && (STACK_ALIGN != 16)
#error "lx_init_tsd: unexpected STACK_[ENTRY_]ALIGN values"
#endif
	/*
	 * The AMD64 ABI requires that, on entry to a function, the stack
	 * pointer must be 8-byte aligned, but _not_ 16-byte aligned.  When
	 * the frame pointer is pushed, the alignment will then be correct.
	 */
	LX_REG(&lxtsd->lxtsd_exit_context, REG_SP) -= STACK_ENTRY_ALIGN;
#endif

	/*
	 * Block all signals in the exit context to avoid taking any signals
	 * (to the degree possible) while exiting.
	 */
	(void) sigfillset(&lxtsd->lxtsd_exit_context.uc_sigmask);

	if ((err = thr_setspecific(lx_tsd_key, lxtsd)) != 0) {
		lx_err_fatal("Unable to initialize thread-specific data: %s",
		    strerror(err));
	}
}

static void
lx_start(uintptr_t sp, uintptr_t entry)
{
	ucontext_t jump_uc;

	if (getcontext(&jump_uc) != 0) {
		lx_err_fatal("Unable to getcontext for program start: %s",
		    strerror(errno));
	}

	/*
	 * We want to load the general registers from this
	 * context, and switch to the BRAND stack.
	 */
	jump_uc.uc_flags = UC_CPU;
	jump_uc.uc_brand_data[0] = (void *)LX_UC_STACK_BRAND;

	LX_REG(&jump_uc, REG_FP) = NULL;
	LX_REG(&jump_uc, REG_SP) = sp;
	LX_REG(&jump_uc, REG_PC) = entry;

#if defined(_LP64)
	/*
	 * The AMD64 ABI states that at process entry, %rdx contains "a
	 * function pointer that the application should register with
	 * atexit()".  We make sure to pass NULL explicitly so that
	 * no function is registered.
	 */
	LX_REG(&jump_uc, REG_RDX) = NULL;
#endif

	lx_debug("starting Linux program sp %p ldentry %p", sp, entry);

	/*
	 * This system call should not return.
	 */
	if (syscall(SYS_brand, B_JUMP_TO_LINUX, &jump_uc) == -1) {
		lx_err_fatal("B_JUMP_TO_LINUX failed: %s",
		    strerror(errno));
	}
	abort();
}

/*ARGSUSED*/
int
lx_init(int argc, char *argv[], char *envp[])
{
	char		*r;
	auxv_t		*ap;
	long		*p;
	int		err;
	lx_elf_data_t	edp;
	lx_brand_registration_t reg;
	lx_tsd_t	*lxtsd;
#if defined(_LP64)
	void		*vdso_hdr;
#endif

	stack_bottom = 2 * sysconf(_SC_PAGESIZE);

	/*
	 * We need to shutdown all libc stdio.  libc stdio normally goes to
	 * file descriptors, but since we're actually part of a linux
	 * process we don't own these file descriptors and we can't make
	 * any assumptions about their state.
	 */
	lx_close_fh(stdin);
	lx_close_fh(stdout);
	lx_close_fh(stderr);

	lx_debug_init();

	r = getenv("LX_RELEASE");
	if (r == NULL) {
		if (zone_getattr(getzoneid(), LX_KERN_VERSION_NUM, lx_release,
		    sizeof (lx_release)) != sizeof (lx_release))
			(void) strlcpy(lx_release, "2.4.21", LX_VERS_MAX);
	} else {
		(void) strlcpy(lx_release, r, 128);
	}

	lx_debug("lx_release: %s\n", lx_release);

	/*
	 * Should we kill an application that attempts an unimplemented
	 * system call?
	 */
	if (getenv("LX_STRICT") != NULL) {
		lx_strict = 1;
		lx_debug("STRICT mode enabled.\n");
	}

	/*
	 * Are we in install mode?
	 */
	if (getenv("LX_INSTALL") != NULL) {
		lx_install = 1;
		lx_debug("INSTALL mode enabled.\n");
	}

	/*
	 * Should we attempt to send messages to the screen?
	 */
	if (getenv("LX_VERBOSE") != NULL) {
		lx_verbose = 1;
		lx_debug("VERBOSE mode enabled.\n");
	}

	(void) strlcpy(lx_cmd_name, basename(argv[0]), sizeof (lx_cmd_name));
	lx_debug("executing linux process: %s", argv[0]);
	lx_debug("branding myself and setting handler to 0x%p",
	    (void *)lx_emulate);

	/*
	 * The version of rpm that ships with CentOS/RHEL 3.x has a race
	 * condition in it.  If it creates a child process to run a
	 * post-install script, and that child process completes too
	 * quickly, it will disappear before the parent notices.  This
	 * causes the parent to hang forever waiting for the already dead
	 * child to die.  I'm sure there's a Lazarus joke buried in here
	 * somewhere.
	 *
	 * Anyway, as a workaround, we make every child of an 'rpm' process
	 * sleep for 1 second, giving the parent a chance to enter its
	 * wait-for-the-child-to-die loop.  Thay may be the hackiest trick
	 * in all of our Linux emulation code - and that's saying
	 * something.
	 */
	if (strcmp("rpm", basename(argv[0])) == NULL)
		lx_is_rpm = B_TRUE;

	reg.lxbr_version = LX_VERSION;
	reg.lxbr_handler = (void *)&lx_emulate;

	/*
	 * Register the address of the user-space handler with the lx brand
	 * module. As a side-effect this leaves the thread in native syscall
	 * mode so that it's ok to continue to make syscalls during setup. We
	 * need to switch to Linux mode at the end of initialization.
	 */
	if (syscall(SYS_brand, B_REGISTER, &reg))
		lx_err_fatal("failed to brand the process");

	/* Look up the PID that serves as init for this zone */
	if ((err = lx_lpid_to_spid(1, &zoneinit_pid)) < 0)
		lx_err_fatal("Unable to find PID for zone init process: %s",
		    strerror(err));

	/*
	 * Upload data about the lx executable from the kernel.
	 */
	if (syscall(SYS_brand, B_ELFDATA, (void *)&edp))
		lx_err_fatal("failed to get required ELF data from the kernel");

	if (lx_stat_init() != 0)
		lx_err_fatal("failed to setup the stat translator");

	if (lx_statfs_init() != 0)
		lx_err_fatal("failed to setup the statfs translator");

	lx_ptrace_init();

#if defined(_LP64)
	vdso_hdr = map_vdso();
#endif

	/*
	 * Find the aux vector on the stack.
	 */
	p = (long *)envp;
	while (*p != NULL)
		p++;
	/*
	 * p is now pointing at the 0 word after the environ pointers. After
	 * that is the aux vectors.
	 */
	p++;
	for (ap = (auxv_t *)p; ap->a_type != 0; ap++) {
		switch (ap->a_type) {
			case AT_BASE:
				ap->a_un.a_val = edp.ed_base;
				break;
			case AT_ENTRY:
				ap->a_un.a_val = edp.ed_entry;
				break;
			case AT_PHDR:
				ap->a_un.a_val = edp.ed_phdr;
				break;
			case AT_PHENT:
				ap->a_un.a_val = edp.ed_phent;
				break;
			case AT_PHNUM:
				ap->a_un.a_val = edp.ed_phnum;
				break;
#if defined(_LP64)
			case AT_SUN_BRAND_LX_SYSINFO_EHDR:
				ap->a_type = AT_SYSINFO_EHDR;
				ap->a_un.a_val = (long)vdso_hdr;
				break;
#endif
			default:
				break;
		}
	}

	/* Do any thunk server initalization. */
	lxt_server_init(argc, argv);

	/* Setup signal handler information. */
	if (lx_siginit()) {
		lx_err_fatal("failed to initialize lx signals for the "
		    "branded process");
	}

	/* Setup thread-specific data area for managing linux threads. */
	if ((err = thr_keycreate(&lx_tsd_key, NULL)) != 0) {
		lx_err_fatal("thr_keycreate(lx_tsd_key) failed: %s",
		    strerror(err));
	}

	lx_debug("thr_keycreate created lx_tsd_key (%d)", lx_tsd_key);

	/*
	 * Initialize the thread specific data for this thread.
	 */
	if ((lxtsd = malloc(sizeof (*lxtsd))) == NULL) {
		lx_err_fatal("failed to allocate tsd for main thread: %s",
		    strerror(errno));
	}
	lx_debug("lx tsd allocated @ %p", lxtsd);
	lx_init_tsd(lxtsd);

	/*
	 * Allocate the brand emulation stack for the main process thread.
	 * Register the thread-specific data structure with the stack list so
	 * that it may be freed at thread exit or fork(2).
	 */
	lx_install_stack(NULL, 0, lxtsd);

	/*
	 * The brand linker expects the stack pointer to point to
	 * "argc", which is just before &argv[0].
	 */
	lx_start((uintptr_t)argv - sizeof (void *), edp.ed_ldentry);

	/*NOTREACHED*/
	abort();
	return (0);
}

/*
 * We "return" to this function via a context hand-crafted by
 * "lx_init_tsd()"; see that function for more detail.
 *
 * NOTE: Our call frame is on the main thread stack, not the alternate native
 * stack -- it is safe to release the latter here.  The frame does not have a
 * valid return address, so this function MUST NOT return.
 */
void
lx_exit_common(void)
{
	lx_tsd_t *lxtsd = lx_get_tsd();
	int ev = (0xff & lxtsd->lxtsd_exit_status);

	switch (lxtsd->lxtsd_exit) {
	case LX_ET_EXIT:
		lx_debug("lx_exit_common(LX_ET_EXIT, %d)\n", ev);

		/*
		 * If the thread is exiting, but not the entire process, we
		 * must free the stack we allocated for usermode emulation.
		 * This is safe to do here because the setcontext() put us
		 * back on the BRAND stack for this process.  This function
		 * also frees the thread-specific data object for this thread.
		 */
		lx_free_stack();

		/*
		 * The native thread return value is never seen so we pass
		 * NULL.
		 */
		thr_exit(NULL);
		break;

	case LX_ET_EXIT_GROUP:
		lx_debug("lx_exit_common(LX_ET_EXIT_GROUP, %d)\n", ev);
		exit(ev);
		break;

	default:
		abort();
	}

	abort();
}

const ucontext_t *
lx_find_brand_uc(void)
{
	ucontext_t *ucp = NULL;

	/*
	 * Ask for the current emulation (or signal handling) ucontext_t...
	 */
	assert(syscall(SYS_brand, B_GET_CURRENT_CONTEXT, &ucp) == 0);

	for (;;) {
		uintptr_t flags;

		lx_debug("lx_find_brand_uc: inspect ucp %p...\n", ucp);
		assert(ucp != NULL);

		flags = (uintptr_t)ucp->uc_brand_data[0];

		if (flags & LX_UC_STACK_BRAND) {
			lx_debug("lx_find_brand_uc: ucp %p\n", ucp);

			return (ucp);
		}

		lx_debug("lx_find_brand_uc: skip non-BRAND ucp %p\n", ucp);

		/*
		 * Walk up the context chain to find the most recently stored
		 * brand register state.
		 */
		ucp = ucp->uc_link;
	}
}

uintptr_t
lx_find_brand_sp(void)
{
	const ucontext_t *ucp = lx_find_brand_uc();
	uintptr_t sp = LX_REG(ucp, REG_SP);

	lx_debug("lx_find_brand_sp: ucp %p sp %p\n", ucp, sp);

	return (sp);
}

ucontext_t *
lx_syscall_regs(void)
{
	ucontext_t *ucp = NULL;
	uintptr_t flags;

	/*
	 * Ask for the current emulation (or signal handling) ucontext_t...
	 */
	assert(syscall(SYS_brand, B_GET_CURRENT_CONTEXT, &ucp) == 0);
	assert(ucp != NULL);

	/*
	 * Use of the lx_syscall_regs() function implies that the topmost (i.e.
	 * current) context is for a system call emulation request from the
	 * kernel, rather than a signal handling frame.
	 */
	flags = (uintptr_t)ucp->uc_brand_data[0];
	assert(flags & LX_UC_FRAME_IS_SYSCALL);

	lx_debug("lx_syscall_regs: ucp %p\n", ucp);

	return (ucp);
}

int
lx_lpid_to_spair(pid_t lpid, pid_t *spid, lwpid_t *slwp)
{
	pid_t pid;
	lwpid_t tid;

	if (lpid == 0) {
		pid = getpid();
		tid = thr_self();
	} else {
		if (syscall(SYS_brand, B_LPID_TO_SPAIR, lpid, &pid, &tid) < 0)
			return (-errno);

		/*
		 * If the returned pid is -1, that indicates we tried to
		 * look up the PID for init, but that process no longer
		 * exists.
		 */
		if (pid == -1)
			return (-ESRCH);
	}

	if (uucopy(&pid, spid, sizeof (pid_t)) != 0)
		return (-errno);

	if (uucopy(&tid, slwp, sizeof (lwpid_t)) != 0)
		return (-errno);

	return (0);
}

int
lx_lpid_to_spid(pid_t lpid, pid_t *spid)
{
	lwpid_t slwp;

	return (lx_lpid_to_spair(lpid, spid, &slwp));
}

char *
lx_fd_to_path(int fd, char *buf, int buf_size)
{
	char	path_proc[MAXPATHLEN];
	pid_t	pid;
	int	n;

	assert((buf != NULL) && (buf_size >= 0));

	if (fd < 0)
		return (NULL);

	if ((pid = getpid()) == -1)
		return (NULL);

	(void) snprintf(path_proc, MAXPATHLEN,
	    "/native/proc/%d/path/%d", pid, fd);

	if ((n = readlink(path_proc, buf, buf_size - 1)) == -1)
		return (NULL);
	buf[n] = '\0';

	return (buf);
}

#if defined(_LP64)
/* The following is the 64-bit syscall table */

static lx_syscall_handler_t lx_handlers[] = {
	NULL,		/*   0: read */
	NULL,		/*   1: write */
	lx_open,
	lx_close,
	lx_stat64,
	lx_fstat64,
	lx_lstat64,
	lx_poll,
	lx_lseek,
	lx_mmap,
	lx_mprotect,
	lx_munmap,
	NULL,		/* 12: brk */
	lx_rt_sigaction,
	lx_rt_sigprocmask,
	lx_rt_sigreturn,
	NULL,		/* 16: ioctl */
	lx_pread,
	lx_pwrite,
	lx_readv,
	lx_writev,
	lx_access,
	NULL,		/* 22: pipe */
	lx_select,
	NULL,		/* 24: sched_yield */
	lx_remap,
	lx_msync,
	lx_mincore,
	lx_madvise,
	lx_shmget,
	lx_shmat,
	lx_shmctl,
	lx_dup,
	lx_dup2,
	lx_pause,
	lx_nanosleep,
	lx_getitimer,
	lx_alarm,
	lx_setitimer,
	NULL,		/* 39: getpid */
	lx_sendfile64,
	lx_socket,
	lx_connect,
	lx_accept,
	lx_sendto,
	lx_recvfrom,
	lx_sendmsg,
	lx_recvmsg,
	lx_shutdown,
	lx_bind,
	lx_listen,
	lx_getsockname,
	lx_getpeername,
	lx_socketpair,
	lx_setsockopt,
	lx_getsockopt,
	lx_clone,
	lx_fork,
	lx_vfork,
	lx_execve,
	lx_exit,
	NULL,		/* 61: wait4 */
	NULL,		/* 62: kill */
	lx_uname,
	lx_semget,
	lx_semop,
	lx_semctl,
	lx_shmdt,
	lx_msgget,
	lx_msgsnd,
	lx_msgrcv,
	lx_msgctl,
	lx_fcntl64,
	lx_flock,
	lx_fsync,
	lx_fdatasync,
	lx_truncate,
	lx_ftruncate,
	lx_getdents,
	lx_getcwd,
	lx_chdir,
	lx_fchdir,
	lx_rename,
	lx_mkdir,
	lx_rmdir,
	lx_creat,
	lx_link,
	lx_unlink,
	lx_symlink,
	lx_readlink,
	lx_chmod,
	lx_fchmod,
	lx_chown,
	lx_fchown,
	lx_lchown,
	lx_umask,
	lx_gettimeofday,
	lx_getrlimit,
	lx_getrusage,
	NULL,		/* 99: sysinfo */
	lx_times,
	lx_ptrace,
	lx_getuid,
	lx_syslog,
	lx_getgid,
	lx_setuid,
	lx_setgid,
	lx_geteuid,
	lx_getegid,
	lx_setpgid,
	NULL,		/* 110: getppid */
	lx_getpgrp,
	lx_setsid,
	lx_setreuid,
	lx_setregid,
	lx_getgroups,
	lx_setgroups,
	NULL,		/* 117: setresuid */
	lx_getresuid,
	NULL,		/* 119: setresgid */
	lx_getresgid,
	lx_getpgid,
	lx_setfsuid,
	lx_setfsgid,
	lx_getsid,
	lx_capget,
	lx_capset,
	lx_rt_sigpending,
	lx_rt_sigtimedwait,
	lx_rt_sigqueueinfo,
	lx_rt_sigsuspend,
	lx_sigaltstack,
	lx_utime,
	lx_mknod,
	NULL,		/* 134: uselib */
	lx_personality,
	NULL,		/* 136: ustat */
	lx_statfs,
	lx_fstatfs,
	lx_sysfs,
	lx_getpriority,
	lx_setpriority,
	lx_sched_setparam,
	lx_sched_getparam,
	lx_sched_setscheduler,
	lx_sched_getscheduler,
	lx_sched_get_priority_max,
	lx_sched_get_priority_min,
	lx_sched_rr_get_interval,
	lx_mlock,
	lx_munlock,
	lx_mlockall,
	lx_munlockall,
	lx_vhangup,
	NULL,		/* 154: modify_ldt */
	NULL,		/* 155: pivot_root */
	lx_sysctl,
	lx_prctl,
	NULL,		/* 158: arch_prctl */
	lx_adjtimex,
	lx_setrlimit,
	lx_chroot,
	lx_sync,
	NULL,		/* 163: acct */
	lx_settimeofday,
	lx_mount,
	lx_umount2,
	NULL,		/* 167: swapon */
	NULL,		/* 168: swapoff */
	lx_reboot,
	lx_sethostname,
	lx_setdomainname,
	NULL,		/* 172: iopl */
	NULL,		/* 173: ioperm */
	NULL,		/* 174: create_module */
	NULL,		/* 175: init_module */
	NULL,		/* 176: delete_module */
	NULL,		/* 177: get_kernel_syms */
	lx_query_module,
	NULL,		/* 179: quotactl */
	NULL,		/* 180: nfsservctl */
	NULL,		/* 181: getpmsg */
	NULL,		/* 182: putpmsg */
	NULL,		/* 183: afs_syscall */
	NULL,		/* 184: tux */
	NULL,		/* 185: security */
	NULL,		/* 186: gettid */
	NULL,		/* 187: readahead */
	NULL,		/* 188: setxattr */
	NULL,		/* 189: lsetxattr */
	NULL,		/* 190: fsetxattr */
	NULL,		/* 191: getxattr */
	NULL,		/* 192: lgetxattr */
	NULL,		/* 193: fgetxattr */
	NULL,		/* 194: listxattr */
	NULL,		/* 195: llistxattr */
	NULL,		/* 196: flistxattr */
	NULL,		/* 197: removexattr */
	NULL,		/* 198: lremovexattr */
	NULL,		/* 199: fremovexattr */
	NULL,		/* 200: tkill */
	lx_time,
	NULL,		/* 202: futex */
	lx_sched_setaffinity,
	lx_sched_getaffinity,
	NULL,		/* 205: set_thread_area */
	NULL,		/* 206: io_setup */
	NULL,		/* 207: io_destroy */
	NULL,		/* 208: io_getevents */
	NULL,		/* 209: io_submit */
	NULL,		/* 210: io_cancel */
	NULL,		/* 211: get_thread_area */
	NULL,		/* 212: lookup_dcookie */
	lx_epoll_create,
	NULL,		/* 214: epoll_ctl_old */
	NULL,		/* 215: epoll_wait_old */
	NULL,		/* 216: remap_file_pages */
	lx_getdents64,
	NULL,		/* 218: set_tid_address */
	NULL,		/* 219: restart_syscall */
	lx_semtimedop,
	lx_fadvise64_64,
	lx_timer_create,
	lx_timer_settime,
	lx_timer_gettime,
	lx_timer_getoverrun,
	lx_timer_delete,
	lx_clock_settime,
	lx_clock_gettime,
	lx_clock_getres,
	lx_clock_nanosleep,
	lx_group_exit,
	lx_epoll_wait,
	lx_epoll_ctl,
	NULL,		/* 234: tgkill */
	lx_utimes,
	NULL,		/* 236: vserver */
	NULL,		/* 237: mbind */
	NULL,		/* 238: set_mempolicy */
	NULL,		/* 239: get_mempolicy */
	NULL,		/* 240: mq_open */
	NULL,		/* 241: mq_unlink */
	NULL,		/* 242: mq_timedsend */
	NULL,		/* 243: mq_timedreceive */
	NULL,		/* 244: mq_notify */
	NULL,		/* 245: mq_getsetattr */
	NULL,		/* 246: kexec_load */
	NULL,		/* 247: waitid */
	NULL,		/* 248: add_key */
	NULL,		/* 249: request_key */
	NULL,		/* 250: keyctl */
	NULL,		/* 251: ioprio_set */
	NULL,		/* 252: ioprio_get */
	lx_inotify_init,
	lx_inotify_add_watch,
	lx_inotify_rm_watch,
	NULL,		/* 256: migrate_pages */
	lx_openat,
	lx_mkdirat,
	lx_mknodat,
	lx_fchownat,
	lx_futimesat,
	lx_fstatat64,
	lx_unlinkat,
	lx_renameat,
	lx_linkat,
	lx_symlinkat,
	lx_readlinkat,
	lx_fchmodat,
	lx_faccessat,
	lx_pselect6,
	lx_ppoll,
	NULL,		/* 272: unshare */
	NULL,		/* 273: set_robust_list */
	NULL,		/* 274: get_robust_list */
	NULL,		/* 275: splice */
	NULL,		/* 276: tee */
	NULL,		/* 277: sync_file_range */
	NULL,		/* 278: vmsplice */
	NULL,		/* 279: move_pages */
	lx_utimensat,
	lx_epoll_pwait,
	NULL,		/* 282: signalfd */
	lx_timerfd_create,
	lx_eventfd,
	NULL,		/* 285: fallocate */
	lx_timerfd_settime,
	lx_timerfd_gettime,
	lx_accept4,
	NULL,		/* 289: signalfd4 */
	lx_eventfd2,
	lx_epoll_create1,
	lx_dup3,
	NULL,		/* 293: pipe2 */
	lx_inotify_init1,
	NULL,		/* 295: preadv */
	NULL,		/* 296: pwritev */
	lx_rt_tgsigqueueinfo,
	NULL,		/* 298: perf_event_open */
	NULL,		/* 299: recvmmsg */
	NULL,		/* 300: fanotify_init */
	NULL,		/* 301: fanotify_mark */
	lx_prlimit64,
	NULL,		/* 303: name_to_handle_at */
	NULL,		/* 304: open_by_handle_at */
	NULL,		/* 305: clock_adjtime */
	NULL,		/* 306: syncfs */
	NULL,		/* 307: sendmmsg */
	NULL,		/* 309: setns */
	lx_getcpu,
	NULL,		/* 310: process_vm_readv */
	NULL,		/* 311: process_vm_writev */
	NULL,		/* 312: kcmp */
	NULL,		/* 313: finit_module */
	NULL,		/* 314: sched_setattr */
	NULL,		/* 315: sched_getattr */
	NULL,		/* 316: renameat2 */
	NULL,		/* 317: seccomp */
	NULL,		/* 318: getrandom */
	NULL,		/* 319: memfd_create */
	NULL,		/* 320: kexec_file_load */
	NULL,		/* 321: bpf */
	NULL,		/* 322: execveat */

	/* XXX TBD gap then x32 syscalls from 512 - 544 */
};

#else
/* The following is the 32-bit syscall table */

static lx_syscall_handler_t lx_handlers[] = {
	NULL,		/*   0: nosys */
	lx_exit,
	lx_fork,
	NULL,		/*   3: read */
	NULL,		/*   4: write */
	lx_open,
	lx_close,
	NULL,		/*   7: waitpid */
	lx_creat,
	lx_link,
	lx_unlink,
	lx_execve,
	lx_chdir,
	lx_time,
	lx_mknod,
	lx_chmod,
	lx_lchown16,
	NULL,		/*  17: break */
	NULL,		/*  18: stat */
	lx_lseek,
	NULL,		/*  20: getpid */
	lx_mount,
	lx_umount,
	lx_setuid16,
	lx_getuid16,
	lx_stime,
	lx_ptrace,
	lx_alarm,
	NULL,		/*  28: fstat */
	lx_pause,
	lx_utime,
	NULL,		/*  31: stty */
	NULL,		/*  32: gtty */
	lx_access,
	lx_nice,
	NULL,		/*  35: ftime */
	lx_sync,
	NULL,		/*  37: kill */
	lx_rename,
	lx_mkdir,
	lx_rmdir,
	lx_dup,
	NULL,		/*  42: pipe */
	lx_times,
	NULL,		/*  44: prof */
	NULL,		/*  45: brk */
	lx_setgid16,
	lx_getgid16,
	lx_signal,
	lx_geteuid16,
	lx_getegid16,
	NULL,		/*  51: acct */
	lx_umount2,
	NULL,		/*  53: lock */
	NULL,		/*  54: ioctl */
	lx_fcntl,
	NULL,		/*  56: mpx */
	lx_setpgid,
	NULL,		/*  58: ulimit */
	NULL,		/*  59: olduname */
	lx_umask,
	lx_chroot,
	NULL,		/*  62: ustat */
	lx_dup2,
	NULL,		/*  64: getppid */
	lx_getpgrp,
	lx_setsid,
	lx_sigaction,
	NULL,		/*  68: sgetmask */
	NULL,		/*  69: ssetmask */
	lx_setreuid16,
	lx_setregid16,
	lx_sigsuspend,
	lx_sigpending,
	lx_sethostname,
	lx_setrlimit,
	lx_oldgetrlimit,
	lx_getrusage,
	lx_gettimeofday,
	lx_settimeofday,
	lx_getgroups16,
	lx_setgroups16,
	NULL,		/*  82: select */
	lx_symlink,
	NULL,		/*  84: oldlstat */
	lx_readlink,
	NULL,		/*  86: uselib */
	NULL,		/*  87: swapon */
	lx_reboot,
	lx_readdir,
	lx_mmap,
	lx_munmap,
	lx_truncate,
	lx_ftruncate,
	lx_fchmod,
	lx_fchown16,
	lx_getpriority,
	lx_setpriority,
	NULL,		/*  98: profil */
	lx_statfs,
	lx_fstatfs,
	NULL,		/* 101: ioperm */
	lx_socketcall,
	lx_syslog,
	lx_setitimer,
	lx_getitimer,
	lx_stat,
	lx_lstat,
	lx_fstat,
	NULL,		/* 109: uname */
	NULL,		/* 110: oldiopl */
	lx_vhangup,
	NULL,		/* 112: idle */
	NULL,		/* 113: vm86old */
	NULL,		/* 114: wait4 */
	NULL,		/* 115: swapoff */
	NULL,		/* 116: sysinfo */
	lx_ipc,
	lx_fsync,
	lx_sigreturn,
	lx_clone,
	lx_setdomainname,
	lx_uname,
	NULL,		/* 123: modify_ldt */
	lx_adjtimex,
	lx_mprotect,
	lx_sigprocmask,
	NULL,		/* 127: create_module */
	NULL,		/* 128: init_module */
	NULL,		/* 129: delete_module */
	NULL,		/* 130: get_kernel_syms */
	NULL,		/* 131: quotactl */
	lx_getpgid,
	lx_fchdir,
	NULL,		/* 134: bdflush */
	lx_sysfs,
	lx_personality,
	NULL,		/* 137: afs_syscall */
	lx_setfsuid16,
	lx_setfsgid16,
	lx_llseek,
	lx_getdents,
	lx_select,
	lx_flock,
	lx_msync,
	lx_readv,
	lx_writev,
	lx_getsid,
	lx_fdatasync,
	lx_sysctl,
	lx_mlock,
	lx_munlock,
	lx_mlockall,
	lx_munlockall,
	lx_sched_setparam,
	lx_sched_getparam,
	lx_sched_setscheduler,
	lx_sched_getscheduler,
	NULL,		/* 158: sched_yield */
	lx_sched_get_priority_max,
	lx_sched_get_priority_min,
	lx_sched_rr_get_interval,
	lx_nanosleep,
	lx_remap,
	NULL,		/* 164: setresuid16 */
	lx_getresuid16,
	NULL,		/* 166: vm86 */
	lx_query_module,
	lx_poll,
	NULL,		/* 169: nfsservctl */
	NULL,		/* 170: setresgid16 */
	lx_getresgid16,
	lx_prctl,
	lx_rt_sigreturn,
	lx_rt_sigaction,
	lx_rt_sigprocmask,
	lx_rt_sigpending,
	lx_rt_sigtimedwait,
	lx_rt_sigqueueinfo,
	lx_rt_sigsuspend,
	lx_pread64,
	lx_pwrite64,
	lx_chown16,
	lx_getcwd,
	lx_capget,
	lx_capset,
	lx_sigaltstack,
	lx_sendfile,
	NULL,		/* 188: getpmsg */
	NULL,		/* 189: putpmsg */
	lx_vfork,
	lx_getrlimit,
	lx_mmap2,
	lx_truncate64,
	lx_ftruncate64,
	lx_stat64,
	lx_lstat64,
	lx_fstat64,
	lx_lchown,
	lx_getuid,
	lx_getgid,
	lx_geteuid,
	lx_getegid,
	lx_setreuid,
	lx_setregid,
	lx_getgroups,
	lx_setgroups,
	lx_fchown,
	NULL,		/* 208: setresuid */
	lx_getresuid,
	NULL,		/* 210: setresgid */
	lx_getresgid,
	lx_chown,
	lx_setuid,
	lx_setgid,
	lx_setfsuid,
	lx_setfsgid,
	NULL,		/* 217: pivot_root */
	lx_mincore,
	lx_madvise,
	lx_getdents64,
	lx_fcntl64,
	NULL,		/* 222: tux */
	NULL,		/* 223: security */
	NULL,		/* 224: gettid */
	NULL,		/* 225: readahead */
	NULL,		/* 226: setxattr */
	NULL,		/* 227: lsetxattr */
	NULL,		/* 228: fsetxattr */
	NULL,		/* 229: getxattr */
	NULL,		/* 230: lgetxattr */
	NULL,		/* 231: fgetxattr */
	NULL,		/* 232: listxattr */
	NULL,		/* 233: llistxattr */
	NULL,		/* 234: flistxattr */
	NULL,		/* 235: removexattr */
	NULL,		/* 236: lremovexattr */
	NULL,		/* 237: fremovexattr */
	NULL,		/* 238: tkill */
	lx_sendfile64,
	NULL,		/* 240: futex */
	lx_sched_setaffinity,
	lx_sched_getaffinity,
	NULL,		/* 243: set_thread_area */
	NULL,		/* 244: get_thread_area */
	NULL,		/* 245: io_setup */
	NULL,		/* 246: io_destroy */
	NULL,		/* 247: io_getevents */
	NULL,		/* 248: io_submit */
	NULL,		/* 249: io_cancel */
	lx_fadvise64,
	NULL,		/* 251: nosys */
	lx_group_exit,
	NULL,		/* 253: lookup_dcookie */
	lx_epoll_create,
	lx_epoll_ctl,
	lx_epoll_wait,
	NULL,		/* 257: remap_file_pages */
	NULL,		/* 258: set_tid_address */
	lx_timer_create,
	lx_timer_settime,
	lx_timer_gettime,
	lx_timer_getoverrun,
	lx_timer_delete,
	lx_clock_settime,
	lx_clock_gettime,
	lx_clock_getres,
	lx_clock_nanosleep,
	lx_statfs64,
	lx_fstatfs64,
	NULL,		/* 270: tgkill */
	lx_utimes,
	lx_fadvise64_64,
	NULL,		/* 273: vserver */
	NULL,		/* 274: mbind */
	NULL,		/* 275: get_mempolicy */
	NULL,		/* 276: set_mempolicy */
	NULL,		/* 277: mq_open */
	NULL,		/* 278: mq_unlink */
	NULL,		/* 279: mq_timedsend */
	NULL,		/* 280: mq_timedreceive */
	NULL,		/* 281: mq_notify */
	NULL,		/* 282: mq_getsetattr */
	NULL,		/* 283: kexec_load */
	NULL,		/* 284: waitid */
	NULL,		/* 285: sys_setaltroot */
	NULL,		/* 286: add_key */
	NULL,		/* 287: request_key */
	NULL,		/* 288: keyctl */
	NULL,		/* 289: ioprio_set */
	NULL,		/* 290: ioprio_get */
	lx_inotify_init,
	lx_inotify_add_watch,
	lx_inotify_rm_watch,
	NULL,		/* 294: migrate_pages */
	lx_openat,
	lx_mkdirat,
	lx_mknodat,
	lx_fchownat,
	lx_futimesat,
	lx_fstatat64,
	lx_unlinkat,
	lx_renameat,
	lx_linkat,
	lx_symlinkat,
	lx_readlinkat,
	lx_fchmodat,
	lx_faccessat,
	lx_pselect6,
	lx_ppoll,
	NULL,		/* 310: unshare */
	NULL,		/* 311: set_robust_list */
	NULL,		/* 312: get_robust_list */
	NULL,		/* 313: splice */
	NULL,		/* 314: sync_file_range */
	NULL,		/* 315: tee */
	NULL,		/* 316: vmsplice */
	NULL,		/* 317: move_pages */
	lx_getcpu,
	lx_epoll_pwait,
	lx_utimensat,
	NULL,		/* 321: signalfd */
	lx_timerfd_create,
	lx_eventfd,
	NULL,		/* 324: fallocate */
	lx_timerfd_settime,
	lx_timerfd_gettime,
	NULL,		/* 327: signalfd4 */
	lx_eventfd2,
	lx_epoll_create1,
	lx_dup3,
	NULL,		/* 331: pipe2 */
	lx_inotify_init1,
	NULL,		/* 333: preadv */
	NULL,		/* 334: pwritev */
	lx_rt_tgsigqueueinfo,
	NULL,		/* 336: perf_event_open */
	NULL,		/* 337: recvmmsg */
	NULL,		/* 338: fanotify_init */
	NULL,		/* 339: fanotify_mark */
	lx_prlimit64,
	NULL,		/* 341: name_to_handle_at */
	NULL,		/* 342: open_by_handle_at */
	NULL,		/* 343: clock_adjtime */
	NULL,		/* 344: syncfs */
	NULL,		/* 345: sendmmsg */
	NULL,		/* 346: setns */
	NULL,		/* 347: process_vm_readv */
	NULL,		/* 348: process_vm_writev */
	NULL,		/* 349: kcmp */
	NULL,		/* 350: finit_module */
	NULL,		/* 351: sched_setattr */
	NULL,		/* 352: sched_getattr */
	NULL,		/* 353: renameat2 */
	NULL,		/* 354: seccomp */
	NULL,		/* 355: getrandom */
	NULL,		/* 356: memfd_create */
	NULL,		/* 357: bpf */
	NULL,		/* 358: execveat */
};
#endif
