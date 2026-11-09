#include "mlibc/tcb.hpp"
#include <abi-bits/errno.h>
#include <bits/ensure.h>
#include <bits/syscall.h>
#include <mlibc/all-sysdeps.hpp>
#include <string.h>
#include "scnum.h"
#include "io.h"
#include "utils.hpp"
#include "exec_build_stack.hpp"


// ANCHOR: stub
#define STUB()                                                                                     \
	({                                                                                             \
		__ensure(!"STUB function was called");                                                     \
		__builtin_unreachable();                                                                   \
	})
// ANCHOR_END: stub

extern "C" void __rudra_mlibc_enter_thread(void *entry, void *user_arg, Tcb *tcb) {
	if (mlibc::sysdep<TcbSet>(tcb))
		__ensure(!"sys_tcb_set() failed");

	while (!__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED))
		mlibc::sysdep<FutexWait>(&tcb->tid, 0, nullptr);

	tcb->invokeThreadFunc(entry, user_arg);

	mlibc::thread_exit(tcb->returnValue);
}



int bad_heap_alloc(size_t size, void ** pointer) {
	// No memset: heap_base only grows, so these addresses have never been
	// mapped, and the kernel hands out zeroed pages when they first fault in.
	// Touching the range here would fault in every page up front.
	static uintptr_t heap_base = 0xFFFFFFFFE0000000;
	*pointer = (void *) heap_base;
	heap_base += align_up(size, 4096);
	return 0;
}

namespace mlibc {

void Sysdeps<LibcPanic>::operator()() {
	sysdep<LibcLog>("!!! mlibc panic !!!");
	sysdep<Exit>(-1);
	__builtin_trap();
}

void Sysdeps<LibcLog>::operator()(const char *msg) {
	// ssize_t unused;
	// sysdep<Write>(2, msg, strlen(msg), &unused);
	ssize_t unused;
	syscall(SYSCALL_SHOUT, msg, &unused);
}

int Sysdeps<Isatty>::operator()(int fd) {
	(void)fd;
	// this returns ENOTTY when it is not a tty, but we do not have a proper implementation
	// so always return that a file is a tty
	return 0;
}

int Sysdeps<Write>::operator()(int fd, void const *buf, size_t size, ssize_t *ret) {
	int result = syscall(SYSCALL_WRITE, fd, buf, size);
	if (result < 0) return -result;

	*ret = result;
	return 0;
}

int Sysdeps<Execve>::operator()(const char * path, char * const argv[], char * const envp[]) {
	void * stack = nullptr;
	size_t stack_size = 0;
	if (int err = build_exec_stack(path, argv, envp, &stack, &stack_size))
		return err;

	int result = syscall(SYSCALL_EXEC, path, stack, stack_size);

	if (result < 0) return -result;

	return 0;
}

int Sysdeps<Fork>::operator()(pid_t * child) {
	int result = syscall(SYSCALL_FORK);

	if (result < 0) return -result;

	*child = result;
	return 0;
}

int Sysdeps<Waitpid>::operator()(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	// Kernel fills only CPU times (see RUsage in sys/api/syscall.zig).
	struct { unsigned long utime_ns, stime_ns; } ku;
	int result = syscall(SYSCALL_WAITPID, pid, status, flags, ru ? &ku : nullptr);

	if (result < 0) return -result;

	if (ru) {
		memset(ru, 0, sizeof(*ru));
		ru->ru_utime.tv_sec = ku.utime_ns / 1000000000UL;
		ru->ru_utime.tv_usec = (ku.utime_ns % 1000000000UL) / 1000;
		ru->ru_stime.tv_sec = ku.stime_ns / 1000000000UL;
		ru->ru_stime.tv_usec = (ku.stime_ns % 1000000000UL) / 1000;
	}

	*ret_pid = result;
	return 0;
}

static constexpr size_t default_stacksize = 32 * 1024; // 32 KiB stack

int Sysdeps<PrepareStack>::operator()(void ** stack, void * entry, void * user_arg, void * tcb, size_t * stack_size, size_t * guard_size, void ** stack_base) {
	if (!*stack_size) *stack_size = default_stacksize;

	*guard_size = 0;

	if (*stack) {
		*stack_base = stack;
	} else {
		if (*stack_size > default_stacksize)
			*stack_size = default_stacksize;
		bad_heap_alloc(*stack_size, stack_base);
	}

	uintptr_t sp = reinterpret_cast<uintptr_t>(*stack_base) + *stack_size;

	sp &= ~0xF;

	sp -= 32;

	uintptr_t * frame = reinterpret_cast<uintptr_t *>(sp);
	frame[0] = reinterpret_cast<uintptr_t>(entry);
	frame[1] = reinterpret_cast<uintptr_t>(user_arg);
	frame[2] = reinterpret_cast<uintptr_t>(tcb);

	*stack = reinterpret_cast<void *>(sp);
	return 0;
}

int Sysdeps<Clone>::operator()(void * tcb, pid_t * pid_out, void * stack) {
	auto tls = reinterpret_cast<char *>(tcb) + sizeof(Tcb);

	long result;

	asm volatile (
        "mv a7, %1\n\t"
        "mv a0, %2\n\t" // user_stack
        "mv a1, %3\n\t" // tls

        "ecall\n\t"

        "bnez a0, 1f\n\t" // if a0 != 0 then parent; else child

        // --- Child Thread Execution ---
        "ld a0, 0(sp)\n\t"  // 1st arg is entry
        "ld a1, 8(sp)\n\t"  // 2nd arg is user_arg
        "ld a2, 16(sp)\n\t" // 3rd arg is tcb

        "call __rudra_mlibc_enter_thread\n\t"
        "ebreak\n\t" // crash if __mlibc_enter_thread unexpectedly returns

        // --- Parent Thread Execution ---
        "1:\n\t"
        "mv %0, a0\n\t" // move kernel return value (TID) into result

        : "=r"(result)                           // %0: Output
        : "r"(SYSCALL_CLONE), "r"(stack), "r"(tls)   // %1, %2, %3: Inputs
        : "a0", "a1", "a2", "a7", "memory"       // Clobbered registers
    );


    // Handle kernel error codes
    if (result < 0) {
        return -result; 
    }

	*pid_out = result;

    return 0; // Success
}

int Sysdeps<TcbSet>::operator()(void *pointer) {
	uintptr_t thread_data = reinterpret_cast<uintptr_t>(pointer) + sizeof(Tcb);
	asm volatile("mv tp, %0" ::"r"(thread_data));
	// this can never fail in the demo os
	return 0;
}


int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
	bad_heap_alloc(size, pointer);
	return 0;
	// auto out = syscall(
	//     SYS_MMAP, nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
	// );
	// *pointer = (void *)out;
	// if (*pointer == MAP_FAILED)
	// 	return ENOMEM; // the syscall does not return a proper errno, so use ENOMEM
	// return 0;
}

int Sysdeps<AnonFree>::operator()(void *, unsigned long) {
	return 0;
} // no-op

int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t * new_offset) {
	unsigned long long pos;
	int result;
	switch (whence) {
		case SEEK_SET: // set pos to exactly offset, return that in new_offset
			pos = static_cast<unsigned long long>(offset);
			break;
		case SEEK_CUR: // set pos to cur pos + offset
			unsigned long long cur_pos;
			result = syscall(SYSCALL_IOCTL, fd, IOC_GETPOS, &cur_pos);
			if (result < 0) {
				// mlibc::sysdep<LibcLog>("failed ioctl getpos");
			}
			pos = static_cast<long long>(offset) + cur_pos;
			break;
		case SEEK_END:
			unsigned long long end;
			result = syscall(SYSCALL_IOCTL, fd, IOC_GETEND, &end);
			if (result < 0) {
				// mlibc::sysdep<LibcLog>("failed ioctl getend");
			}
			pos = end + static_cast<long long>(offset);
			break;
		case SEEK_DATA:
		case SEEK_HOLE:
			return ENOSYS;
		default:
			return EINVAL;
	}

	result = syscall(SYSCALL_IOCTL, fd, IOC_SETPOS, &pos);
	if (result < 0) {
		// mlibc::sysdep<LibcLog>("failed ioctl setpos");
	}
	if (new_offset)
		*new_offset = static_cast<off_t>(pos);
	return 0;
}

void Sysdeps<Exit>::operator()(int status) {
	syscall(SYSCALL_EXIT, status);
	__builtin_unreachable();
}

void Sysdeps<ThreadExit>::operator()(void) {
	syscall(SYSCALL_THREADEXIT);
	__builtin_unreachable();
}

int Sysdeps<Close>::operator()(int fd) {
	int result = syscall(SYSCALL_CLOSE, fd);

	if (result < 0) return -result;

	return 0;
}
// ANCHOR_END: stubbed-sysdep

int Sysdeps<FutexWait>::operator()(int * pointer, int expected, const struct timespec * time) {
	unsigned long long time_usec;
	if (time == NULL) time_usec = 0;
	else time_usec = time->tv_sec * 1000000 + time->tv_nsec / 1000;
	int result = syscall(SYSCALL_FUTEXWAIT, pointer, expected, time_usec);

	if (result < 0) return -result;

	return 0;
}

int Sysdeps<FutexWake>::operator()(int * pointer, bool all) {
	int result = syscall(SYSCALL_FUTEXWAKE, pointer, all);
	
	if (result < 0) return -result;

	return 0;
}

int Sysdeps<Read>::operator()(int fd, void * buf, unsigned long size, long * ret) {
	int result = syscall(SYSCALL_READ, fd, buf, size);
	if (result < 0) return -result;

	*ret = result;
	return 0;
}
int Sysdeps<Open>::operator()(const char * path, int flags, unsigned int mode, int * fd) {
	int result = syscall(SYSCALL_OPEN, path, flags, mode);

	if (result < 0) return -result;

	*fd = result;
	return 0;
}
int Sysdeps<VmMap>::operator()(void *, size_t, int, int, int, off_t, void **) {
	STUB();
}
int Sysdeps<VmUnmap>::operator()(void *, size_t) {
	STUB();
}
// The kernel only has a since-boot clock, so every clockid reads it.
int Sysdeps<ClockGet>::operator()(int, time_t *secs, long *nanos) {
	long ns = syscall(SYSCALL_CLOCKGET);
	if (ns < 0)
		return -ns;
	*secs = ns / 1000000000L;
	*nanos = ns % 1000000000L;
	return 0;
}

int Sysdeps<Sleep>::operator()(time_t *secs, long *nanos) {
	unsigned long long usec =
	    (unsigned long long)*secs * 1000000ULL + (unsigned long long)*nanos / 1000ULL;
	int result = syscall(SYSCALL_USLEEP, usec);
	if (result < 0)
		return -result;
	*secs = 0;
	*nanos = 0;
	return 0;
}

int Sysdeps<Pipe>::operator()(int * fds, int flags) {
	fds[0] = -1;
	fds[1] = -1;
	int result = syscall(SYSCALL_PIPE, fds, fds + 1);
	if (result < 0) return -result;
	return 0;
}

int Sysdeps<Dup>::operator()(int fd, int flags, int * newfd) {
	*newfd = -1;
	int result = syscall(SYSCALL_IODUP, fd, newfd);
	if (result < 0) return -result;
	return 0;
}

int Sysdeps<Dup2>::operator()(int fd, int flags, int newfd) {
	int result = syscall(SYSCALL_IODUP, fd, &newfd);
	if (result < 0) return -result;
	return 0;
}


} // namespace mlibc
