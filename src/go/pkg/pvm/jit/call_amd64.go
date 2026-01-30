package jit

/*
#cgo CFLAGS: -D_GNU_SOURCE
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>

// x86_64 register indices in gregset_t (from sys/ucontext.h)
#define JIT_REG_RAX 13
#define JIT_REG_RDX 12
#define JIT_REG_RIP 16

// Thread-local JIT context for parallel execution
typedef struct {
    uintptr_t code_start;
    uintptr_t code_end;
    uintptr_t recovery_addr;
} jit_thread_ctx_t;

static __thread jit_thread_ctx_t tls_ctx = {0, 0, 0};

// Previous handlers
static struct sigaction old_sigsegv;
static struct sigaction old_sigbus;

// Signal handler - uses thread-local context
static void jit_fault_handler(int sig, siginfo_t *info, void *uctx) {
    ucontext_t *ctx = (ucontext_t *)uctx;
    uintptr_t pc = (uintptr_t)ctx->uc_mcontext.gregs[JIT_REG_RIP];

    // Check thread-local context
    if (pc >= tls_ctx.code_start && pc < tls_ctx.code_end && tls_ctx.recovery_addr != 0) {
        // Encode faulting address in the lower 56 bits of RAX
        uintptr_t fault_addr = (uintptr_t)info->si_addr;
        ctx->uc_mcontext.gregs[JIT_REG_RAX] = 0x8200000000000000ULL | (fault_addr & 0x00FFFFFFFFFFFFFFULL); // PageFault exit (exitType=2) with address
        ctx->uc_mcontext.gregs[JIT_REG_RDX] = 0;
        ctx->uc_mcontext.gregs[JIT_REG_RIP] = tls_ctx.recovery_addr;
        return;
    }

    // Chain to old handler
    struct sigaction *old = (sig == SIGSEGV) ? &old_sigsegv : &old_sigbus;
    if (old->sa_flags & SA_SIGINFO) {
        old->sa_sigaction(sig, info, uctx);
    } else if (old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN) {
        old->sa_handler(sig);
    } else {
        signal(sig, SIG_DFL);
        raise(sig);
    }
}

int jit_install_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = jit_fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, &old_sigsegv) < 0) return -1;
    if (sigaction(SIGBUS, &sa, &old_sigbus) < 0) return -1;
    return 0;
}

void jit_set_region(uintptr_t start, uintptr_t end) {
    tls_ctx.code_start = start;
    tls_ctx.code_end = end;
}

void jit_set_recovery(uintptr_t addr) {
    tls_ctx.recovery_addr = addr;
}

int jit_clear_fault(void) {
    // No longer needed with TLS, but keep for API compatibility
    return 0;
}

// Call JIT code - this is the trampoline from C to JIT
typedef struct { uint64_t exit; uint64_t pc; } jit_result_t;

static inline jit_result_t call_jit(uintptr_t entry, uintptr_t state) {
    jit_result_t r;
    __asm__ volatile(
        "movq %2, %%rdi\n\t"  // state -> RDI (first arg)
        "callq *%1\n\t"       // call entry
        "movq %%rax, %0\n\t"  // exit reason
        : "=r"(r.exit), "=r"(r.pc)
        : "r"(state), "1"(entry)
        : "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "memory", "cc"
    );
    __asm__ volatile("movq %%rdx, %0" : "=r"(r.pc));
    return r;
}
*/
import "C"
import (
	"jam/pkg/pvm/jit/asm"
	"sync"
	"unsafe"
)

var (
	signalHandlerInstalled bool
	signalMutex            sync.Mutex
)

// InstallSignalHandler installs the custom SIGSEGV/SIGBUS handler for JIT faults
func InstallSignalHandler() error {
	signalMutex.Lock()
	defer signalMutex.Unlock()

	if signalHandlerInstalled {
		return nil
	}

	if C.jit_install_handler() < 0 {
		return ErrSignalHandlerFailed
	}

	signalHandlerInstalled = true
	return nil
}

// SetCodeRegion tells the signal handler the bounds of JIT code
func SetCodeRegion(start, end uintptr) {
	C.jit_set_region(C.uintptr_t(start), C.uintptr_t(end))
}

// SetRecoveryAddr sets the address to jump to on fault
func SetRecoveryAddr(addr uintptr) {
	C.jit_set_recovery(C.uintptr_t(addr))
}

// CheckAndClearFault checks if a fault occurred and clears the flag
func CheckAndClearFault() bool {
	return C.jit_clear_fault() != 0
}

// ErrSignalHandlerFailed is returned when signal handler installation fails
var ErrSignalHandlerFailed = &signalError{"failed to install signal handler"}

type signalError struct {
	msg string
}

func (e *signalError) Error() string {
	return e.msg
}

// callJITCode calls JIT-compiled code with System V AMD64 ABI
// entryPoint: address of compiled code
// statePtr: pointer to State struct (passed in RDI)
// Returns: exitReason (RAX), nextPC (RDX)
func callJITCode(entryPoint uintptr, statePtr unsafe.Pointer) (exitReason uint64, nextPC uint64) {
	// Use pure Go assembly trampoline from asm package to avoid cgo overhead
	return asm.CallJITCode(entryPoint, uintptr(statePtr))
}
