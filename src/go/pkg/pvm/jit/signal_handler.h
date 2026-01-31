#ifndef JIT_SIGNAL_HANDLER_H
#define JIT_SIGNAL_HANDLER_H

#include <stdint.h>

int jit_install_handler(void);
void jit_set_region(uintptr_t start, uintptr_t end);
void jit_set_recovery(uintptr_t addr);
int jit_clear_fault(void);

#endif
