#ifndef GDBSTUB_PT_H
#define GDBSTUB_PT_H

#include "qemu/osdep.h"

#ifdef CONFIG_LINUX
void gdb_pt_register(void);
bool gdb_pt_is_available(void);
void gdb_pt_cleanup_all(void);
#else
static inline void gdb_pt_register(void) { }
static inline bool gdb_pt_is_available(void) { return false; }
static inline void gdb_pt_cleanup_all(void) { }
#endif

#endif
