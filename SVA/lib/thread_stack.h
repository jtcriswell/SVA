/*===- thread_stack.h - SVA Execution Engine ------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file functions for SVA code to use to access the thread stack.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_LIB_THREAD_STACK_H_
#define _SVA_LIB_THREAD_STACK_H_

#include "sva/state.h"
#include <stdint.h>

extern void init_threads(void);
extern struct SVAThread * findNextFreeThread (void);
extern void ftstack_push(struct SVAThread *thread);
extern struct SVAThread * validateThreadPointer(uintptr_t p);

#endif /* _SVA_LIB_THREAD_STACK_H_ */
