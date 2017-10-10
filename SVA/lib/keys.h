/*===- keys.h - SVA Execution Engine Assembly ---------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file contains internal functions for SVA code to use to access vg key
 * functions.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_LIB_KEYS_H_
#define _SVA_LIB_KEYS_H_

#include "sva/state.h"

extern void init_thread_key (struct SVAThread * thread);



#endif /* _SVA_LIB_KEYS_H_ */
