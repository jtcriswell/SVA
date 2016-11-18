/* SVA/include/sva/asmconfig.h.  Generated from asmconfig.h.in by configure.  */
/*===- asmconfig.h - SVA Utilities -----------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header file contains macros that can be used to configure the SVA
 * Execution Engine.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_ASMCONFIG_H
#define _SVA_ASMCONFIG_H

/* Let the configure script determine if we enable Virtual Ghost */
#define VG 1

/* Let the configure script determine if we enable MPX support for SFI */
#define MPX 1

/* Let the configure script determine if we enable SVA MMU Checks */
/* #undef CHECKMMU */

#endif
