/*===- icat.h - SVA Execution Engine Assembly ------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the Rochester Security Group and is distributed
 * under the University of Illinois Open Source License. See LICENSE.TXT for
 * details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file defines constants that SVA uses for configuring the Intel Cache
 * Allocation Technology (Intel CAT) feature.
 *
 * This file is designed to be used by both assembly and C code.
 *
 *===----------------------------------------------------------------------===
 */

/* Intel CAT MSR */
#define COS_MSR 0xc8f

/* Cache Partitions used by SVA */
#define APP_COS 0
#define OS_COS  1
#define SVA_COS 2
