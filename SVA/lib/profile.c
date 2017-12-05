/*===- profile.c - SVA Execution Engine Assembly ---------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the Rochester Security Group and is distributed
 * under the University of Illinois Open Source License. See LICENSE.TXT for
 * details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file provides functions that profile the time spent in different
 * SVA-OS intrinsics.
 *
 *===----------------------------------------------------------------------===
 */


#include <sys/types.h>

#include <sva/util.h>

/* Global variables used for profiling */
unsigned tsc_read_enable = 0;
unsigned tsc_read_enable_sva = 0;
uint64_t sva_tsc_val[SVA_API_NUM];
uint64_t sva_call_freq[SVA_API_NUM];
uint64_t wp_num;
uint64_t as_num;

