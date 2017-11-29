/*===- config.h - SVA Utilities --------------------------------------------===
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

#ifndef _SVA_CONFIG_H
#define _SVA_CONFIG_H

#include <limits.h>
#include <sva/asmconfig.h>

/* Determine whether the virtual ghost features are enabled */
#ifdef VG
static const unsigned char vg = 1;
#else
static const unsigned char vg = 0;
#endif

/* Determine whether the randomized Ghost Memory allocation is enabled */
#ifdef VG_RANDOM
static const unsigned char vg_random = 1;
#else
static const unsigned char vg_random = 0;
#endif

/* Enable or Disable the use of MPX */
#ifdef MPX
static const unsigned char usempx = 1;
#else
static const unsigned char usempx = 0;
#endif

/* Enable or Disable the use of page table side-channel defenses*/
#ifdef SVA_PG_DEF
static const unsigned char pgdef = 1;
#else
static const unsigned char pgdef = 0;
#endif

/* Configure whether to use the hack that keeps page tables writeable */
static unsigned char keepPTWriteableHack = 1;

/* Enable/Disable MMU checks */
#ifdef CHECKMMU
static unsigned char disableMMUChecks = 0;
#else
static unsigned char disableMMUChecks = 1;
#endif

/* Enable copying of the Interrupt Context to Trapframe for Debugging */
static unsigned char copyICToTrapFrame = 0;

/* Total number of processors supported by this SVA Execution Engine */
static const unsigned int numProcessors=2;

/* Structure for describing processors */
struct procMap {
  unsigned char allocated;
  unsigned int apicID;
};

/*
 * Function: getProcessorID()
 *
 * Description:
 *  Determine the processor ID of the current processor.
 *
 * Inputs:
 *  None.
 *
 * Return value:
 *  An index value less than numProcessors that can be used to index into
 *  per-CPU SVA data structures.
 */
static unsigned int
getProcessorID() {
  /* Map logical processor ID to an array in the SVA data structures */
  extern struct procMap svaProcMap[numProcessors];

  /*
   * Use the CPUID instruction to get a local APIC2 ID for the processor.
   */
  unsigned int apicID;
  __asm__ __volatile__ ("movl $0xB, %%eax\ncpuid" : "=d" (apicID));

  /*
   * Convert the APIC2 ID into an SVA logical processor ID.
   */
  for (unsigned index = 0; index < numProcessors; ++index) {
    if ((svaProcMap[index].apicID == apicID) && (svaProcMap[index].allocated))
      return index;
  }

  return UINT_MAX;
}

#endif
