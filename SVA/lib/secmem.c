/*===- secmem.h - SVA Execution Engine  =------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements the new secure memory feature of SVA.
 *
 *===----------------------------------------------------------------------===
 */

#include <string.h>

#include <sys/types.h>

#include "sva/config.h"
#include "sva/callbacks.h"
#include "sva/mmu.h"
#include "sva/state.h"
#include "sva/util.h"

/* Size of frame cache queue */
#define FRAME_CACHE_SIZE 4096

/*
 * Maximum number of frames per allocation or deallocation,
 * if not randomly.
 */
#define MAX_FRAMES_PER_OP 32

extern u_long random(void);

/* Frame cache queue */
static uintptr_t frame_cache[FRAME_CACHE_SIZE];

/* Front and rear of frame cache queue */
static int frame_cache_st = 0;
static int frame_cache_ed = 0;

/*
 * Internal frame cache queue operations, should not be called anywhere
 * else except in alloc_frame() and free_frame().
 */
static inline int frame_cache_used(void);
static inline int frame_cache_full(void);
static inline int frame_cache_empty(void);
static inline void frame_enqueue(uintptr_t paddr);
static inline uintptr_t frame_dequeue(void);
static inline void fill_in_frames(void);
static inline void release_frames(void);

/*
 * Function: frame_cache_used()
 *
 * Description:
 *  Return the number of frames currently in the frame cache.
 */
static inline int
frame_cache_used(void) {
  return (frame_cache_ed - frame_cache_st + FRAME_CACHE_SIZE) % FRAME_CACHE_SIZE;
}

/*
 * Function: frame_cache_full()
 *
 * Description:
 *  Determine if the frame cache queue is full.
 */
static inline int
frame_cache_full(void) {
  return frame_cache_used() == FRAME_CACHE_SIZE - 1;
}

/*
 * Function: frame_cache_empty()
 *
 * Description:
 *  Determine if the frame cache queue is empty.
 */
static inline int
frame_cache_empty(void) {
  return frame_cache_used() == 0;
}

/*
 * Function: frame_enqueue()
 *
 * Description:
 *  Enqueue a frame into the frame cache queue.
 *
 * Input:
 *  paddr - The physical address of the frame to enqueue
 */
static inline void
frame_enqueue(uintptr_t paddr) {
  /* If our cache is full, release some frames */
  if (frame_cache_full()) {
    release_frames();
  }

  frame_cache[frame_cache_ed] = paddr;
  frame_cache_ed = (frame_cache_ed + 1) % FRAME_CACHE_SIZE;
}

/*
 * Function: frame_dequeue()
 *
 * Description:
 *  Dequeue a frame out of the frame cache queue.
 */
static inline uintptr_t
frame_dequeue(void) {
  uintptr_t paddr = 0;

  /* If we don't have any frames in cache, grab some */
  if (frame_cache_empty()) {
    fill_in_frames();
  }

  paddr = frame_cache[frame_cache_st];
  frame_cache[frame_cache_st] = 0;
  frame_cache_st = (frame_cache_st + 1) % FRAME_CACHE_SIZE;

  return paddr;
}

/*
 * Function: fill_in_frames()
 *
 * Description:
 *  Allocate some number of frames and put them into the frame cache
 *  queue.
 */
static inline void
fill_in_frames(void) {
  int i, max_nframe, nframe;
  uintptr_t paddr;

  /*
   * Generate a suitable number not so big that triggers
   * release_frames() when calling frame_enqueue().
   */
  max_nframe = FRAME_CACHE_SIZE - 1 - frame_cache_used();
  if (vg_random) {
    /* A random number between 1 and current capacity of frame cache queue */
    nframe = random() % max_nframe + 1;
  } else {
    /* Minimum of a constant and current capacity of frame cache queue */
    nframe = max_nframe < MAX_FRAMES_PER_OP ? max_nframe : MAX_FRAMES_PER_OP;
  }

  for (i = 0; i < nframe; ++i) {
    paddr = provideSVAMemory(X86_PAGE_SIZE);
    frame_enqueue(paddr);
  }
}

/*
 * Function: release_frames()
 *
 * Description:
 *  Dequeue and free some number of frames in the frame cache queue.
 */
static inline void
release_frames(void) {
  int i, max_nframe, nframe;
  uintptr_t paddr;

  /*
   * Generate a suitable number not so big that triggers
   * fill_in_frames() when calling frame_dequeue().
   */
  max_nframe = frame_cache_used();
  if (vg_random) {
    /* A random number between 1 and current occupancy of frame cache queue */
    nframe = random() % max_nframe + 1;
  } else {
    /* Minimum of a constant and current occupancy of frame cache queue */
    nframe = max_nframe < MAX_FRAMES_PER_OP ? max_nframe : MAX_FRAMES_PER_OP;
  }

  for (i = 0; i < nframe; ++i) {
    paddr = frame_dequeue();
    releaseSVAMemory(paddr, X86_PAGE_SIZE);
  }
}

/*
 * Function: alloc_frame()
 *
 * Description:
 *  The front end function for allocating a physical frame.
 */
uintptr_t
alloc_frame(void) {
  return frame_dequeue();
}

/*
 * Function: free_frame()
 *
 * Description:
 *  The front end function for freeing a physical frame.
 */
void
free_frame(uintptr_t paddr) {
  frame_enqueue(paddr);
}

/*
 * Function: getNextSecureAddress()
 *
 * Description:
 *  Find the next available address in the secure virtual address space.
 *
 * Inputs:
 *  threadp - The thread for which to allocate more ghost memory.
 *  size    - The size of memory to allocate in bytes.
 */
static inline unsigned char *
getNextSecureAddress (struct SVAThread * threadp, uintptr_t size) {
  /* Start of virtual address space used for secure memory */
  unsigned char * secmemStartp = (unsigned char *) SECMEMSTART;

  /* Secure memory address to return */
  unsigned char * secmemp = secmemStartp + threadp->secmemSize;

  /*
   * Advance the address by a single page frame and return the value before
   * increment.
   */
  threadp->secmemSize += size;
  return secmemp;
}

/*
 * Function: ghostMalloc()
 *
 * Description:
 *  Allocate ghost memory.
 */
unsigned char *
ghostMalloc (intptr_t size) {
  /* Physical address of allocated secure memory pointer */
  uintptr_t sp;

  /* Virtual address assigned to secure memory by SVA */
  unsigned char * vaddrStart = 0;

  /* The address of the PML4e page table */
  pml4e_t pml4e = 0;

  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;

  /*
   * Determine if this is the first secure memory allocation.
   */
  unsigned char firstSecAlloc = (threadp->secmemSize == 0);

  /*
   * Determine where this ghost memory will be allocated and update the size
   * of the ghost memory.
   */
  unsigned char * vaddr = vaddrStart = getNextSecureAddress (threadp, size);

  /*
   * Get a page of memory from the operating system.  Note that the OS provides
   * the physical address of the allocated memory.
   */
  for (intptr_t remaining = size; remaining > 0; remaining -= X86_PAGE_SIZE) {
    if ((sp = alloc_frame()) != 0) {
      /* Physical address of the allocated page */
      uintptr_t paddr = sp;

      /*
       * Map the memory into a part of the address space reserved for secure
       * memory.
       */
      pml4e = mapSecurePage ((uintptr_t)vaddr, paddr);

      /*
       * If this is the first piece of secure memory that we've allocated,
       * record the address of the top-level page table that maps in the secure
       * memory region.  The context switching intrinsics will want to know
       * where this entry is so that it can quickly enable and disable it on
       * context switches.
       */
      if (firstSecAlloc) {
        threadp->secmemPML4e = pml4e;
      }

      /*
       * Move to the next virtual address.
       */
      vaddr += X86_PAGE_SIZE;
    } else {
      panic ("SVA: Kernel secure memory allocation failed!\n");
    }
  }

  /* Return a pointer to the allocated ghost memory */
  return vaddrStart;
}

/*
 * Function: allocSecureMemory()
 *
 * Description:
 *  Allocate secure memory.  Fetch it from the operating system kernel if
 *  necessary.
 *
 * Inputs:
 *  size - The amount of secure memory to allocate measured in bytes.
 *
 * Return value:
 *  A pointer to the first byte of the secure memory.
 */
unsigned char *
allocSecureMemory (void) {
  /*
   * Get the number of bytes to allocate.  This is stored in the %rdi register
   * of the interrupted program state.
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * icp = cpup->newCurrentIC;
  intptr_t size = icp->rdi;

  /*
   * Check that the size is positive.
   */
  if (size < 0)
    return 0;

  /*
   * If we have already allocated ghost memory, then merely extend the size of
   * of the ghost partition and let the ghost memory be demand paged into
   * memory.  Otherwise, allocate some ghost memory just to make adding the
   * demand-paged ghost memory easier.
   */
  unsigned char * vaddrStart = 0;
  struct SVAThread * threadp = cpup->currentThread;
  if (threadp->secmemSize && !pgdef) {
    /*
     * Pretend to allocate more ghost memory (but let demand paging actually
     * map it in.
     */
    vaddrStart = getNextSecureAddress (threadp, size);
  } else {
    /*
     * Call the ghost memory allocator to allocate some ghost memory.
     */
    vaddrStart = ghostMalloc (size);

    /*
     * Zero out the memory.
     */
    memset (vaddrStart, 0, size);
  }
  /*
   * Set the return value in the Interrupt Context to be a pointer to the
   * newly allocated memory.
   */
  icp->rax = (uintptr_t) vaddrStart;

  /*
   * Return the first address of the newly available ghost memory.
   */
  return vaddrStart;
}

/*
 * Function: ghostFree()
 *
 * Description:
 *  Free the physical frames backing ghost memory at the specified virtual
 *  address.  This function frees entire frames and returns the physical memory
 *  to the operating system kernel.
 *
 *  Note that this function may be called upon to unmap ghost memory from a
 *  thread *other* than the one currently running on the CPU.
 *
 * Inputs:
 *  threadp - A pointer to the SVA Thread for which we should release the frame
 *            of secure memory.
 *  p        - A pointer to the virtual address of the ghost memory to free.
 *  size     - The amount of ghost memory in bytes to free.
 *
 */
void
ghostFree (struct SVAThread * threadp, unsigned char * p, intptr_t size) {
  /* Per-CPU data structure maintained by SVA */
  struct CPUState * cpup;

  /* Pointer to thread currently executing on the CPU */
  struct SVAThread * currentThread;

  /*
   * If the amount of memory to free is zero, do nothing.
   */
  if (size == 0) {
    return;
  }

  /*
   * Get a pointer to the thread currently running on the CPU.
   */
  cpup = getCPUState();
  currentThread = cpup->currentThread;

  /*
   * Get the PML4E entry for the Ghost Memory for the thread.
   */
  pml4e_t * secmemPML4Ep = &(threadp->secmemPML4e);

  /*
   * Verify that the memory is within the secure memory portion of the
   * address space.
   */
  uintptr_t pint = (uintptr_t) p;
  if ((SECMEMSTART <= pint) && (pint < SECMEMEND) &&
     (SECMEMSTART <= (pint + size)) && ((pint + size) < SECMEMEND)) {
    /*
     * Loop through each page of the ghost memory until all of the frames
     * have been returned to the operating system kernel.
     */
    for (unsigned char * ptr = p; ptr < (p + size); ptr += X86_PAGE_SIZE) {
      /*
       * Get the physical address before unmapping the page.  We do this
       * because unmapping the page may remove page table pages that are no
       * longer needed for mapping secure pages.
       */
      uintptr_t paddr;
      if (getPhysicalAddrFromPML4E (ptr, secmemPML4Ep, &paddr)) {
        
        /*
         * Unmap the memory from the secure memory virtual address space.
         */
        unmapSecurePage (threadp, ptr);

        /*
         * Release the memory to the operating system.  Note that we must first
         * get the physical address of the data page as that is what the OS is
         * expecting.
         *
         * TODO:
         *  This code works around a limitation in the releaseSVAMemory()
         *  implementation in which it only releases one page at a time to the
         *  OS.
         */
        if (getPageDescPtr(paddr)->count == 0) {
          /*
           * Zero out the contents of the ghost memory.
           */
          if (threadp == currentThread) {
#ifdef SVA_DMAP
            unsigned char * dmapAddr = getVirtualSVADMAP (paddr);
            memset (dmapAddr, 0, X86_PAGE_SIZE);
#else
            memset (ptr, 0, X86_PAGE_SIZE);
#endif
          }
          free_frame(paddr);
        }
      }
    }
  }

  return;
}

/*
 * Function: freeSecureMemory()
 *
 * Description:
 *  Free a single page of secure memory.
 *
 * Inputs:
 *  p    - The first virtual address of the secure memory to free.
 *  size - The amount of secure memory to allocate measured in bytes.
 *
 */
void
freeSecureMemory (void) {
  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  sva_icontext_t * icp = getCPUState()->newCurrentIC;

  /*
   * Get the pointer address and size out of the interrupt context.
   */
  unsigned char * p = (unsigned char *)(icp->rdi);
  uintptr_t size = icp->rsi;

  /* Free the ghost memory */
  struct CPUState * cpup = getCPUState();
  ghostFree (cpup->currentThread, p, size);

  return;
}

void
sva_ghost_fault (uintptr_t vaddr, unsigned long code) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /* Old interrupt flags */
  uintptr_t rflags;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /* Physical address of allocated secure memory pointer */
  uintptr_t sp;

  /* The address of the PML4e page table */
  pml4e_t pml4e;

  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;

  /* copy-on-write page fault */
  if ((code & PGEX_P) && (code & PGEX_W)){
     pml4e_t * pml4e_ptr = get_pml4eVaddr (get_pagetable(), vaddr);
     if(!isPresent (pml4e_ptr)) 
        panic("sva_ghost_fault: cow pgfault pml4e %p does not exist\n", pml4e);
     pdpte_t * pdpte = get_pdpteVaddr (pml4e_ptr, vaddr);
     if(!isPresent (pdpte)) 
        panic("sva_ghost_fault: cow pgfault pdpte %p does not exist\n", pdpte);
     pde_t * pde = get_pdeVaddr (pdpte, vaddr);
     if(!isPresent (pde)) 
        panic("sva_ghost_fault: cow pgfault pde %p does not exist\n", pde);
     pte_t * pte = get_pteVaddr (pde, vaddr);
     uintptr_t paddr = *pte & PG_FRAME;
     page_desc_t * pgDesc = getPageDescPtr (paddr);

     if (pgDesc->type != PG_GHOST)
      panic("SVA: sva_ghost_fault: vaddr = 0x%lx paddr = 0x%lx is not a ghost memory page!\n", vaddr, paddr); 

     /*
      * If only one process maps this page, directly grant this process write
      * permission.  Otherwise, perform a copy-on-write.
      */
#ifndef SVA_DMAP
     unprotect_paging();
#endif
     if (pgDesc->count == 1) {
        * pte = (* pte) | PTE_CANWRITE;
     } else {
#ifdef SVA_DMAP
        uintptr_t vaddr_old = (uintptr_t) getVirtualSVADMAP(paddr);
#else
        uintptr_t vaddr_old = (uintptr_t) getVirtual(paddr);
#endif
        uintptr_t paddr_new = alloc_frame();
        page_desc_t * pgDesc_new = getPageDescPtr (paddr_new);
        if (pgRefCount (pgDesc_new) > 1) {
                panic ("SVA: Ghost page still in use somewhere else!\n");
        }
        if (isPTP(pgDesc_new) || isCodePG (pgDesc_new)) {
                panic ("SVA: Ghost page has wrong type!\n");
        }

        memcpy(getVirtualSVADMAP(paddr_new), (void *) vaddr_old, X86_PAGE_SIZE);   
        *pte = (paddr_new & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
        invlpg(vaddr);
       
        getPageDescPtr (paddr_new)->type = PG_GHOST;
        getPageDescPtr (paddr_new)->count = 1;
        pgDesc->count --;
     }
#ifndef SVA_DMAP 
     protect_paging();
#endif
     return; 
   }

  /*
   * Determine if this is the first secure memory allocation.
   */
  unsigned char firstSecAlloc = (threadp->secmemSize == 0);

  /*
   * Get a page of memory from the operating system.  Note that the OS provides
   * the physical address of the allocated memory.
   */
  if ((sp = alloc_frame()) != 0) {
    /* Physical address of the allocated page */
    uintptr_t paddr = (uintptr_t) sp;

    /*
     * Map the memory into a part of the address space reserved for secure
     * memory.
     */
    pml4e = mapSecurePage ((uintptr_t)vaddr, paddr);

    /*
     * If this is the first piece of secure memory that we've allocated,
     * record the address of the top-level page table that maps in the secure
     * memory region.  The context switching intrinsics will want to know
     * where this entry is so that it can quickly enable and disable it on
     * context switches.
     */
    if (firstSecAlloc) {
      threadp->secmemPML4e = pml4e;
    }
  } else {
    panic ("SVA: Kernel secure memory allocation failed!\n");
  }

  /*
   * Zero out the ghost memory contents.
   */
  memset ((void *)vaddr, 0, X86_PAGE_SIZE);

  /* Re-enable interrupts if necessary */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_ghost_fault_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

