/*===- mmu.c - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * Note: We try to use the term "frame" to refer to a page of physical memory
 *       and a "page" to refer to the virtual addresses mapped to the page of
 *       physical memory.
 *
 *===----------------------------------------------------------------------===
 */

#include <string.h>

#include <sys/types.h>

#include "icat.h"

#include "sva/callbacks.h"
#include "sva/config.h"
#include "sva/mmu.h"
#include "sva/mmu_intrinsics.h"
#include "sva/x86.h"
#include "sva/state.h"
#include "sva/util.h"

/* 
 * Defines for #if #endif blocks for commenting out lines of code
 */
/* Used to denote unimplemented code */
#define NOT_YET_IMPLEMENTED 0   

/* Used to denote obsolete code that hasn't been deleted yet */
#define OBSOLETE            0   

/* Define whether to enable DEBUG blocks #if statements */
#define DEBUG               0

/* Define whether or not the mmu_init code assumes virtual addresses */
#define USE_VIRT            0

/*
 *****************************************************************************
 * Function prototype declarations.
 *****************************************************************************
 */

/*
 * SVA direct mapping related functions
 */
static inline uintptr_t getPhysicalAddrKDMAP (void * v);
static inline uintptr_t getPhysicalAddrSVADMAP (void * v);

/* 
 * Function prototypes for finding the virtual address of page table components
 */
static inline page_entry_t * get_pgeVaddr (uintptr_t vaddr);

/*
 * Mapping update function prototypes.
 */
static inline void __update_mapping (pte_t * pageEntryPtr, page_entry_t val);

/*
 *****************************************************************************
 * Define paging structures and related constants local to this source file
 *****************************************************************************
 */

/* Flags whether the MMU has been initialized */
static unsigned char mmuIsInitialized = 0;

/*
 * Struct: PTInfo
 *
 * Description:
 *  This structure contains information on pages fetched from the OS that are
 *  used for page table pages that the SVA VM creates for its own purposes
 *  (e.g., secure memory).
 */
struct PTInfo {
  /* Virtual address of page provided by the OS */
  unsigned char * vosaddr;

  /* Physical address to which the virtual address is mapped. */
  uintptr_t paddr;

  /* Number of uses in this page table page */
  unsigned short uses;

  /* Flags whether this entry is used */
  unsigned char valid;
};


/*
 * Structure: PTPages
 *
 * Description:
 *  This table records information on pages fetched from the operating system
 *  that the SVA VM will use for its own purposes.
 */
struct PTInfo PTPages[1024] __attribute__ ((section ("svamem")));

/* Cache of page table pages */
extern unsigned char
SVAPTPages[1024][X86_PAGE_SIZE] __attribute__ ((section ("svamem")));

/* Array describing the physical pages */
/* The index is the physical page number */
page_desc_t page_desc[numPageDescEntries];

/*
 * Description:
 *  Given a page table entry value, return the page description associate with
 *  the frame being addressed in the mapping.
 *
 * Inputs:
 *  mapping: the mapping with the physical address of the referenced frame
 *
 * Return:
 *  Pointer to the page_desc for this frame
 */
page_desc_t * getPageDescPtr(unsigned long mapping) {
  unsigned long frameIndex = (mapping & PG_FRAME) / pageSize;
  if (frameIndex >= numPageDescEntries)
    panic ("SVA: getPageDescPtr: %lx %lx\n", frameIndex, numPageDescEntries);
  return page_desc + frameIndex;
}

void
printPageType (unsigned char * p) {
  printf ("SVA: page type: %p: %x\n", p, getPageDescPtr(getPhysicalAddr(p))->type);
  return;
}


/*
 * Function: init_mmu
 *
 * Description:
 *  Initialize MMU data structures.
 */
void 
init_mmu () {
  /* Initialize the page descriptor array */
  memset (page_desc, 0, sizeof (struct page_desc_t) * numPageDescEntries);
  return;
}



/*
 *****************************************************************************
 * Define helper functions for MMU operations
 *****************************************************************************
 */

/* Functions for aiding in declare and updating of page tables */

/*
 * Function: page_entry_store
 *
 * Description:
 *  This function takes a pointer to a page table entry and updates its value
 *  to the new value provided.
 *
 * Assumptions: 
 *  - This function assumes that write protection is enabled in CR0 (WP bit set
 *    to 1). 
 *
 * Inputs:
 *  *page_entry -: A pointer to the page entry to store the new value to, a
 *                 valid VA for accessing the page_entry.
 *  newVal      -: The new value to store, including the address of the
 *                 referenced page.
 *
 * Side Effect:
 *  - This function enables system wide write protection in CR0. 
 *    
 *
 */
static inline void
page_entry_store (unsigned long *page_entry, page_entry_t newVal) {
  uint64_t tsc_tmp; 
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

#ifdef SVA_DMAP
  uintptr_t phys;
  unsigned long* page_entry_svadm;
  page_desc_t * pgDescPtr; 

  phys = getPhysicalAddr(page_entry);
  page_entry_svadm = (unsigned long*)getVirtualSVADMAP(phys);
  //printf("page_entry = 0x%lx, page_entry_svadm = 0x%lx\n", page_entry, page_entry_svadm);  
  pgDescPtr = getPageDescPtr(phys);

  if(pgDescPtr->dmap)
  {
	newVal |= PG_RW;
  }

    
  /* Write the new value to the page_entry */
  *page_entry_svadm = newVal;

#else
  /* Disable page protection so we can write to the referencing table entry */
  unprotect_paging();
  
  /* Write the new value to the page_entry */
  *page_entry = newVal;

  /* Reenable page protection */
  protect_paging();    
#endif

    record_tsc(page_entry_store_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

/*
 *****************************************************************************
 * Page table page index and entry lookups 
 *****************************************************************************
 */

/*
 * Function: pt_update_is_valid()
 *
 * Description:
 *  This function assesses a potential page table update for a valid mapping.
 *
 *  NOTE: This function assumes that the page being mapped in has already been
 *  declared and has its intial page metadata captured as defined in the
 *  initial mapping of the page.
 *
 * Inputs:
 *  *page_entry  - VA pointer to the page entry being modified
 *  newVal       - Representes the new value to write including the reference
 *                 to the underlying mapping.
 *
 * Return:
 *  0  - The update is not valid and should not be performed.
 *  1  - The update is valid but should disable write access.
 *  2  - The update is valid and can be performed.
 */
static inline unsigned char
pt_update_is_valid (page_entry_t *page_entry, page_entry_t newVal) {
  /* Collect associated information for the existing mapping */
  unsigned long origPA = *page_entry & PG_FRAME;
  unsigned long origFrame = origPA >> PAGESHIFT;
  uintptr_t origVA = (uintptr_t) getVirtual(origPA);
  page_desc_t *origPG = &page_desc[origFrame];

  /* Get associated information for the new page being mapped */
  unsigned long newPA = newVal & PG_FRAME;
  unsigned long newFrame = newPA >> PAGESHIFT;
  uintptr_t newVA = (uintptr_t) getVirtual(newPA);
  page_desc_t *newPG = &page_desc[newFrame];

  /* Get the page table page descriptor. The page_entry is the viratu */
  uintptr_t ptePAddr = getPhysicalAddr (page_entry);
  page_desc_t *ptePG = getPageDescPtr(ptePAddr);

  /* Return value */
  unsigned char retValue = 2;

  /*
   * If MMU checks are disabled, allow the page table entry to be modified.
   */
  if (disableMMUChecks)
    return retValue;

  /*
   * Determine if the page table pointer is within the direct map.  If not,
   * then it's an error.
   *
   * TODO: This check can cause a panic because the SVA VM does not set
   *       up the direct map before starting the kernel.  As a result, we get
   *       page table addresses that don't fall into the direct map.
   */
  SVA_NOOP_ASSERT (isDirectMap (page_entry), "SVA: MMU: Not direct map\n");

  /*
   * Verify that we're not trying to modify the PML4E entry that controls the
   * ghost address space.
   */
  if (vg) {
    if ((ptePG->type == PG_L4) && ((ptePAddr & PG_FRAME) == secmemOffset)) {
      panic ("SVA: MMU: Trying to modify ghost memory pml4e!\n");
    }
  }

  /*
   * Verify that we're not modifying any of the page tables that control
   * the ghost virtual address space.  Ensuring that the page that we're
   * writing into isn't a ghost page table (along with the previous check)
   * should suffice.
   */
  if (vg) {
    SVA_ASSERT (!isGhostPTP(ptePG), "SVA: MMU: Kernel modifying ghost memory!\n");
  }

  /*
   * Add check that the direct map is not being modified.
   */
  if ((PG_DML1 <= ptePG->type) && (ptePG->type <= PG_DML4)) {
    panic ("SVA: MMU: Modifying direct map!\n");
  }

  /* 
   * If we aren't mapping a new page then we can skip several checks, and in
   * some cases we must, otherwise, the checks will fail. For example if this
   * is a mapping in a page table page then we allow a zero mapping. 
   */
  if (newVal & PG_V) {
    /*
     * If the new mapping references a secure memory page, then silently
     * ignore the request.  This reduces porting effort because the kernel
     * can try to map a ghost page, and the mapping will just never happen.
     */
    if (vg && isGhostPG(newPG)) {
      return 0;
    }

    /* If the new mapping references a secure memory page fail */
    if (vg) SVA_ASSERT (!isGhostPTP(newPG), "MMU: Kernel mapping a ghost PTP");

    /* If the mapping is to an SVA page then fail */
    SVA_ASSERT (!isSVAPg(newPG), "Kernel attempted to map an SVA page");

    /*
     * New mappings to code pages are permitted as long as they are either
     * for user-space pages or do not permit write access.
     */
    if (isCodePg (newPG)) {
      if ((newVal & (PG_RW | PG_U)) == (PG_RW)) {
        panic ("SVA: Making kernel code writeable: %lx %lx\n", newVA, newVal);
      }
    }

    /* 
     * If the new page is a page table page, then we verify some page table
     * page specific checks. 
     */
    if (isPTP(newPG)) {
      /* 
       * If we have a page table page being mapped in and it currently
       * has a mapping to it, then we verify that the new VA from the new
       * mapping matches the existing currently mapped VA.   
       *
       * This guarantees that we each page table page (and the translations
       * within it) maps a singular region of the address space.
       *
       * Otherwise, this is the first mapping of the page, and we should record
       * in what virtual address it is being placed.
       */
#if 0
      if (pgRefCount(newPG) > 1) {
        if (newPG->pgVaddr != page_entry) {
          panic ("SVA: PG: %lx %lx: type=%x\n", newPG->pgVaddr, page_entry, newPG->type);
        }
        SVA_ASSERT (newPG->pgVaddr == page_entry, "MMU: Map PTP to second VA");
      } else {
        newPG->pgVaddr = page_entry;
      }
#endif
    }

    /*
     * Verify that that the mapping matches the correct type of page
     * allowed to be mapped into this page table. Verify that the new
     * PTP is of the correct type given the page level of the page
     * entry. 
     */
    switch (ptePG->type) {
      case PG_L1:
        if (!isFramePg(newPG)) {
          /* If it is a ghost frame, stop with an error */
          if (vg && isGhostPG (newPG)) panic ("SVA: MMU: Mapping ghost page!\n");

          /*
           * If it is a page table page, just ensure that it is not writeable.
           * The kernel may be modifying the direct map, and we will permit
           * that as long as it doesn't make page tables writeable.
           *
           * Note: The SVA VM really should have its own direct map that the
           *       kernel cannot use or modify, but that is too much work, so
           *       we make this compromise.
           */
          if ((newPG->type >= PG_L1) && (newPG->type <= PG_L4)) {
            retValue = 1;
          } else {
            panic ("SVA: MMU: Map bad page type into L1: %x\n", newPG->type);
          }
        }

        break;

      case PG_L2:
        if (newVal & PG_PS) {
          if (!isFramePg(newPG)) {
            /* If it is a ghost frame, stop with an error */
            if (vg && isGhostPG (newPG)) panic ("SVA: MMU: Mapping ghost page!\n");

            /*
             * If it is a page table page, just ensure that it is not writeable.
             * The kernel may be modifying the direct map, and we will permit
             * that as long as it doesn't make page tables writeable.
             *
             * Note: The SVA VM really should have its own direct map that the
             *       kernel cannot use or modify, but that is too much work, so
             *       we make this compromise.
             */
            if ((newPG->type >= PG_L1) && (newPG->type <= PG_L4)) {
              retValue = 1;
            } else {
              panic ("SVA: MMU: Map bad page type into L2: %x\n", newPG->type);
            }
          }
        } else {
          SVA_ASSERT (isL1Pg(newPG), "MMU: Mapping non-L1 page into L2.");
        }
        break;

      case PG_L3:
        if (newVal & PG_PS) {
          if (!isFramePg(newPG)) {
            /* If it is a ghost frame, stop with an error */
            if (vg && isGhostPG (newPG)) panic ("SVA: MMU: Mapping ghost page!\n");

            /*
             * If it is a page table page, just ensure that it is not writeable.
             * The kernel may be modifying the direct map, and we will permit
             * that as long as it doesn't make page tables writeable.
             *
             * Note: The SVA VM really should have its own direct map that the
             *       kernel cannot use or modify, but that is too much work, so
             *       we make this compromise.
             */
            if ((newPG->type >= PG_L1) && (newPG->type <= PG_L4)) {
              retValue = 1;
            } else {
              panic ("SVA: MMU: Map bad page type into L2: %x\n", newPG->type);
            }
          }
        } else {
          SVA_ASSERT (isL2Pg(newPG), "MMU: Mapping non-L2 page into L3.");
        }
        break;

      case PG_L4:
        /* 
         * FreeBSD inserts a self mapping into the pml4, therefore it is
         * valid to map in an L4 page into the L4.
         *
         * TODO: Consider the security implications of allowing an L4 to map
         *       an L4.
         */
        SVA_ASSERT (isL3Pg(newPG) || isL4Pg(newPG), 
                    "MMU: Mapping non-L3/L4 page into L4.");
        break;

      default:
        break;
    }
  }

  if(isCodePg (newPG)) {
    retValue = 1;
  }

  /*
   * If the new mapping is set for user access, but the VA being used is to
   * kernel space, fail. Also capture in this check is if the new mapping is
   * set for super user access, but the VA being used is to user space, fail.
   *
   * 3 things to assess for matches: 
   *  - U/S Flag of new mapping
   *  - Type of the new mapping frame
   *  - Type of the PTE frame
   * 
   * Ensures the new mapping U/S flag matches the PT page frame type and the
   * mapped in frame's page type, as well as no mapping kernel code pages
   * into userspace.
   */
  
  /* 
   * If the original PA is not equivalent to the new PA then we are creating
   * an entirely new mapping, thus make sure that this is a valid new page
   * reference. Also verify that the reference counts to the old page are
   * sane, i.e., there is at least a current count of 1 to it. 
   */
  if (origPA != newPA) {
    /* 
     * If the old mapping was to a code page then we know we shouldn't be
     * pointing this entry to another code page, thus fail.
     */
    if (isCodePg (origPG)) {
      SVA_ASSERT ((*page_entry & PG_U),
                  "Kernel attempting to modify code page mapping");
    }
  }

  return retValue;
}

/*
 * Function: updateNewPageData
 *
 * Description: 
 *  This function is called whenever we are inserting a new mapping into a page
 *  entry. The goal is to manage any SVA page data that needs to be set for
 *  tracking the new mapping with the existing page data. This is essential to
 *  enable the MMU verification checks.
 *
 * Inputs:
 *  mapping - The new mapping to be inserted in x86_64 page table format.
 */
static inline void
updateNewPageData(page_entry_t mapping) {
  uintptr_t newPA = mapping & PG_FRAME;
  unsigned long newFrame = newPA >> PAGESHIFT;
  uintptr_t newVA = (uintptr_t) getVirtual(newPA);
  page_desc_t *newPG = getPageDescPtr(mapping);

  /*
   * If the new mapping is valid, update the counts for it.
   */
  if (mapping & PG_V) {
#if 0
    /*
     * If the new page is to a page table page and this is the first reference
     * to the page, we need to set the VA mapping this page so that the
     * verification routine can enforce that this page is only mapped
     * to a single VA. Note that if we have gotten here, we know that
     * we currently do not have a mapping to this page already, which
     * means this is the first mapping to the page. 
     */
    if (isPTP(newPG)) {
      newPG->pgVaddr = newVA;
    }
#endif

    /* 
     * Update the reference count for the new page frame. Check that we aren't
     * overflowing the counter.
     */
    SVA_ASSERT (pgRefCount(newPG) < ((1u << 13) - 1), 
                "MMU: overflow for the mapping count");
    newPG->count++;

    /* 
     * Set the VA of this entry if it is the first mapping to a page
     * table page.
     */
  }

  return;
}

/*
 * Function: updateOrigPageData
 *
 * Description:
 *  This function updates the metadata for a page that is being removed from
 *  the mapping. 
 * 
 * Inputs:
 *  mapping - An x86_64 page table entry describing the old mapping of the page
 */
static inline void
updateOrigPageData(page_entry_t mapping) {
  uintptr_t origPA = mapping & PG_FRAME; 
  unsigned long origFrame = origPA >> PAGESHIFT;
  page_desc_t *origPG = &page_desc[origFrame];

  /* 
   * Only decrement the mapping count if the page has an existing valid
   * mapping.  Ensure that we don't drop the reference count below zero.
   */
  if ((mapping & PG_V) && (origPG->count)) {
    --(origPG->count);
    if(origPG->count == 1)
    {
	invltlb_all();
    }
  }

  return;
}

/*
 * Function: __do_mmu_update
 *
 * Description:
 *  If the update has been validated, this function manages metadata by
 *  updating the internal SVA reference counts for pages and then performs the
 *  actual update. 
 *
 * Inputs: 
 *  *page_entry  - VA pointer to the page entry being modified 
 *  newVal       - Representes the mapping to insert into the page_entry
 */
static inline void
__do_mmu_update (pte_t * pteptr, page_entry_t mapping) {
  uintptr_t origPA = *pteptr & PG_FRAME;
  uintptr_t newPA = mapping & PG_FRAME;

  /*
   * If we have a new mapping as opposed to just changing the flags of an
   * existing mapping, then update the SVA meta data for the pages. We know
   * that we have passed the validation checks so these updates have been
   * vetted.
   */
  if (newPA != origPA) {
    updateOrigPageData(*pteptr);
    updateNewPageData(mapping);
  } else if ((*pteptr & PG_V) && ((mapping & PG_V) == 0)) {
    /*
     * If the old mapping is marked valid but the new mapping is not, then
     * decrement the reference count of the old page.
     */
    updateOrigPageData(*pteptr);
  } else if (((*pteptr & PG_V) == 0) && (mapping & PG_V)) {
    /*
     * Contrariwise, if the old mapping is invalid but the new mapping is valid,
     * then increment the reference count of the new page.
     */
    updateNewPageData(mapping);
  }

  /* Perform the actual write to into the page table entry */
  page_entry_store ((page_entry_t *) pteptr, mapping);
  return;
}

/*
 * Function: initDeclaredPage
 *
 * Description:
 *  This function zeros out the physical page pointed to by frameAddr and
 *  changes the permissions of the page in the direct map to read-only.
 *  This function is agnostic as to which level page table entry we are
 *  modifying because the format of the entry is the same in all cases. 
 *
 * Assumption: This function should only be called by a declare intrinsic.
 *      Otherwise it has side effects that may break the system.
 *
 * Inputs:
 *  frameAddr: represents the physical address of this frame
 *
 *  *page_entry: A pointer to a page table entry that will be used to
 *      initialize the mapping to this newly created page as read only. Note
 *      that the address of the page_entry must be a virtually accessible
 *      address.
 */
static inline void 
initDeclaredPage (unsigned long frameAddr) {
  /*
   * Get the direct map virtual address of the physical address.
   */
  unsigned char * vaddr = getVirtual (frameAddr);

  /*
   * Initialize the contents of the page to zero.  This will ensure that no
   * existing page translations which have not been vetted exist within the
   * page.
   */
  memset (vaddr, 0, X86_PAGE_SIZE);

  /*
   * Get a pointer to the page table entry that maps the physical page into the
   * direct map.
   */
  page_entry_t * page_entry = get_pgeVaddr ((uintptr_t)vaddr);
  if (page_entry) {
    /*
     * Make the direct map entry for the page read-only to ensure that the OS
     * goes through SVA to make page table changes.  Also be sure to flush the
     * TLBs for the direct map address to ensure that it's made read-only
     * right away.
     */
    if (((*page_entry) & PG_PS) == 0) {
      page_entry_store (page_entry, setMappingReadOnly(*page_entry));
      sva_mm_flush_tlb (vaddr);
    }
  }

  return;
}

/*
 * Function: __update_mapping
 *
 * Description:
 *  Mapping update function that is agnostic to the level of page table. Most
 *  of the verification code is consistent regardless of which level page
 *  update we are doing. 
 *
 * Inputs:
 *  - pageEntryPtr : reference to the page table entry to insert the mapping
 *      into
 *  - val : new entry value
 */
static inline void
__update_mapping (pte_t * pageEntryPtr, page_entry_t val) {
  /* 
   * If the given page update is valid then store the new value to the page
   * table entry, else raise an error.
   */
  switch (pt_update_is_valid((page_entry_t *) pageEntryPtr, val)) {
    case 1:
      val = setMappingReadOnly (val);
      __do_mmu_update ((page_entry_t *) pageEntryPtr, val);
      break;

    case 2:
      __do_mmu_update ((page_entry_t *) pageEntryPtr, val);
      break;

    case 0:
      /* Silently ignore the request */
      return;

    default:
      panic("##### SVA invalid page update!!!\n");
  }

  return;
}

/* Functions for finding the virtual address of page table components */

/* 
 * Function: get_pgeVaddr
 *
 * Description:
 *  This function does page walk to find the entry controlling access to the
 *  specified address. The function takes into consideration the potential use
 *  of larger page sizes.
 * 
 * Inputs:
 *  vaddr - Virtual Address to find entry for
 *
 * Return value:
 *  0 - There is no mapping for this virtual address.
 *  Otherwise, a pointer to the PTE that controls the mapping of this virtual
 *  address is returned.
 */
static inline page_entry_t * 
get_pgeVaddr (uintptr_t vaddr) {
  /* Pointer to the page table entry for the virtual address */
  page_entry_t *pge = 0;

  /* Get the base of the pml4 to traverse */
  uintptr_t cr3 = (uintptr_t) get_pagetable();
  if ((cr3 & 0xfffffffffffff000u) == 0)
    return 0;

  /* Get the VA of the pml4e for this vaddr */
  pml4e_t *pml4e = get_pml4eVaddr ((unsigned char *)cr3, vaddr);

  if (*pml4e & PG_V) {
    /* Get the VA of the pdpte for this vaddr */
    pdpte_t *pdpte = get_pdpteVaddr (pml4e, vaddr);
    if (*pdpte & PG_V) {
      /* 
       * The PDPE can be configurd in large page mode. If it is then we have the
       * entry corresponding to the given vaddr If not then we go deeper in the
       * page walk.
       */
      if (*pdpte & PG_PS) {
        pge = pdpte;
      } else {
        /* Get the pde associated with this vaddr */
        pde_t *pde = get_pdeVaddr (pdpte, vaddr);
        if (*pde & PG_V) {
          /* 
           * As is the case with the pdpte, if the pde is configured for large
           * page size then we have the corresponding entry. Otherwise we need
           * to traverse one more level, which is the last. 
           */
          if (*pde & PG_PS) {
            pge = pde;
          } else {
            pge = get_pteVaddr (pde, vaddr);
          }
        }
      }
    }
  }

  /* Return the entry corresponding to this vaddr */
  return pge;
}


/*
 * Function: getPhysicalAddrDMAP()
 *
 * Description:
 *  Find the physical page number of the specified virtual address based on kernel direct mapping.
 */

static inline uintptr_t
getPhysicalAddrKDMAP (void * v) {
 return  ((uintptr_t) v & ~0xfffffe0000000000u);
}



/*
 * Function: getPhysicalAddrSVADMAP()
 *
 * Description:
 *  Find the physical page number of the specified virtual address based on SVA direct mapping.
 */

static inline uintptr_t
getPhysicalAddrSVADMAP (void * v) {
 return  ((uintptr_t) v & ~SVADMAPSTART);
}


/*
 * Function: getPhysicalAddrFromPML4E()
 *
 * Description:
 *  Find the physical page number of the specified virtual address.  Begin the
 *  translation starting from the specified PML4E.
 *
 * Inputs:
 *  v - The virtual address to look up.
 *  pmlr4e - A pointer to the PML4E entry from which to start the lookup.
 *
 * Outputs:
 *  paddr - A pointer into which to store the physical address.
 *
 * Return value:
 *  1 - A physical frame was mapped at the specified virtual address.
 *  0 - No frame was mapped at the specified virtual address.
 */
unsigned char
getPhysicalAddrFromPML4E (void * v, pml4e_t * pml4e, uintptr_t * paddr) {
  /* Mask to get the proper number of bits from the virtual address */
  static const uintptr_t vmask = 0x0000000000000fffu;

  /* Virtual address to convert */
  uintptr_t vaddr  = ((uintptr_t) v);

  /* Offset into the page table */
  uintptr_t offset = 0;

  /*
   * Determine if the PML4E is present.  If not, stop the page table walk.
   */
  if (((*pml4e) & PG_V) == 0) {
    return 0;
  }

  /*
   * Use the PML4E to get the address of the PDPTE.
   */
  pdpte_t * pdpte = get_pdpteVaddr (pml4e, vaddr);

  /*
   * Determine if the PDPTE is present.  If not, stop the page table walk.
   */
  if (((*pdpte) & PG_V) == 0) {
    return 0;
  }

  /*
   * Determine if the PDPTE has the PS flag set.  If so, then it's pointing to
   * a 1 GB page; return the physical address of that page.
   */
  if ((*pdpte) & PTE_PS) {
    *paddr = (*pdpte & 0x000fffffc0000000u) + (vaddr & 0x3fffffffu);
    return 1;
  }

  /*
   * Find the page directory entry table from the PDPTE value.
   */
  pde_t * pde = get_pdeVaddr (pdpte, vaddr);

  /*
   * Determine if the PDE is present.  If not, stop the page table walk.
   */
  if (((*pde) & PG_V) == 0) {
    return 0;
  }

  /*
   * Determine if the PDE has the PS flag set.  If so, then it's pointing to a
   * 2 MB page; return the physical address of that page.
   */
  if ((*pde) & PTE_PS) {
    *paddr = ((*pde & 0x000fffffffe00000u) + (vaddr & 0x1fffffu));
    return 1;
  }

  /*
   * Find the PTE pointed to by this PDE.
   */
  pte_t * pte = get_pteVaddr (pde, vaddr);

  /*
   * Compute the physical address.
   */
  if ((*pte) & PG_V) {
    offset = vaddr & vmask;
    *paddr = ((*pte & 0x000ffffffffff000u) + offset);
    return 1;
  }

  /* No entry was found.  Return zero */
  return 0;
}

/*
 * Function: getPhysicalAddr()
 *
 * Description:
 *  Find the physical page number of the specified virtual address using the
 *  virtual address space currently in use on this processor.
 */
uintptr_t
getPhysicalAddr (void * v) {
  /* Mask to get the proper number of bits from the virtual address */
  static const uintptr_t vmask = 0x0000000000000fffu;

  /* Virtual address to convert */
  uintptr_t vaddr  = ((uintptr_t) v);

  /* Physical address */
  uintptr_t paddr;

  /*
   * If the pointer is within the kernel's direct map, use a simple
   * bit-masking operation to convert the virtual address to a physical
   * address.
   */
  if (((uintptr_t) v >= 0xfffffe0000000000u) && ((uintptr_t) v < 0xffffff0000000000u))
       return getPhysicalAddrKDMAP(v);

  /*
   * If the virtual address falls within the SVA VM's direct map, use a simple
   * bit-masking operation to find the physical address.
   */
#ifdef SVA_DMAP
  if (((uintptr_t) v >= SVADMAPSTART) && ((uintptr_t) v <= SVADMAPEND))
       return getPhysicalAddrSVADMAP(v);
#endif

  /*
   * Get the currently active page table.
   */
  unsigned char * cr3 = get_pagetable();

  /*
   * Get the address of the PML4e.
   */
  pml4e_t * pml4e = get_pml4eVaddr (cr3, vaddr);

  /*
   * Perform the rest of the page table walk.
   */
  if (getPhysicalAddrFromPML4E (v, pml4e, &paddr)) {
    return paddr;
  }

  return 0;
}

/*
 * Function: removeOSDirectMap
 * 
 * Description:
 *  This function removes the OS's direct mapping page table entry
 *  translating the virtual address of the newly allocated SVA page 
 *  table page for ghost memory.
 *
 * Inputs:
 *  v    -   Virtual address of the page table page of ghost memory*
 *  val  -   The translation to insert into the direct mapping
 */

void
removeOSDirectMap (void * v) {

  /* Mask to get the proper number of bits from the virtual address */
  static const uintptr_t vmask = 0x0000000000000fffu;

  /* Virtual address to convert */
  uintptr_t vaddr  = ((uintptr_t) v);

  /* Offset into the page table */
  uintptr_t offset = 0;

  /*
   * Get the currently active page table.
   */
  unsigned char * cr3 = get_pagetable();

  /*
   * Get the address of the PML4e.
   */
  pml4e_t * pml4e = get_pml4eVaddr (cr3, vaddr);

  /*
   * Use the PML4E to get the address of the PDPTE.
   */
  pdpte_t * pdpte = get_pdpteVaddr (pml4e, vaddr);

  /*
   * Determine if the PDPTE has the PS flag set.  If so, then it's pointing to
   * a 1 GB page; return the physical address of that page.
   */
  if ((*pdpte) & PTE_PS) {
    *pdpte = 0;
    return; 
  }

  /*
   * Find the page directory entry table from the PDPTE value.
   */
  pde_t * pde = get_pdeVaddr (pdpte, vaddr);

  /*
   * Determine if the PDE has the PS flag set.  If so, then it's pointing to a
   * 2 MB page; return the physical address of that page.
   */
  if ((*pde) & PTE_PS) {
    *pde = 0;
    return;
  }

  /*
   * Find the PTE pointed to by this PDE.
   */
  pte_t * pte = get_pteVaddr (pde, vaddr);

  if(*pte == 0)
  	panic("The direct mapping PTE of the SVA PTP does not exist");

  *pte = 0; 

  return;
}


/*
 * Function: allocPTPage()
 *
 * Description:
 *  This function allocates a page table page, initializes it, and returns it
 *  to the caller.
 */
static unsigned int
allocPTPage (void) {
  /* Index into the page table information array */
  unsigned int ptindex;

  /* Pointer to newly allocated memory */
  unsigned char * p;

  /*
   * Find an empty page table array entry to record information about this page
   * table page.  Note that we're a multi-processor system, so use an atomic to
   * keep things valid.
   *
   * Note that we leave the first entry reserved.  This permits us to use a
   * zero index to denote an invalid index.
   */
  for (ptindex = 1; ptindex < 1024; ++ptindex) {
    if (__sync_bool_compare_and_swap (&(PTPages[ptindex].valid), 0, 1)) {
      break;
    }
  }
  if (ptindex == 1024)
    panic ("SVA: allocPTPage: No more table space!\n");

  /*
   * Ask the system software for a page of memory.
   */
#ifdef SVA_DMAP
  if ((p = PTPages[ptindex].vosaddr) != NULL) {
#else
  if ((p = SVAPTPages[ptindex]) != NULL) {
#endif
    /*
     * Initialize the memory.
     */
    memset (p, 0, X86_PAGE_SIZE);

    /*
     * Record the information about the page in the page table page array.
     * We'll need the virtual address by which the system software knows the
     * page as well as the physical address so that the SVA VM can unmap it
     * later.
     */
#ifndef SVA_DMAP
    PTPages[ptindex].vosaddr = p;
    PTPages[ptindex].paddr   = getPhysicalAddr (p);
#endif
    /*
     * Set the type of the page to be a ghost page table page.
     */
    getPageDescPtr(getPhysicalAddr (p))->ghostPTP = 1;

    /*
     * Return the index in the table.
     */
    return ptindex;
  }

  return 0;
}

/*
 * Function: freePTPage()
 *
 * Description:
 *  Return an SVA VM page table page back to the operating system for use.
 */
void
freePTPage (unsigned int ptindex) {
  /*
   * Mark the entry in the page table page array as available.
   */
  PTPages[ptindex].valid = 0;

  /*
   * Change the type of the page table page.
   */
  getPageDescPtr(PTPages[ptindex].paddr)->ghostPTP = 0;

  return;
}

/*
 * Function: updateUses()
 *
 * Description:
 *  This function will update the number of present entries within a page table
 *  page that was allocated by the SVA VM.
 *
 * Inputs:
 *  ptp - A pointer to the page table page.  This does not need to be a page
 *        table page owned by the SVA VM.
 */
static void
updateUses (uintptr_t * ptp) {
  /* Page table page array index */
  unsigned int ptindex;

  /*
   * Find the physical address to which this virtual address is mapped.  We'll
   * use it to determine if this is an SVA VM page.
   */
  uintptr_t paddr = getPhysicalAddr (ptp) & 0xfffffffffffff000u;

  /*
   * Look for the page table page with the specified physical address.  If we
   * find it, increment the number of uses.
   */
  for (ptindex = 0; ptindex < 1024; ++ptindex) {
    if (paddr == PTPages[ptindex].paddr) {
      ++PTPages[ptindex].uses;
    }
  }

  return;
}

/*
 * Function: releaseUse()
 *
 * Description:
 *  This function will decrement the number of present entries within a page
 *  table page allocated by the SVA VM.
 *
 * Inputs:
 *  pde - A pointer to the page table page.  This does not need to be an SVA VM
 *        page table page.
 *
 * Return value:
 *  0 - The page is not a SVA VM page table page, or the page still has live
 *      references in it.
 *  Otherwise, the index into the page table array will be returned.
 */
static unsigned int
releaseUse (uintptr_t * ptp) {
  /* Page table page array index */
  unsigned int ptindex;

  /*
   * Find the physical address to which this virtual address is mapped.  We'll
   * use it to determine if this is an SVA VM page.
   */
  uintptr_t paddr = getPhysicalAddr (ptp) & 0xfffffffffffff000u;

  /*
   * Look for the page table page with the specified physical address.  If we
   * find it, decrement the uses.
   */
  for (ptindex = 0; ptindex < 1024; ++ptindex) {
    if (paddr == PTPages[ptindex].paddr) {
      if ((--(PTPages[ptindex].uses)) == 0) {
        return ptindex;
      }
    }
  }

  return 0;
}

/*
 * Function: mapSecurePage()
 *
 * Description:
 *  Map a single frame of secure memory into the specified virtual address.
 *
 * Inputs:
 *  vaddr - The virtual address into which to map the physical page frame.
 *  paddr - The physical address of the page frame to map.
 *
 * Return value:
 *  The value of the PML4E entry mapping the secure memory region is returned.
 */
uintptr_t
mapSecurePage (uintptr_t vaddr, uintptr_t paddr) {
  
  /* PML4e value for the secure memory region */
  pml4e_t pml4eVal;
  /*
   * Ensure that this page is not being used for something else.
   */
  page_desc_t * pgDesc = getPageDescPtr (paddr);
  if (pgRefCount (pgDesc) > 1) {
    panic ("SVA: Ghost page still in use somewhere else!\n");
  }
  if (isPTP(pgDesc) || isCodePG (pgDesc)) {
    panic ("SVA: Ghost page has wrong type!\n");
  }

  /*
   * Disable protections.
   */
#ifndef SVA_DMAP
  unprotect_paging();
#endif
  /*
   * Get the PML4E of the current page table.  If there isn't one in the
   * table, add one.
   */
  pml4e_t * pml4e = get_pml4eVaddr (get_pagetable(), vaddr);
  if (!isPresent (pml4e)) {
    /* Page table page index */
    unsigned int ptindex;

    /* Fetch a new page table page */
    ptindex = allocPTPage ();

    /*
     * Install a new PDPTE entry using the page.
     */
    uintptr_t paddr = PTPages[ptindex].paddr;
    *pml4e = (paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
  }

  /*
   * Enable writing to the virtual address space used for secure memory.
   */
  *pml4e |= PTE_CANUSER;

  /*
   * Record the value of the PML4E so that we can return it to the caller.
   */
  pml4eVal = *pml4e;

  /*
   * Get the PDPTE entry (or add it if it is not present).
   */
  pdpte_t * pdpte = get_pdpteVaddr (pml4e, vaddr);
  if (!isPresent (pdpte)) {
    /* Page table page index */
    unsigned int ptindex;

    /* Fetch a new page table page */
    ptindex = allocPTPage ();

    /*
     * Install a new PDPTE entry using the page.
     */
    uintptr_t pdpte_paddr = PTPages[ptindex].paddr;
    *pdpte = (pdpte_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;

    /*
     * Note that we've added another translation to the pml4e.
     */
    updateUses (pdpte);
  }
  *pdpte |= PTE_CANUSER;

  if ((*pdpte) & PTE_PS) {
    printf ("mapSecurePage: PDPTE has PS BIT\n");
  }

  /*
   * Get the PDE entry (or add it if it is not present).
   */
  pde_t * pde = get_pdeVaddr (pdpte, vaddr);
  if (!isPresent (pde)) {
    /* Page table page index */
    unsigned int ptindex;

    /* Fetch a new page table page */
    ptindex = allocPTPage ();

    /*
     * Install a new PDE entry.
     */
    uintptr_t pde_paddr = PTPages[ptindex].paddr;
    *pde = (pde_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;

    /*
     * Note that we've added another translation to the pdpte.
     */
    updateUses (pde);
  }
  *pde |= PTE_CANUSER;

  if ((*pde) & PTE_PS) {
    printf ("mapSecurePage: PDE has PS BIT\n");
  }

  /*
   * Get the PTE entry (or add it if it is not present).
   */
  pte_t * pte = get_pteVaddr (pde, vaddr);
#if 0
  if (isPresent (pte)) {
    panic ("SVA: mapSecurePage: PTE is present: %p!\n", pte);
  }
#endif

  /*
   * Modify the PTE to install the physical to virtual page mapping.
   */
  *pte = (paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;

  /*
   * Note that we've added another translation to the pde.
   */
  updateUses (pte);

  /*
   * Mark the physical page frame as a ghost memory page frame.
   */
  getPageDescPtr (paddr)->type = PG_GHOST;
 
  getPageDescPtr (paddr)->count = 1;
  /*
   * Mark the physical page frames used to map the entry as Ghost Page Table
   * Pages.  Note that we don't mark the PML4E as a ghost page table page
   * because it is also used to map traditional memory pages (it is a top-most
   * level page table page).
   */
  getPageDescPtr (get_pdptePaddr (pml4e, vaddr))->ghostPTP = 1;
  getPageDescPtr (get_pdePaddr (pdpte, vaddr))->ghostPTP = 1;
  getPageDescPtr (get_ptePaddr (pde, vaddr))->ghostPTP = 1;

  /*
   * Re-enable page protections.
   */
#ifndef SVA_DMAP
  protect_paging();
#endif

  return pml4eVal;
}

/*
 * Function: unmapSecurePage()
 *
 * Description:
 *  Unmap a single frame of secure memory from the specified virtual address.
 *
 * Inputs:
 *  threadp - A pointer to the SVA Thread for which we should release the frame
 *            of secure memory.
 *  v       - The virtual address to unmap.
 *
 * Return value:
 *  The physical address of the unmapped page on success, 0 otherwise
 *
 * TODO:
 *  Implement code that will tell other processors to invalidate their TLB
 *  entries for this page.
 */
uintptr_t
unmapSecurePage (struct SVAThread * threadp, unsigned char * v) {
  /*
   * Get the PML4E of the page table associated with the specified thread.
   */
  uintptr_t vaddr = (uintptr_t) v;
  uintptr_t paddr = 0;
  pdpte_t * pdpte = get_pdpteVaddr (&(threadp->secmemPML4e), vaddr);
  if (!isPresent (pdpte)) {
    return 0;
  }

  if ((*pdpte) & PTE_PS) {
    return 0;
  }

  /*
   * Get the PDE entry (or add it if it is not present).
   */
  pde_t * pde = get_pdeVaddr (pdpte, vaddr);
  if (!isPresent (pde)) {
    return 0;
  }

  if ((*pde) & PTE_PS) {
    return 0;
  }

  /*
   * Get the PTE entry (or add it if it is not present).
   */
  pte_t * pte = get_pteVaddr (pde, vaddr);
  if (!isPresent (pte)) {
    return 0;
  }

  page_desc_t * pageDesc = getPageDescPtr (*pte & PG_FRAME);
  pageDesc->count --;
  /*
   * Mark the physical page is a regular type page now.
   */
  if(pageDesc->count == 0)
    pageDesc->type = PG_UNUSED;

  /*
   * Modify the PTE so that the page is not present.
   */
#ifndef SVA_DMAP
  unprotect_paging();
#endif
  paddr = *pte & PG_FRAME;
  *pte = 0;

  /*
   * Invalidate any TLBs in the processor.
   */
  sva_mm_flush_tlb (v);

  /*
   * Go through and determine if any of the SVA VM pages tables are now unused.
   * If so, decrement their uses.
   *
   * The goal here is to make unused page tables have all unused entries so
   * that the operating system doesn't get confused.
   */
  unsigned int ptindex;
  if ((ptindex = releaseUse (pte))) {
    freePTPage (ptindex);
    *pde = 0;
    if ((ptindex = releaseUse (pde))) {
      freePTPage (ptindex);
      *pdpte = 0;
      if ((ptindex = releaseUse (pdpte))) {
        freePTPage (ptindex);
        threadp->secmemPML4e = 0;
#if 0
        if ((ptindex = releaseUse (getVirtual(*thread->secmemPML4e)))) {
          freePTPage (ptindex);
        }
#endif
      }
    }
  }

#ifndef SVA_DMAP
  /* Re-enable protection of page table pages */
  protect_paging();
#endif
  return paddr;
}

/*   Function: ghostmemCOW()
 *   
 *   Description: 
 *   Copy the parent's page table of ghost memory to the child. 
 *   Write protect these page table entries for both the parent and the child.
 *
 *   Inputs:
 *   oldThread - the SVAThread variable of the parent process
 *   newThread - the SVAThread variable of the child process   
 */
void
ghostmemCOW(struct SVAThread* oldThread, struct SVAThread* newThread)
{
    uintptr_t vaddr_start, vaddr_end, size;
    
    vaddr_start = (uintptr_t) SECMEMSTART;
    size = oldThread->secmemSize;
    vaddr_end = vaddr_start + size;    

   /*
    * Create the PML4E of the new process's page table. 
    */
    pml4e_t pml4e_val;

    /* Page table page index */
    unsigned int ptindex;

    /* Fetch a new page table page */
    ptindex = allocPTPage ();
    /*
     * Install a new PDPTE entry using the page.
     */
    uintptr_t paddr = PTPages[ptindex].paddr;
    pml4e_val = (paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
    
    /*
     * Enable writing to the virtual address space used for secure memory.
     */
    pml4e_val |= PTE_CANUSER;
     
    newThread->secmemPML4e = pml4e_val;

    pdpte_t * src_pdpte = (pdpte_t *) get_pdpteVaddr (&(oldThread->secmemPML4e), vaddr_start);
    pdpte_t * pdpte = get_pdpteVaddr (&pml4e_val, vaddr_start);   

#ifndef SVA_DMAP
    unprotect_paging(); 
#endif
   
    for(uintptr_t vaddr_pdp = vaddr_start;
    vaddr_pdp < vaddr_end; 
    vaddr_pdp += NBPDP,\
    src_pdpte ++,\
    pdpte ++)
    {
      
           if(!isPresent (src_pdpte))
              continue;
           if (!isPresent (pdpte)) {
             /* Page table page index */
             unsigned int ptindex;

             /* Fetch a new page table page */
             ptindex = allocPTPage ();

             /*
              * Install a new PDPTE entry using the page.
              */
             uintptr_t pdpte_paddr = PTPages[ptindex].paddr;
             *pdpte = (pdpte_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
           }
           *pdpte |= PTE_CANUSER;

          /*
           * Note that we've added another translation to the pml4e.
           */
           updateUses (pdpte);

           if ((*pdpte) & PTE_PS) {
             printf ("ghostmemCOW: PDPTE has PS BIT\n");
           }

           pde_t * src_pde = get_pdeVaddr (src_pdpte, vaddr_pdp);
           pde_t * pde = get_pdeVaddr (pdpte, vaddr_pdp);
           for(uintptr_t vaddr_pde = vaddr_pdp;
           vaddr_pde < vaddr_pdp + NBPDP; 
           vaddr_pde += NBPDR,\
           src_pde ++,\
           pde ++) 
           {

             /*
              * Get the PDE entry (or add it if it is not present).
              */
              if(!isPresent (src_pde))
	        continue;
		  
	      if (!isPresent (pde)) {
                /* Page table page index */
     	        unsigned int ptindex;

                /* Fetch a new page table page */
	        ptindex = allocPTPage ();

                /*
                 * Install a new PDE entry.
                 */
                uintptr_t pde_paddr = PTPages[ptindex].paddr;
                *pde = (pde_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
               }
               *pde |= PTE_CANUSER;

               /*
          	* Note that we've added another translation to the pdpte.
           	*/
               updateUses (pde);

               if ((*pde) & PTE_PS) {
                 printf ("ghostmemCOW: PDE has PS BIT\n");
               }

               pte_t * src_pte = get_pteVaddr (src_pde, vaddr_pde);
               pte_t * pte = get_pteVaddr (pde, vaddr_pde);	
               for(uintptr_t vaddr_pte = vaddr_pde;
               vaddr_pte < vaddr_pde + NBPDR; 
               vaddr_pte += PAGE_SIZE,\
               src_pte ++,\
               pte ++)
               {
                  if(!isPresent (src_pte))
	            continue;

	       	  page_desc_t * pgDesc = getPageDescPtr (*src_pte & PG_FRAME);
		  
		  if(pgDesc->type != PG_GHOST)
                    panic("ghostmemCOW: page is not a ghost memory page! vaddr = 0x%lx, src_pte = 0x%lx, *src_pte = 0x%lx, src_pde = 0x%lx, *src_pde = 0x%lx\n", vaddr_pte, src_pte, *src_pte, src_pde, *src_pde);

               	  *src_pte &= ~PTE_CANWRITE; 
                  *pte = *src_pte;
      		  updateUses(pte);  
               	  pgDesc->count ++;
           	} 
     	}
     }
#ifndef SVA_DMAP
    protect_paging(); 
#endif
}

/*
 * Intrinsic: sva_mm_load_pgtable()
 *
 * Description:
 *  Set the current page table.  This implementation will also enable paging.
 *
 * Inputs:
 *  pg - The physical address of the top-level page table page.
 */
void
sva_mm_load_pgtable (void * pg_ptr) {
  /* Cast the page table pointer to an integer */
  uintptr_t pg = (uintptr_t) pg_ptr;
  uintptr_t data = 0;

  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /* Control Register 0 Value (which is used to enable paging) */
  unsigned long cr0;

  /*
   * Check that the new page table is an L4 page table page.
   */
  if ((mmuIsInitialized) && (!disableMMUChecks) && (getPageDescPtr(pg)->type != PG_L4)) {
    panic ("SVA: Loading non-L4 page into CR3: %lx %x\n", pg, getPageDescPtr (pg)->type);
  }
#ifdef SVA_ASID_PG
  invltlb_kernel();
  pg = ((unsigned long) pg & ~((unsigned long)1 << 63)) & ~0xfff;
#endif
  /*
   * Load the new page table and enable paging in the CR0 register.
   */
  __asm__ __volatile__ ("movq %0, %%cr3\n"
                        "movq %%cr0, %%rax\n"
                        "orl  $0x80000000, %%eax\n"
                        "movq %%rax, %%cr0\n"
                        :
                        : "r" (pg)
                        : "%rax", "memory");

  /*
   * Ensure that the secure memory region is still mapped within the current
   * set of page tables.
   */
  struct SVAThread * threadp = getCPUState()->currentThread;
  if (vg && threadp->secmemSize) {
    /* 
     * Unset page protection so that we can write into the top-level page-table
     * page if necessary.
     */
#ifndef SVA_DMAP
    unprotect_paging();
#endif
    /*
     * Get a pointer into the page tables for the secure memory region.
     */
#ifdef SVA_DMAP
    pml4e_t * secmemp = (pml4e_t *) getVirtualSVADMAP ((uintptr_t)get_pagetable() + secmemOffset);
#else
    pml4e_t * secmemp = (pml4e_t *) getVirtual ((uintptr_t)get_pagetable() + secmemOffset);
#endif
    /*
     * Restore the PML4E entry for the secure memory region.
     */
    *secmemp = threadp->secmemPML4e;

    /*
     * Mark the page table pages as read-only again.
     */

    __asm __volatile("movq %%cr3,%0" : "=r" (data));
    __asm __volatile("movq %0,%%cr3" : : "r" (data) : "memory");

    protect_paging();
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_mm_load_pgtable_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Function: sva_load_cr0
 *
 * Description:
 *  SVA Intrinsic to load the cr0 value. We need to make sure write protection
 *  is enabled. 
 */
void 
sva_load_cr0 (unsigned long val) {
    uint64_t tsc_tmp;
    if(tsc_read_enable_sva)
       tsc_tmp = sva_read_tsc();


    val |= CR0_WP;
    _load_cr0(val);


    record_tsc(sva_load_cr0_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}


/*
 * Function: declare_ptp_and_walk_pt_entries
 *
 * Descriptions:
 *  This function recursively walks a page table and it's entries to initalize
 *  the SVA data structures for the given page. This function is meant to
 *  initialize SVA data structures so they mirror the static page table setup
 *  by a kernel. However, it uses the paging structure itself to walk the
 *  pages, which means it should be agnostic to the operating system being
 *  employed upon. The function only walks into page table pages that are valid
 *  or enabled. It also makes sure that if a given page table is already active
 *  in SVA then it skips over initializing its entries as that could cause an
 *  infinite loop of recursion. This is an issue in FreeBSD as they have a
 *  recursive mapping in the pml4 top level page table page.
 *  
 *  If a given page entry is marked as having a larger page size, such as may
 *  be the case with a 2MB page size for PD entries, then it doesn't traverse
 *  the page. Therefore, if the kernel page tables are configured correctly
 *  this won't initialize any SVA page descriptors that aren't in use.
 *
 *  The primary objective of this code is to for each valid page table page:
 *      [1] Initialize the page_desc for the given page
 *      [2] Set the page permissions as read only
 *
 * Assumptions:
 *  - The number of entries per page assumes a amd64 paging hardware mechanism.
 *    As such the number of entires per a 4KB page table page is 2^9 or 512
 *    entries. 
 *  - This page referenced in pageMapping has already been determined to be
 *    valid and requires SVA metadata to be created.
 *
 * Inputs:
 *   pageMapping: Page mapping associated with the given page being traversed.
 *                This mapping identifies the physical address/frame of the
 *                page table page so that SVA can initialize it's data
 *                structures then recurse on each entry in the page table page. 
 *  numPgEntries: The number of entries for a given level page table. 
 *     pageLevel: The page level of the given mapping {1,2,3,4}.
 *
 *
 * TODO: 
 *  - Modify the page entry number to be dynamic in some way to accomodate
 *    differing numbers of entries. This only impacts how we traverse the
 *    address structures. The key issue is that we don't want to traverse an
 *    entry that randomly has the valid bit set, but not have it point to a
 *    real page. For example, if the kernel did not zero out the entire page
 *    table page and only inserted a subset of entries in the page table, the
 *    non set entries could be identified as holding valid mappings, which
 *    would then cause this function to traverse down truly invalid page table
 *    pages. In FreeBSD this isn't an issue given the way they initialize the
 *    static mapping, but could be a problem given differnet intialization
 *    methods.
 *
 *  - Add code to mark direct map page table pages to prevent the OS from
 *    modifying them.
 *
 */
#define DEBUG_INIT 0
void 
declare_ptp_and_walk_pt_entries(page_entry_t *pageEntry, unsigned long
        numPgEntries, enum page_type_t pageLevel ) 
{ 
  int i;
  int traversedPTEAlready;
  enum page_type_t subLevelPgType;
  unsigned long numSubLevelPgEntries;
  page_desc_t *thisPg;
  page_entry_t pageMapping; 
  page_entry_t *pagePtr;

  /* Store the pte value for the page being traversed */
  pageMapping = *pageEntry;

  /* Set the page pointer for the given page */
#if USE_VIRT
  uintptr_t pagePhysAddr = pageMapping & PG_FRAME;
  pagePtr = (page_entry_t *) getVirtual(pagePhysAddr);
#else
  pagePtr = (page_entry_t *)(pageMapping & PG_FRAME);
#endif

  /* Get the page_desc for this page */
  thisPg = getPageDescPtr(pageMapping);

  /* Mark if we have seen this traversal already */
  traversedPTEAlready = (thisPg->type != PG_UNUSED);

#if DEBUG_INIT >= 1
  /* Character inputs to make the printing pretty for debugging */
  char * indent = "";
  char * l4s = "L4:";
  char * l3s = "\tL3:";
  char * l2s = "\t\tL2:";
  char * l1s = "\t\t\tL1:";

  switch (pageLevel){
    case PG_L4:
        indent = l4s;
        printf("%sSetting L4 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PG_L3:
        indent = l3s;
        printf("%sSetting L3 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PG_L2:
        indent = l2s;
        printf("%sSetting L2 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PG_L1:
        indent = l1s;
        printf("%sSetting L1 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    default:
        break;
  }
#endif

  /*
   * For each level of page we do the following:
   *  - Set the page descriptor type for this page table page
   *  - Set the sub level page type and the number of entries for the
   *    recursive call to the function.
   */
  switch(pageLevel){

    case PG_L4:

      thisPg->type = PG_L4;       /* Set the page type to L4 */
      thisPg->user = 0;           /* Set the priv flag to kernel */
      ++(thisPg->count);
      subLevelPgType = PG_L3;
      numSubLevelPgEntries = NPML4EPG;//    numPgEntries;
      break;

    case PG_L3:
      
      /* TODO: Determine why we want to reassign an L4 to an L3 */
      if (thisPg->type != PG_L4)
        thisPg->type = PG_L3;       /* Set the page type to L3 */
      thisPg->user = 0;           /* Set the priv flag to kernel */
      ++(thisPg->count);
      subLevelPgType = PG_L2;
      numSubLevelPgEntries = NPDPEPG; //numPgEntries;
      break;

    case PG_L2:
      
      /* 
       * If my L2 page mapping signifies that this mapping references a 1GB
       * page frame, then get the frame address using the correct page mask
       * for a L3 page entry and initialize the page_desc for this entry.
       * Then return as we don't need to traverse frame pages.
       */
      if ((pageMapping & PG_PS) != 0) {
#if DEBUG_INIT >= 1
        printf("\tIdentified 1GB page...\n");
#endif
        unsigned long index = (pageMapping & ~PDPMASK) / pageSize;
        page_desc[index].type = PG_TKDATA;
        page_desc[index].user = 0;           /* Set the priv flag to kernel */
        ++(page_desc[index].count);
        return;
      } else {
        thisPg->type = PG_L2;       /* Set the page type to L2 */
        thisPg->user = 0;           /* Set the priv flag to kernel */
        ++(thisPg->count);
        subLevelPgType = PG_L1;
        numSubLevelPgEntries = NPDEPG; // numPgEntries;
      }
      break;

    case PG_L1:
      /* 
       * If my L1 page mapping signifies that this mapping references a 2MB
       * page frame, then get the frame address using the correct page mask
       * for a L2 page entry and initialize the page_desc for this entry. 
       * Then return as we don't need to traverse frame pages.
       */
      if ((pageMapping & PG_PS) != 0){
#if DEBUG_INIT >= 1
        printf("\tIdentified 2MB page...\n");
#endif
        /* The frame address referencing the page obtained */
        unsigned long index = (pageMapping & ~PDRMASK) / pageSize;
        page_desc[index].type = PG_TKDATA;
        page_desc[index].user = 0;           /* Set the priv flag to kernel */
        ++(page_desc[index].count);
        return;
      } else {
        thisPg->type = PG_L1;       /* Set the page type to L1 */
        thisPg->user = 0;           /* Set the priv flag to kernel */
        ++(thisPg->count);
        subLevelPgType = PG_TKDATA;
        numSubLevelPgEntries = NPTEPG;//      numPgEntries;
      }
      break;

    default:
      printf("SVA: page type %d. Frame addr: %p\n",thisPg->type, pagePtr); 
      panic("SVA: walked an entry with invalid page type.");
  }
  
  /* 
   * There is one recursive mapping, which is the last entry in the PML4 page
   * table page. Thus we return before traversing the descriptor again.
   * Notice though that we keep the last assignment to the page as the page
   * type information. 
   */
  if(traversedPTEAlready) {
#if DEBUG_INIT >= 1
    printf("%s Recursed on already initialized page_desc\n", indent);
#endif
    return;
  }

#if DEBUG_INIT >= 1
  u_long nNonValPgs=0;
  u_long nValPgs=0;
#endif
  /* 
   * Iterate through all the entries of this page, recursively calling the
   * walk on all sub entries.
   */
  for (i = 0; i < numSubLevelPgEntries; i++){
   if ((pageLevel == PG_L4) && (i == 256))
	continue;
#if 0
    /*
     * Do not process any entries that implement the direct map.  This prevents
     * us from marking physical pages in the direct map as kernel data pages.
     */
    if ((pageLevel == PG_L4) && (i == (0xfffffe0000000000 / 0x1000))) {
      continue;
    }
#endif
#if OBSOLETE
    //pagePtr += (sizeof(page_entry_t) * i);
    //page_entry_t *nextEntry = pagePtr;
#endif
    page_entry_t * nextEntry = & pagePtr[i];

#if DEBUG_INIT >= 5
    printf("%sPagePtr in loop: %p, val: 0x%lx\n", indent, nextEntry, *nextEntry);
#endif

    /* 
     * If this entry is valid then recurse the page pointed to by this page
     * table entry.
     */
    if (*nextEntry & PG_V) {
#if DEBUG_INIT >= 1
      nValPgs++;
#endif 

      /* 
       * If we hit the level 1 pages we have hit our boundary condition for
       * the recursive page table traversals. Now we just mark the leaf page
       * descriptors.
       */
      if (pageLevel == PG_L1){
#if DEBUG_INIT >= 2
          printf("%sInitializing leaf entry: pteaddr: %p, mapping: 0x%lx\n",
                  indent, nextEntry, *nextEntry);
#endif
      } else {
#if DEBUG_INIT >= 2
      printf("%sProcessing:pte addr: %p, newPgAddr: %p, mapping: 0x%lx\n",
              indent, nextEntry, (*nextEntry & PG_FRAME), *nextEntry ); 
#endif
          declare_ptp_and_walk_pt_entries(nextEntry,
                  numSubLevelPgEntries, subLevelPgType); 
      }
    } 
#if DEBUG_INIT >= 1
    else {
      nNonValPgs++;
    }
#endif
  }

#if DEBUG_INIT >= 1
  SVA_ASSERT((nNonValPgs + nValPgs) == 512, "Wrong number of entries traversed");

  printf("%sThe number of || non valid pages: %lu || valid pages: %lu\n",
          indent, nNonValPgs, nValPgs);
#endif

}

/*
 * Function: declare_kernel_code_pages()
 *
 * Description:
 *  Mark all kernel code pages as code pages.
 *
 * Inputs: 
 *  btext - The first virtual address of the text segment.
 *  etext - The last virtual address of the text segment.
 */
void
declare_kernel_code_pages (uintptr_t btext, uintptr_t etext) {
  /* Get pointers for the pages */
  uintptr_t page;
  uintptr_t btextPage = getPhysicalAddr((void *)btext) & PG_FRAME;
  uintptr_t etextPage = getPhysicalAddr((void *)etext) & PG_FRAME;

  /*
   * Scan through each page in the text segment.  Note that it is a code page,
   * and make the page read-only within the page table.
   */
  for (page = btextPage; page < etextPage; page += pageSize) {
    /* Mark the page as both a code page and kernel level */
    page_desc[page / pageSize].type = PG_CODE;
    page_desc[page / pageSize].user = 0;

    /* Configure the MMU so that the page is read-only */
    page_entry_t * page_entry = get_pgeVaddr (btext + (page - btextPage));
    page_entry_store(page_entry, setMappingReadOnly (*page_entry));
  }
}

/*
 * Function: makePTReadOnly()
 *
 * Description:
 *  Scan through all of the page descriptors and find all the page descriptors
 *  for page table pages.  For each such page, make the virtual page that maps
 *  it into the direct map read-only.
 */
static inline void
makePTReadOnly (void) {
  /* Disable page protection */
  //unprotect_paging();

  /*
   * For each physical page, determine if it is used as a page table page.
   * If so, make its entry in the direct map read-only.
   */
  uintptr_t paddr;
  for (paddr = 0; paddr < memSize; paddr += pageSize) {
    enum page_type_t pgType = getPageDescPtr(paddr)->type;
    if ((PG_L1 <= pgType) && (pgType <= PG_L4)) {
      page_entry_t * pageEntry = get_pgeVaddr ((uintptr_t)getVirtual(paddr));
      page_entry_store (pageEntry, setMappingReadOnly(*pageEntry));
    }
  }

  /* Re-enable page protection */
  //protect_paging();
}

extern int cache_part_enable_sva;
static __inline void
wrmsr(u_int msr, uint64_t newval)
{
  uint32_t low, high;
  low = newval;
  high = newval >> 32;
  __asm __volatile("wrmsr" : : "a" (low), "d" (high), "c" (msr));
}

/* PCID-related functions: 
 * kernel pcid is 1, and user/SVA pcid is 0
 */

void usersva_to_kernel_pcid(void)
{
#ifdef SVA_ASID_PG
  unsigned long cr3;
  struct SVAThread * curThread;
  unsigned long pg = 0;

  __asm __volatile("movq %%cr3,%0" : "=r" (cr3));
  if(!(cr3 & 0x1))
  {
        page_desc_t * ptDesc = getPageDescPtr(cr3);
        pg = ptDesc->other_pgPaddr;
        pg = (pg == 0)? cr3 : pg;
        cr3 = (pg & ~0xfff) | 0x1 | ((unsigned long)1 << 63);
        __asm __volatile("movq %0,%%cr3" : : "r" (cr3) : "memory");

	if(tsc_read_enable_sva)
		as_num ++;
  }
#endif

#ifdef SVA_LLC_PART
if(cache_part_enable_sva) 
  wrmsr(COS_MSR, OS_COS);
#endif
}

void kernel_to_usersva_pcid(void)
{
#ifdef SVA_ASID_PG
  unsigned long cr3;
  struct SVAThread * curThread;
  unsigned long pg = 0;

  __asm __volatile("movq %%cr3,%0" : "=r" (cr3));
  if(cr3 & 0x1)
  {
        page_desc_t * ptDesc = getPageDescPtr(cr3);
        pg = ptDesc->other_pgPaddr;
        pg = (pg == 0)? cr3 : pg;
        cr3 = (pg & ~0xfff) | ((unsigned long)1 << 63);
        __asm __volatile("movq %0,%%cr3" : : "r" (cr3) : "memory");

	if(tsc_read_enable_sva)
		as_num ++;
  }
#endif

#ifdef SVA_LLC_PART
if(cache_part_enable_sva)
  wrmsr(COS_MSR, SVA_COS);
#endif
}

void sva_enable_cache_part()
{
  cache_part_enable_sva = 1;
}

void sva_disable_cache_part()
{
  cache_part_enable_sva = 0;
}

/*
 * Function: remap_internal_memory()
 *
 * Description:
 *  Map sufficient physical memory into the SVA VM internal address space.
 *
 * Inputs:
 *  firstpaddr - A pointer to the first free physical address.
 *
 * Outputs:
 *  firstpaddr - The first free physical address is updated to account for the
 *               pages used in the remapping.
 */
void
remap_internal_memory (uintptr_t * firstpaddr) {
  /* Pointers to the internal SVA VM memory */
  extern char _svastart[];
  extern char _svaend[];

  /*
   * Determine how much memory we need to map into the SVA VM address space.
   */
  uintptr_t svaSize = ((uintptr_t) _svaend) - ((uintptr_t) _svastart);

  /*
   * Disable protections.
   */
#ifndef SVA_DMAP
  unprotect_paging();
#endif
  /*
   * Create a PML4E for the SVA address space.
   */
  pml4e_t pml4eVal;

  /*
   * Get the PML4E of the current page table.  If there isn't one in the
   * table, add one.
   */
  uintptr_t vaddr = 0xffffff8000000000u;
  pml4e_t * pml4e = get_pml4eVaddr (get_pagetable(), vaddr);
  if (!isPresent (pml4e)) {
    /* Allocate a new frame */
    uintptr_t paddr = *(firstpaddr);
    (*firstpaddr) += X86_PAGE_SIZE;

    /* Set the type of the frame */
    getPageDescPtr(paddr)->type = PG_L3;
    ++(getPageDescPtr(paddr)->count);

    /* Zero the contents of the frame */
#ifdef SVA_DMAP
    memset (getVirtualSVADMAP (paddr), 0, X86_PAGE_SIZE);
#else
    memset (getVirtual (paddr), 0, X86_PAGE_SIZE);
#endif
    /* Install a new PDPTE entry using the page  */
    *pml4e = (paddr & addrmask) | PTE_CANWRITE | PTE_PRESENT;
  }

  /*
   * Get the PDPTE entry (or add it if it is not present).
   */
  pdpte_t * pdpte = get_pdpteVaddr (pml4e, vaddr);
  if (!isPresent (pdpte)) {
    /* Allocate a new frame */
    uintptr_t pdpte_paddr = *(firstpaddr);
    (*firstpaddr) += X86_PAGE_SIZE;

    /* Set the type of the frame */
    getPageDescPtr(pdpte_paddr)->type = PG_L2;
    ++(getPageDescPtr(pdpte_paddr)->count);

    /* Zero the contents of the frame */
#ifdef SVA_DMAP
    memset (getVirtualSVADMAP (pdpte_paddr), 0, X86_PAGE_SIZE);
#else
    memset (getVirtual (pdpte_paddr), 0, X86_PAGE_SIZE);
#endif
    /* Install a new PDE entry using the page. */
    *pdpte = (pdpte_paddr & addrmask) | PTE_CANWRITE | PTE_PRESENT;
  }

  /*
   * Advance the physical address to the next 2 MB boundary.
   */
  if ((*firstpaddr & 0x0fffff)) {
    uintptr_t oldpaddr = *firstpaddr;
    *firstpaddr = ((*firstpaddr) + 0x200000) & 0xffffffffffc00000u;
    printf ("SVA: remap: %lx %lx\n", oldpaddr, *firstpaddr);
  }

  /*
   * Allocate 8 MB worth of SVA address space.
   */
  for (unsigned index = 0; index < 4; ++index) {
    /*
     * Get the PDE entry.
     */
    pde_t * pde = get_pdeVaddr (pdpte, vaddr);
    /* Allocate a new frame */
    uintptr_t pde_paddr = *(firstpaddr);
    (*firstpaddr) += (2 * 1024 * 1024);

    /*
     * Set the types of the frames
     */
    for (uintptr_t p = pde_paddr; p < *firstpaddr; p += X86_PAGE_SIZE) {
      getPageDescPtr(p)->type = PG_L1;
      ++(getPageDescPtr(p)->count);
    }

    /*
     * Install a new PDE entry.
     */
    *pde = (pde_paddr & addrmask) | PTE_CANWRITE | PTE_PRESENT | PTE_PS;
    *pde |= PG_G;

    /*
     * Verify that the mapping works.
     */
    unsigned char * p = (unsigned char *) vaddr;
#ifdef SVA_DMAP
    unsigned char * q = (unsigned char *) getVirtualSVADMAP (pde_paddr);
#else
    unsigned char * q = (unsigned char *) getVirtual (pde_paddr);
#endif
    for (unsigned index = 0; index < 100; ++index) {
      (*(p + index)) = ('a' + index);
    }

    for (unsigned index = 0; index < 100; ++index) {
      if ((*(q + index)) != ('a' + index))
        panic ("SVA: No match: %x: %lx != %lx\n", index, p + index, q + index);
    }

    /* Move to the next virtual address */
    vaddr += (2 * 1024 * 1024);
  }

  /*
   * Re-enable page protections.
   */
#ifndef SVA_DMAP
  protect_paging();
#endif
  return;
}

/*
 * Function: sva_create_dmap()
 *
 * Description:
 *  This function sets up the SVA direct mapping region.
 *
 * Input:
 * KPML4phys - phys addr of kernel level 4 page table page
 * DMPDPphys - phys addr of SVA direct mapping level 3 page table page
 * DMPDphys -  phys addr of SVA direct mapping level 2 page table page
 * DMPTphys -  phys addr of SVA direct mapping level 1 page table page
 * ndmpdp   -  number of SVA direct mapping level 3 page table pages
 * ndm1g    -  number of 1GB pages used for SVA direct mapping
 */

void
sva_create_dmap(void * KPML4phys, void * DMPDPphys,
void * DMPDphys, void * DMPTphys, int ndmpdp, int ndm1g)
{
  int i, j;

  for (i = 0; i < NPTEPG * NPDEPG * ndmpdp; i++) {
	        ((pte_t *)DMPTphys)[i] = (uintptr_t) i << PAGE_SHIFT;
		((pte_t *)DMPTphys)[i] |= PG_RW | PG_V 
#ifdef SVA_ASID_PG
			;
#else
			| PG_G;
#endif
       }

  for (i = NPDEPG * ndm1g, j = 0; i < NPDEPG * ndmpdp; i++, j++) {
                ((pde_t *)DMPDphys)[j] = (uintptr_t)DMPTphys + ((uintptr_t)j << PAGE_SHIFT);
                /* Preset PG_M and PG_A because demotion expects it. */
                ((pde_t *)DMPDphys)[j] |= PG_RW | PG_V; /*| PG_PS | 
#ifdef SVA_ASID_PG
                    PG_M | PG_A;
#else	
		    PG_G | PG_M | PG_A;
#endif*/
       }

  for (i = 0/*384*/; i < 0 /*384*/ + ndm1g; i++) {
                ((pdpte_t *)DMPDPphys)[i] = (uintptr_t)(i /*- 384*/) << PDPSHIFT;
                /* Preset PG_M and PG_A because demotion expects it. */
                ((pdpte_t *)DMPDPphys)[i] |= PG_RW | PG_V | PG_PS | 
#ifdef SVA_ASID_PG
                    PG_M | PG_A;
#else	
		    PG_G | PG_M | PG_A;
#endif
  }
  for (j = 0; i < /*384 +*/ ndmpdp; i++, j++) {
                ((pdpte_t *)DMPDPphys)[i] = (uintptr_t)DMPDphys + (uintptr_t)(j << PAGE_SHIFT);
                ((pdpte_t *)DMPDPphys)[i] |= PG_RW | PG_V | PG_U;

  }


  /* Connect the Direct Map slot(s) up to the PML4. */
  for (i = 0; i < NDMPML4E; i++) {
                ((pdpte_t *)KPML4phys)[DMPML4I + i] = (uintptr_t)DMPDPphys + (uintptr_t)
                    (i << PAGE_SHIFT);
                ((pdpte_t *)KPML4phys)[DMPML4I + i] |= PG_RW | PG_V | PG_U;
  }


  for(i = 0; i < NDMPML4E; i++)
  {
	sva_declare_dmap_page((unsigned long)DMPDPphys + (i << PAGE_SHIFT));
  }

  for(i = 0; i < ndmpdp - ndm1g; i ++)
  {
	sva_declare_dmap_page((unsigned long)DMPDphys + (i << PAGE_SHIFT));
  }

  return;
}


/*
 * Instrinsic: sva_update_l4_dmap
 *
 * Description:
 *  This function updates the pml4 entries of a process with the SVA direct mapping.
 *
 * Input:
 *  pml4pg - the virtual address of the pml4 page table page to be updated
 *  index  - the index of the SVA direct mapping pml4 entry
 *  val    - the page table entry to be populated in
 */

void sva_update_l4_dmap(void * pml4pg, int index, page_entry_t val)
{
  if(index < NDMPML4E)
  sva_update_l4_mapping(&(((pdpte_t *)pml4pg)[DMPML4I + index]), val);
}


/*
 * Function: sva_mmu_init
 *
 * Description:
 *  This function initializes the sva mmu unit by zeroing out the page
 *  descriptors, capturing the statically allocated initial kernel mmu state,
 *  and identifying all kernel code pages, and setting them in the page
 *  descriptor array.
 *
 *  To initialize the sva page descriptors, this function takes the pml4 base
 *  mapping and walks down each level of the page table tree. 
 *
 *  NOTE: In this function we assume that he page mapping for the kpml4 has
 *  physical addresses in it. We then dereference by obtaining the virtual
 *  address mapping of this page. This works whether or not the processor is in
 *  a virtually addressed or physically addressed mode. 
 *
 * Inputs:
 *  - kpml4Mapping  : Mapping referencing the base kernel pml4 page table page
 *  - nkpml4e       : The number of entries in the pml4
 *  - firstpaddr    : A pointer to the physical address of the first free frame.
 *  - btext         : The first virtual address of the text segment.
 *  - etext         : The last virtual address of the text segment.
 */
void 
sva_mmu_init (pml4e_t * kpml4Mapping,
              unsigned long nkpml4e,
              uintptr_t * firstpaddr,
              uintptr_t btext,
              uintptr_t etext) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  /* Get the virtual address of the pml4e mapping */
#if USE_VIRT
  pml4e_t * kpml4eVA = (pml4e_t *) getVirtual( (uintptr_t) kpml4Mapping);
#else
  pml4e_t * kpml4eVA = kpml4Mapping;
#endif

  /* Zero out the page descriptor array */
  memset (page_desc, 0, numPageDescEntries * sizeof(page_desc_t));

#if 0
  /*
   * Remap the SVA internal data structure memory into the part of the address
   * space protected by the sandboxing (SF) instrumentation.
   */
  remap_internal_memory(firstpaddr);
#endif

  /* Walk the kernel page tables and initialize the sva page_desc */
  declare_ptp_and_walk_pt_entries(kpml4eVA, nkpml4e, PG_L4);

  /* TODO: Set page_desc pages as SVA pages */

  /* Identify kernel code pages and intialize the descriptors */
  declare_kernel_code_pages(btext, etext);

#ifdef SVA_ASID_PG
  load_cr4(_rcr4()|CR4_PCIDE);
  /* Now load the initial value of the cr3 to complete kernel init */
  unsigned long kernel_pg = *kpml4Mapping & PG_FRAME;
  kernel_pg = (kernel_pg & ~0xfff) | 0x1;
#endif
  unprotect_paging();
#ifdef SVA_ASID_PG
  load_cr3(kernel_pg);
#else
  load_cr3(*kpml4Mapping & PG_FRAME);
#endif
  protect_paging();

  /*
   * Make existing page table pages read-only.
   *
   * TODO:
   *  Using this function on the SVA test machine with 16 GB of RAM worked when
   *  writing the Virtual Ghost and KCoFI papers.  However, either there has
   *  been a regression, or this code does not work on VirtualBox on Mac OS X
   *  with a 4 GB VM running SVA FreeBSD.  Either way, there is a bug that
   *  needs to be fixed.
   */
  if (!keepPTWriteableHack) {
    makePTReadOnly();
  }

  /*
   * Note that the MMU is now initialized.
   */
  mmuIsInitialized = 1;

#ifdef SVA_DMAP  
  int ptindex;
  unsigned char * p;
  for(ptindex = 0; ptindex < 1024; ++ptindex)
  {
	  if((p = SVAPTPages[ptindex]) == NULL)
		panic("SVAPTPages[%d] is not allocated\n", ptindex);  
	  PTPages[ptindex].paddr   = getPhysicalAddr (p);
	  PTPages[ptindex].vosaddr = getVirtualSVADMAP(PTPages[ptindex].paddr);
	  if(pgdef)
	  	removeOSDirectMap(getVirtual(PTPages[ptindex].paddr)); 
  }
  
#endif
  record_tsc(sva_mmu_init_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

/*
 * Intrinsic: sva_declare_l1_page()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 1 page table
 *  frame.  It will zero out the contents of the page frame so that stale
 *  mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The address of the physical page frame that will be used as a
 *              Level 1 page frame.
 */
void
sva_declare_l1_page (uintptr_t frameAddr) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L1 page, an unused page, or a kernel
   * data page.
   */
  switch (pgDesc->type) {
    case PG_UNUSED:
    case PG_L1:
    case PG_TKDATA:
      break;

    default:
      printf ("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic ("SVA: Declaring L1 for wrong page: frameAddr = %lx, pgDesc=%lx, type=%x\n", frameAddr, pgDesc, pgDesc->type);
      break;
  }

#ifdef SVA_DMAP
  /* A page can only be declared as a page table page if its reference count is less than 2.*/
  SVA_ASSERT((pgRefCount(pgDesc) <= 2), "sva_declare_l1_page: more than one virtual addresses are still using this page!");
#else
  /* A page can only be declared as a page table page if its reference count is 0 or 1.*/
  //SVA_ASSERT((pgRefCount(pgDesc) <= 1), "sva_declare_l1_page: more than one virtual addresses are still using this page!");
#endif

  /* 
   * Declare the page as an L1 page (unless it is already an L1 page).
   */
  if (pgDesc->type != PG_L1) {
    /*
     * Mark this page frame as an L1 page frame.
     */
    pgDesc->type = PG_L1;

    /*
     * Reset the virtual address which can point to this page table page.
     */
    pgDesc->pgVaddr = 0;

    /* 
     * Initialize the page data and page entry. Note that we pass a general
     * page_entry_t to the function as it enables reuse of code for each of the
     * entry declaration functions. 
     */
    initDeclaredPage(frameAddr);
  } else {
    panic ("SVA: declare L1: type = %x\n", pgDesc->type);
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_declare_l1_page_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_declare_l2_page()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 2 page table
 *  frame.  It will zero out the contents of the page frame so that stale
 *  mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The address of the physical page frame that will be used as a
 *              Level 2 page frame.
 */
void
sva_declare_l2_page (uintptr_t frameAddr) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L2 page, an unused page, or a kernel
   * data page.
   */
  switch (pgDesc->type) {
    case PG_UNUSED:
    case PG_L2:
    case PG_TKDATA:
      break;

    default:
      printf ("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic ("SVA: Declaring L2 for wrong page: frameAddr = %lx, pgDesc=%lx, type=%x count=%x\n", frameAddr, pgDesc, pgDesc->type, pgDesc->count);
      break;
  }

#ifdef SVA_DMAP
 /* A page can only be declared as a page table page if its reference count is less than 2.*/
  SVA_ASSERT((pgRefCount(pgDesc) <= 2), "sva_declare_l2_page: more than one virtual addresses are still using this page!");
#else
  /* A page can only be declared as a page table page if its reference count is 0 or 1.*/
  //SVA_ASSERT((pgRefCount(pgDesc) <= 1), "sva_declare_l2_page: more than one virtual addresses are still using this page!");
#endif

  /* 
   * Declare the page as an L2 page (unless it is already an L2 page).
   */
  if (pgDesc->type != PG_L2) {
    /* Setup metadata tracking for this new page */
    pgDesc->type = PG_L2;

    /*
     * Reset the virtual address which can point to this page table page.
     */
    pgDesc->pgVaddr = 0;

    /* 
     * Initialize the page data and page entry. Note that we pass a general
     * page_entry_t to the function as it enables reuse of code for each of the
     * entry declaration functions. 
     */
    initDeclaredPage(frameAddr);
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_declare_l2_page_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_declare_l3_page()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 3 page table
 *  frame.  It will zero out the contents of the page frame so that stale
 *  mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The address of the physical page frame that will be used as a
 *              Level 3 page frame.
 */
void
sva_declare_l3_page (uintptr_t frameAddr) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L3 page, an unused page, or a kernel
   * data page.
   */
  switch (pgDesc->type) {
    case PG_UNUSED:
    case PG_L3:
    case PG_TKDATA:
      break;

    default:
      printf ("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic ("SVA: Declaring L3 for wrong page: frameAddr = %lx, pgDesc=%lx, type=%x count=%x\n", frameAddr, pgDesc, pgDesc->type, pgDesc->count);
      break;
  }

#ifdef SVA_DMAP
 /* A page can only be declared as a page table page if its reference count is less than 2.*/
  SVA_ASSERT((pgRefCount(pgDesc) <= 2), "sva_declare_l3_page: more than one virtual addresses are still using this page!");
#else
   /* A page can only be declared as a page table page if its reference count is 0 or 1.*/
  //SVA_ASSERT((pgRefCount(pgDesc) <= 1), "sva_declare_l3_page: more than one virtual addresses are still using this page!");
#endif

  /* 
   * Declare the page as an L3 page (unless it is already an L3 page).
   */
  if (pgDesc->type != PG_L3) {
    /* Mark this page frame as an L3 page frame */
    pgDesc->type = PG_L3;

    /*
     * Reset the virtual address which can point to this page table page.
     */
    pgDesc->pgVaddr = 0;

    /* 
     * Initialize the page data and page entry. Note that we pass a general
     * page_entry_t to the function as it enables reuse of code for each of the
     * entry declaration functions. 
     */
    initDeclaredPage(frameAddr);
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_declare_l3_page_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_declare_l4_page()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 4 page table
 *  frame.  It will zero out the contents of the page frame so that stale
 *  mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The address of the physical page frame that will be used as a
 *              Level 4 page frame.
 */
void
sva_declare_l4_page (uintptr_t frameAddr) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /* 
   * Assert that this is a new L4. We don't want to declare an L4 with and
   * existing mapping
   */
#if 0
  SVA_ASSERT(pgRefCount(pgDesc) == 0, "MMU: L4 reference count non-zero.");
#endif

  /*
   * Make sure that this is already an L4 page, an unused page, or a kernel
   * data page.
   */
  switch (pgDesc->type) {
    case PG_UNUSED:
    case PG_L4:
    case PG_TKDATA:
      break;

    default:
      printf ("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic ("SVA: Declaring L4 for wrong page: frameAddr = %lx, pgDesc=%lx, type=%x\n", frameAddr, pgDesc, pgDesc->type);
      break;
  }

#ifdef SVA_DMAP
 /* A page can only be declared as a page table page if its reference count is 0 or 1.*/
  SVA_ASSERT((pgRefCount(pgDesc) <= 2), "sva_declare_l4_page: more than one virtual addresses are still using this page!");
#else
 /* A page can only be declared as a page table page if its reference count is less than 2.*/
  //SVA_ASSERT((pgRefCount(pgDesc) <= 1), "sva_declare_l4_page: more than one virtual addresses are still using this page!");
#endif
  /* 
   * Declare the page as an L4 page (unless it is already an L4 page).
   */
  if (pgDesc->type != PG_L4) {
    /* Mark this page frame as an L4 page frame */
    pgDesc->type = PG_L4;

    /*
     * Reset the virtual address which can point to this page table page.
     */
    pgDesc->pgVaddr = 0;

    /* 
     * Initialize the page data and page entry. Note that we pass a general
     * page_entry_t to the function as it enables reuse of code for each of the
     * entry declaration functions. 
     */
    initDeclaredPage(frameAddr);
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_declare_l4_page_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}

/*
 * Function: sva_declare_dmap_page()
 *
 * Description:
 *   Declare a physical page frame to be a page for SVA direct mapping
 *
 * Input:
 *   frameAddr - the address of a physical page frame
 */
void sva_declare_dmap_page(uintptr_t frameAddr)
 {
    getPageDescPtr(frameAddr)->dmap = 1;
 }

static inline page_entry_t * 
printPTES (uintptr_t vaddr) {
  /* Pointer to the page table entry for the virtual address */
  page_entry_t *pge = 0;

  /* Get the base of the pml4 to traverse */
  unsigned char * cr3 = get_pagetable();
  if ((((uintptr_t)(cr3)) & 0xfffffffffffff000u) == 0)
    return 0;

  /* Get the VA of the pml4e for this vaddr */
  pml4e_t *pml4e = get_pml4eVaddr (cr3, vaddr);

  if (*pml4e & PG_V) {
    /* Get the VA of the pdpte for this vaddr */
    pdpte_t *pdpte = get_pdpteVaddr (pml4e, vaddr);
    if (*pdpte & PG_V) {
      /* 
       * The PDPE can be configurd in large page mode. If it is then we have the
       * entry corresponding to the given vaddr If not then we go deeper in the
       * page walk.
       */
      if (*pdpte & PG_PS) {
        pge = pdpte;
      } else {
        /* Get the pde associated with this vaddr */
        pde_t *pde = get_pdeVaddr (pdpte, vaddr);
        if (*pde & PG_V) {
          /* 
           * As is the case with the pdpte, if the pde is configured for large
           * page size then we have the corresponding entry. Otherwise we need
           * to traverse one more level, which is the last. 
           */
          if (*pde & PG_PS) {
            pge = pde;
          } else {
            pge = get_pteVaddr (pde, vaddr);
            printf ("SVA: PTE: %lx %lx %lx %lx\n", *pml4e, *pdpte, *pde, *pge);
          }
        }
      }
    }
  }

  /* Return the entry corresponding to this vaddr */
  return pge;
}

/*
 * Function: sva_remove_page()
 *
 * Description:
 *  This function informs the SVA VM that the system software no longer wants
 *  to use the specified page as a page table page.
 *
 * Inputs:
 *  paddr - The physical address of the page table page.
 */
void
sva_remove_page (uintptr_t paddr) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();
  
  kernel_to_usersva_pcid();
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the entry controlling the permissions for this pte PTP */
  page_entry_t *pte = get_pgeVaddr((uintptr_t)getVirtual (paddr));

  /* Get the page_desc for the l1 page frame */
  page_desc_t *pgDesc = getPageDescPtr(paddr);

  /*
   * Make sure that this is a page table page.  We don't want the system
   * software to trick us.
   */
  switch (pgDesc->type)  {
    case PG_L1:
    case PG_L2:
    case PG_L3:
    case PG_L4:
      break;

    default:
      /* Restore interrupts */
      panic ("SVA: undeclare bad page type: %lx %lx\n", paddr, pgDesc->type);
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      record_tsc(sva_remove_page_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
      return;
      break;
  }

  /*
   * Check that there are no references to this page (i.e., there is no page
   * table entry that refers to this physical page frame).  If there is a
   * mapping, then someone is still using it as a page table page.  In that
   * case, ignore the request.
   *
   * Note that we check for a reference count of 1 because the page is always
   * mapped into the direct map.
   */
#ifdef SVA_DMAP
  if (pgDesc->count <= 2) {
#else
  if (pgDesc->count <= 1) {
#endif

#ifdef SVA_ASID_PG
    if(pgDesc->type == PG_L4)
    {
	uintptr_t other_cr3 = pgDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;
	
	if(other_cr3)
	{  
		page_desc_t *other_pgDesc = getPageDescPtr(other_cr3);
		SVA_ASSERT((other_pgDesc->count <= 2),
			    "the kernel or usersva version pml4 page table page still has reference.\n" );
		other_pgDesc->type = PG_UNUSED;
		page_entry_t *other_pte = get_pgeVaddr((uintptr_t)getVirtual (other_cr3));
	        page_entry_store ((page_entry_t *) other_pte, setMappingReadWrite (*other_pte));
		sva_mm_flush_tlb(getVirtual(other_cr3));
		other_pgDesc->other_pgPaddr = 0;
		pgDesc->other_pgPaddr = 0;
	}
    }
#endif
    /*
     * Mark the page frame as an unused page.
     */
    pgDesc->type = PG_UNUSED;
   
    /*
     * Make the page writeable again.  Be sure to flush the TLBs to make the
     * change take effect right away.
     */
    page_entry_store ((page_entry_t *) pte, setMappingReadWrite (*pte));
    sva_mm_flush_tlb (getVirtual (paddr));
  } else {
    printf ("SVA: remove_page: type=%x count %x\n", pgDesc->type, pgDesc->count);
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_remove_page_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Function: sva_get_kernel_pml4pg
 * 
 * Description:
 *   Return the physical address of the kernel pml4 page table page
 *
 * Input:
 *   paddr - the physical address of the original (user/sva verison) pml4 page table page
 */
uintptr_t sva_get_kernel_pml4pg(uintptr_t paddr)
{
	page_desc_t *pgDesc = getPageDescPtr(paddr);
	uintptr_t other_paddr = pgDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;
	return other_paddr;		
}


/* 
 * Function: sva_remove_mapping()
 *
 * Description:
 *  This function updates the entry to the page table page and is agnostic to
 *  the level of page table. The particular needs for each page table level are
 *  handled in the __update_mapping function. The primary function here is to
 *  set the mapping to zero, if the page was a PTP then zero it's data and set
 *  it to writeable.
 *
 * Inputs:
 *  pteptr - The location within the page table page for which the translation
 *           should be removed.
 */
void
sva_remove_mapping(page_entry_t * pteptr) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();

  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(*pteptr);

  /* Update the page table mapping to zero */
  __update_mapping (pteptr, ZERO_MAPPING);

#ifdef SVA_ASID_PG
  uintptr_t phys = getPhysicalAddr(pteptr);
  page_desc_t * cur_pgDesc = getPageDescPtr(phys);
  if(cur_pgDesc->type == PG_L4)
  {
   uintptr_t other_cr3 = cur_pgDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;
   if(other_cr3)
   {
        page_entry_t * other_pteptr = (page_entry_t *) ((unsigned long) getVirtual(other_cr3) | ((unsigned long) pteptr & vmask));
        __update_mapping (other_pteptr, ZERO_MAPPING);
   }
  }
#endif
  

  /* Restore interrupts */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_remove_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
}


/* 
 * Function: sva_update_l1_mapping_checkglobal()
 *
 * Description:
 *  This function updates a Level-1 Mapping.  In other words, it adds a
 *  a direct translation from a virtual page to a physical page.
 *  Compared to sva_update_l1_mapping, this function checks whether the virtual 
 *  address falls within the sva internal memory. If yes, make sure the PTEs are
 *  not marked as global.
 *
 *  This function makes different checks to ensure the mapping
 *  does not bypass the type safety proved by the compiler.
 *
 * Inputs:
 *  pteptr - The location within the L1 page in which the new translation
 *           should be place.
 *  val    - The new translation to insert into the page table.
 */
void
sva_update_l1_mapping_checkglobal(pte_t * pteptr, page_entry_t val, unsigned long va) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  if((va >= 0xffffffff819ef000u) && (va <= 0xffffffff89b96060u) )
  {
    val &= ~PG_G;
  }

  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr(pteptr));
  if ((ptDesc->type != PG_L1) && (!disableMMUChecks)) {
    panic ("SVA: MMU: update_l1 not an L1: %lx %lx: %lx\n", pteptr, val, ptDesc->type);
  }

  /*
   * Update the page table with the new mapping.
   */
  __update_mapping(pteptr, val);

  /* Restore interrupts */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  record_tsc(sva_update_l1_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/* 
 * Function: sva_update_l1_mapping()
 *
 * Description:
 *  This function updates a Level-1 Mapping.  In other words, it adds a
 *  a direct translation from a virtual page to a physical page.
 *
 *  This function makes different checks to ensure the mapping
 *  does not bypass the type safety proved by the compiler.
 *
 * Inputs:
 *  pteptr - The location within the L1 page in which the new translation
 *           should be place.
 *  val    - The new translation to insert into the page table.
 */
void
sva_update_l1_mapping(pte_t * pteptr, page_entry_t val) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr(pteptr));
  if ((ptDesc->type != PG_L1) && (!disableMMUChecks)) {
    panic ("SVA: MMU: update_l1 not an L1: %lx %lx: %lx\n", pteptr, val, ptDesc->type);
  }

  /*
   * Update the page table with the new mapping.
   */
  __update_mapping(pteptr, val);

  /* Restore interrupts */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  record_tsc(sva_update_l1_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Updates a level2 mapping (a mapping to a l1 page).
 *
 * This function checks that the pages involved in the mapping
 * are correct, ie pmdptr is a level2, and val corresponds to
 * a level1.
 */
void
sva_update_l2_mapping(pde_t * pdePtr, page_entry_t val) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr (pdePtr));
  if ((ptDesc->type != PG_L2) && (!disableMMUChecks)) {
    panic ("SVA: MMU: update_l2 not an L2: %lx %lx: type=%lx count=%lx\n", pdePtr, val, ptDesc->type, ptDesc->count);
  }

  /*
   * Update the page mapping.
   */
  __update_mapping(pdePtr, val);

  /* Restore interrupts */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_update_l2_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Updates a level3 mapping 
 */
void sva_update_l3_mapping(pdpte_t * pdptePtr, page_entry_t val) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr (pdptePtr));
  if ((ptDesc->type != PG_L3) && (!disableMMUChecks)) {
    panic ("SVA: MMU: update_l3 not an L3: %lx %lx: %lx\n", pdptePtr, val, ptDesc->type);
  }

  __update_mapping(pdptePtr, val);

  /* Restore interrupts */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();
  record_tsc(sva_update_l3_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * updates a level4 mapping 
 */
void sva_update_l4_mapping (pml4e_t * pml4ePtr, page_entry_t val) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr (pml4ePtr));
  if ((ptDesc->type != PG_L4) && (!disableMMUChecks)) {
    panic ("SVA: MMU: update_l4 not an L4: %lx %lx: %lx\n", pml4ePtr, val, ptDesc->type);
  }


  __update_mapping(pml4ePtr, val);

#ifdef SVA_ASID_PG 
  uintptr_t other_cr3 = ptDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;
  if(other_cr3)
  {
    uintptr_t index = (uintptr_t)pml4ePtr & vmask;
    pml4e_t * kernel_pml4ePtr = (pml4e_t *)((uintptr_t) getVirtual(other_cr3) | index); 
    page_desc_t * kernel_ptDesc = getPageDescPtr(other_cr3);
    if((kernel_ptDesc->type != PG_L4) && (!disableMMUChecks)){
           panic ("SVA: MMU: update_l4 kernel or sva version pte not an L4: %lx %lx: %lx\n", kernel_pml4ePtr, val, kernel_ptDesc->type);
    }

    if(((index >> 3) == PML4PML4I) && ((val & PG_FRAME) == (getPhysicalAddr(pml4ePtr) & PG_FRAME)))
        val = other_cr3 | (val & 0xfff);
    __update_mapping(kernel_pml4ePtr, val);
  }
#endif

  /* Restore interrupts */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  record_tsc(sva_update_l4_mapping_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}


/*
 * Function: sva_create_kernel_pml4pg
 *
 * Description:
 *   Record the kernel version pml4 page table page in the page descriptor
 * of the orignal (user/sva version) pml4 page table page. The kernel version 
 * does not have the mappings of ghost memory and SVA internal memory. 
 * Currently, for the pure purpose of measuring the overhead of ASID and 
 * page table manipulation, this kernel version pml4 page table page is entirely 
 * the same as the user/sva version to walk around a problem 
 * due to the feature of x86, which automatically saves interrupt context on one stack upon trap/interrupt.
 *
 * Input:
 *   orig_phys - the original pml4 page table page
 *   kernel_phys  - the kernel version pml4 page table page
 */

void sva_create_kernel_pml4pg(uintptr_t orig_phys, uintptr_t kernel_phys)
{
   page_desc_t * kernel_ptDesc = getPageDescPtr(kernel_phys);
   page_desc_t * usersva_ptDesc = getPageDescPtr(orig_phys);

   kernel_ptDesc->other_pgPaddr = orig_phys;
   usersva_ptDesc->other_pgPaddr = kernel_phys | PML4_SWITCH_DISABLE;

}

void sva_set_kernel_pml4pg_ready(uintptr_t orig_phys)
{
  page_desc_t * usersva_ptDesc = getPageDescPtr(orig_phys);
  usersva_ptDesc->other_pgPaddr = usersva_ptDesc->other_pgPaddr & ~PML4_SWITCH_DISABLE;

}
