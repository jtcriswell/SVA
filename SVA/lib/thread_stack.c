/*===- thread_stack.c - SVA Execution Engine  -----------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file implements the stack of thread contexts.
 *
 *===----------------------------------------------------------------------===
 */

#include "sva/config.h"
#include "sva/callbacks.h"
#include "keys.h"
#include "thread_stack.h"

/*
 * Prototype of [static] functions used outside this module (and therefore not defined in a header)
 */
static inline struct SVAThread *ftstack_pop(void);

/* Definitions of functions and variables related to the stack
   that is used for finding the next free thread.
*/
#define THREAD_STACK_SIZE 4096
#define spin_lock(l)  while (__sync_lock_test_and_set((l), 1))
#define spin_unlock(l) __sync_lock_release((l))
#define init_lock(l) *(l) = 0
#define NULL  0

/* Pre-allocate a large number of SVA Threads */
static struct SVAThread Threads[THREAD_STACK_SIZE] __attribute__ ((aligned (16)))
__attribute__ ((section ("svamem")));

typedef volatile int lock_t;

/* Stack for storing the free treads */
struct FT_stack{
  struct SVAThread *threads[THREAD_STACK_SIZE];
  int top;
  int initialized;
  lock_t lock;
};

/* Initialization of the stack */
static struct FT_stack fthreads __attribute__ ((aligned (16))) __attribute__ ((section ("svamem"))) = {
  .top = -1,
  .lock = 0,
  .initialized = 0,
};

/* Push function for the stack. The action has to be protected by a spinlock. */
void ftstack_push(struct SVAThread *thread){
  spin_lock(&fthreads.lock);

  fthreads.top++;
  if (fthreads.top >= THREAD_STACK_SIZE) {
    spin_unlock(&fthreads.lock);
    panic("SVA: ftstack_push: Free-thread stack is full.\n");
    //This could only happen if we somehow double-free a thread.
    return;
  }
  fthreads.threads[fthreads.top] = thread;

  spin_unlock(&fthreads.lock);
}

/* Pop function for the stack. */
static inline struct SVAThread *ftstack_pop(void) {

  struct SVAThread *result = NULL;

  spin_lock(&fthreads.lock);

  if(!fthreads.initialized) {

    for (unsigned index = 0; index < THREAD_STACK_SIZE; ++index) {
      Threads[index].used = 0;
      fthreads.top++;
      fthreads.threads[fthreads.top] = &Threads[index];
    }

    fthreads.initialized = 1;
  }

  if(fthreads.top == -1) {
    spin_unlock(&fthreads.lock);
    panic("SVA: ftstack_pop: No free threads available!\n");
    return NULL;
  }

  result = fthreads.threads[fthreads.top];
  fthreads.top--;

  spin_unlock(&fthreads.lock);

  return result;
}

void
init_threads(void) {
  return;
}

/*
 * Function: randomNumber()
 *
 * Description:
 *  Use the rdrand instruction to generate a 64-bit random number.
 */
static inline uintptr_t
randomNumber (void) {
  uintptr_t rand;
  __asm__ __volatile__ ("1: rdrand %0\n"
                        "jae 1b\n" : "=r" (rand));
  return rand;
}

/*
 * Function: validateThreadPointer()
 *
 * Description:
 *  Determines that an unsigned integer provided as input is a valid pointer to
 *  a SVAThread instance.
 *
 * Returns: NULL if pointer was invalid, else a pointer to the valid SVAThread instance
 */
struct SVAThread *
validateThreadPointer(uintptr_t p) {
  if (p < (uintptr_t) Threads) {
    panic("SVA: validateThreadPointer: below start of array");
    //p is below the start of the array
    return NULL;
  }

  uintptr_t offset = p - (uintptr_t)Threads;
  uintptr_t thread_alignment = ((uintptr_t)(Threads+1)) - ((uintptr_t)Threads);
  uintptr_t index = offset / thread_alignment;
  if (offset % thread_alignment){
    //p does not point to the start of a thread
    panic("SVA: validateThreadPointer: invalid offset");
    return NULL;
  }

  if (index < THREAD_STACK_SIZE) {
    //We've got a live one
    return (struct SVAThread*)p;
  }

  //We weren't within the bounds of the array
  panic("SVA: validateThreadPointer: above end of array");
  return NULL;
}

/*
 * Function: findNextFreeThread()
 *
 * Description:
 *  This function returns the index of the next thread which is not in use.
 */
struct SVAThread *
findNextFreeThread (void) {
  /*
   * Find the next free thread.
   */
  struct SVAThread *newThread = ftstack_pop();
  if (newThread) {
    /*
     * Do some basic initialization of the thread.
     */
    newThread->integerState.valid = 0;
    newThread->savedICIndex = 0;
    newThread->ICFPIndex = 0;
    newThread->secmemSize = 0;
    newThread->numPushTargets = 0;
    newThread->secmemPML4e = 0;
    newThread->isInitialForCPU = 0;

    /*
     * This function currently sets the thread secret with a default
     * statically defined key.  However, in the future will obtain said key
     * from the executable image.  There is also some issue with
     * bootstrapping the initial key and whether or not on the first
     * execution of an application the key will need to be generated by SVA.
     * Thus, future design is yet to be done, however, the following function
     * should suffice to enable any of the above scenarios.
     *
     * TODO: The function currently uses a dummy static key, but in the
     * future will obtain the key from the executable image and then
     * decrypted with the VirtualGhost private key.
     */
    if (vg) {
      init_thread_key(newThread);
    }

#if DEBUG
    printf("<<<< SVA: Created new private key: value: %s\n",
            newThread->secret.key);
#endif

    /*
     * Use the next-to-last interrupt context in the list as the first
     * interrupt context.  This may be slightly wasteful, but it's a little
     * easier to make it work correctly right now.
     *
     * The processor's IST3 field should be configured so that the next
     * interrupt context is at maxIC - 2.
     */
    sva_icontext_t * icontextp = newThread->interruptContexts + maxIC - 1;
    newThread->integerState.ist3 = ((uintptr_t) icontextp) - 0x10;
    newThread->integerState.kstackp = newThread->integerState.ist3;

    /*
     * Generate a random identifier for the new thread.
     */
    if (vg) {
      newThread->rid = randomNumber();
    }
    return newThread;
  }

  panic ("SVA: findNextFreeThread: Exhausted SVA Threads!\n");
  return 0;
}

