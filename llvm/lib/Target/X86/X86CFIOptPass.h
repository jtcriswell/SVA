//                     Control-Flow Integrity Implementation
//
// This file was written by Bin Zeng at the Lehigh University CSE Department.
// All Right Reserved.
//
//===----------------------------------------------------------------------===//
// Copyright (c) 2011-2014. Bin Zeng and Gang Tan.
// The SOS lab. Lehigh University.  All rights reserved.
// 
// This software implements the CFI/SFI implementation described by the
// paper "Combining Control-Flow Integrity and Static Analysis for
// Efficient and Validated Data Sandboxing" in ACM CCS 2011.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met: 
// 
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer. 
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution. 
// 
//    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
//    IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
//    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
//    PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
//    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
//    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
//    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//===----------------------------------------------------------------------===//
//
//
// This file defines a machine language level transform that enforces control
// flow integrity.
//
//===----------------------------------------------------------------------===//

#ifndef X86CFIOPTPASS_H
#define X86CFIOPTPASS_H

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "X86TargetMachine.h"

namespace llvm{

  class MachineBasicBlock;
  class MachineInstr;
  class DebugLoc;
  class TargetInstrInfo;
  class MachineFunction;
  
  struct X86CFIOptPass : public MachineFunctionPass {
    // the CFI ID
#if 0
    const static int CFI_ID = 19880616;
#else
    const static int CFI_ID = 0x0000beef;
#endif

    const static bool JTOpt  = true; // jump table index optimization
    const static bool skipID = false; // skip prefetchnta 
  
    // The X86 target machine
    X86TargetMachine &TM;

    // the ID of this pass
    static char ID;
    
    X86CFIOptPass(X86TargetMachine &tm);  

    virtual const char *getPassName() const;  

    virtual void getAnalysisUsage(AnalysisUsage &AU) const;

    // Flag whether we're compiling for 32-bit or 64-bit x86
    bool is64Bit(void) {
      return TM.getSubtarget<X86Subtarget>().is64Bit();
    }

    // Add the code to skip over a prefetchnta CFI label
    void addSkipInstruction (MachineBasicBlock & MBB,
                             MachineInstr * MI,
                             DebugLoc & dl,
                             const TargetInstrInfo * TII,
                             unsigned reg);

    // Add the code to check the CFI label
    void addCheckInstruction (MachineBasicBlock & MBB,
                              MachineInstr * MI,
                              DebugLoc & dl,
                              const TargetInstrInfo * TII,
                              const unsigned reg);

    // insert check before call32r
    void insertCheckCall32r(MachineBasicBlock& MBB, MachineInstr* MI,
              DebugLoc& dl, const TargetInstrInfo* TII,
              MachineBasicBlock* EMBB);
    //insert check before call64r
    void insertCheckCall64r(MachineBasicBlock& MBB, MachineInstr* MI,
              DebugLoc& dl, const TargetInstrInfo* TII,
              MachineBasicBlock* EMBB);
    // insert check before call32m
    void insertCheckCall32m(MachineBasicBlock& MBB, MachineInstr* MI,
              DebugLoc& dl, const TargetInstrInfo* TII,
              MachineBasicBlock* EMBB);
    // insert check before call64m
    void insertCheckCall64m(MachineBasicBlock& MBB, MachineInstr* MI,
              DebugLoc& dl, const TargetInstrInfo* TII,
              MachineBasicBlock* EMBB);
    // insert check before jmp32r
    void insertCheckJmp32r(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);
    // insert check before jmp64r
    void insertCheckJmp64r(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);
    // insert a check before JMP32m
    void insertCheckJmp32m(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);

    // insert a check before TAILJMPm
    void insertCheckTailJmpm(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);
    // insert a check before TAILJMPr
    void insertCheckTailJmpr(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);
  
    // insert a check before JMP64m
    void insertCheckJmp64m(MachineBasicBlock& MBB, MachineInstr* MI,
               DebugLoc& dl, const TargetInstrInfo* TII,
               MachineBasicBlock* EMBB);

    // insert a check before ret using cdecl calling convention
    // %ecx is used for comparision
    void insertCheckRet(MachineBasicBlock& MBB, MachineInstr* MI,
            DebugLoc& dl, const TargetInstrInfo* TII,
            MachineBasicBlock* EMBB);

    // insert a check before reti using cdecl calling convention
    // %ecx is used for comparison
    void insertCheckReti(MachineBasicBlock& MBB, MachineInstr* MI,
             DebugLoc& dl, const TargetInstrInfo* TII,
             MachineBasicBlock *EMBB);

    // insert prefetchnta CFI_ID
    void insertIDFunction(MachineFunction& F, DebugLoc& dl, const TargetInstrInfo* TII);
    
    // insert prefetchnta CFI_ID at the beginning of MBB
    void insertIDBasicBlock(MachineBasicBlock& MBB,
          DebugLoc& dl, const TargetInstrInfo* TII);
    
    // insert prefetchnta CFI_ID at the beginning of the successors of MBB
    void insertIDSuccessors(MachineBasicBlock& MBB,
          DebugLoc& dl, const TargetInstrInfo* TII);

    // insert prefetchnta after call, MI points to the call instruction
    // next points to the inst after call
    void insertIDCall(MachineBasicBlock& MBB, MachineInstr* MI,
            MachineInstr* next, DebugLoc& dl,
            const TargetInstrInfo* TII);
    
    // returns the register number killed by the instruction if any
    // if there are multiple,return the first one
    // if none, return 0
    unsigned getRegisterKilled(MachineInstr* const MI);

    // insert a BasicBlock after MBB
    // the MachineBasicBlock is inserted right before I
    // return the pointer to the new MachineBasicBlock
    MachineBasicBlock* insertBasicBlockBefore(MachineFunction& MF,
                          MachineFunction::iterator I);
  
    // splitMBBAt - Given a machine basic block and an iterator
    // into it, split the MBB so that the part before the
    // iterator falls into the part starting at the iterator.
    // This returns the new MBB
    MachineBasicBlock* splitMBBAt(MachineBasicBlock &CurMBB,
                  MachineBasicBlock::iterator BBI1);

    // returns true if the register used by this instruction is from
    // a jump table entry
    bool fromJmpTable(const MachineInstr* const MI);
  
    virtual bool runOnMachineFunction(MachineFunction &F);

#if 0
    // insert the error label BasicBlock
    void insertErrorLabel();

  
    // do initialization on the module before optimization
    bool doInitialization(Module &M);

    // the function that does the real work
    bool runOnMachineFunction(MachineFunction &MF);

    // do some finalization after optimization is finished
    bool doFinalization(Module &M);
#endif
  };

}

#endif
