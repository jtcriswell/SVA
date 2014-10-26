//===-- X86CFIAlignPass.h - CFI Alignment Pass for Intel X86 --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
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
//    THE IMPLIED
//    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
//    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
//    THE POSSIBILITY OF SUCH DAMAGE.
//
//===----------------------------------------------------------------------===//
//
// This file defines a Machine Function pass that adds NOP padding instructions
// so that all instructions are aligned properly for control-flow integrity
// (CFI).
//
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "X86TargetMachine.h"

namespace llvm {
  struct X86CFIAlignPass : public MachineFunctionPass {
    public:
      // The pass identifier
      static char ID;

      // Pass constructor
      X86CFIAlignPass (X86TargetMachine & tm) : MachineFunctionPass(ID) {
        return;
      }

      // Return the name of the pass
      const char * getPassName(void) const {
        return "X86 CFI Alignment Pass";
      }

      // Get analysis passed needed and preserved by this pass
      virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        // This pass does not modify the control-flow graph of the function
        AU.setPreservesCFG();
        return;
      }

      virtual bool runOnMachineFunction (MachineFunction &F);
  };
}

