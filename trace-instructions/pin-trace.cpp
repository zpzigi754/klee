/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2017 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include "pin.H"
#include <fstream>
#include <string>

std::ofstream trace;

typedef struct {
  unsigned long ip;
  std::string function;
  std::string assembly;
} instruction_data_t;

std::vector<std::pair<bool, unsigned long>> addresses;
std::vector<std::string> calls;
bool call = false;

VOID log_read_op(VOID *ip, VOID *addr) {
  addresses.push_back(std::make_pair(0, (unsigned long)addr));
}

VOID log_write_op(VOID *ip, VOID *addr) {
  addresses.push_back(std::make_pair(1, (unsigned long)addr));
}

// This function is called before every instruction is executed
// and prints the IP
VOID log_instruction(instruction_data_t *id) {
  if (call) {
    calls.push_back(id->function);
    call = false;
  }

  trace << std::hex << std::uppercase << id->ip << " |";
  for (auto c : calls) {
    trace << " " << c;
  }

  trace << " | " << id->function << " | " << id->assembly << " |";

  for (auto a : addresses) {
    trace << " " << (a.first ? "w" : "r") << a.second;
  }
  addresses.clear();

  trace << std::endl;
}

VOID log_call() { call = true; }

VOID log_return() {
  assert((!calls.empty()) && "Return with no Call.");
  calls.pop_back();
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v) {
  // Insert a call to printins before every instruction
  instruction_data_t *id = new instruction_data_t();
  id->ip = INS_Address(ins);
  id->function = RTN_FindNameByAddress(id->ip);
  id->assembly = INS_Disassemble(ins);

  // Instruments memory accesses using a predicated call, i.e.
  // the instrumentation is called iff the instruction will actually be
  // executed.
  //
  // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
  // prefixed instructions appear as predicated instructions in Pin.
  UINT32 memOperands = INS_MemoryOperandCount(ins);
  // Iterate over each memory operand of the instruction.
  for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
    if (INS_MemoryOperandIsRead(ins, memOp)) {
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)log_read_op,
                               IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                               IARG_END);
    }
    // Note that in some architectures a single memory operand can be
    // both read and written (for instance incl (%eax) on IA-32)
    // In that case we instrument it once for read and once for write.
    if (INS_MemoryOperandIsWritten(ins, memOp)) {
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)log_write_op,
                               IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                               IARG_END);
    }
  }

  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_instruction, IARG_PTR, id,
                 IARG_END);

  if (INS_IsRet(ins)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_return, IARG_END);
  } else if (INS_IsProcedureCall(ins)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_call, IARG_END);
  }
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v) {
  trace << "#eof" << std::endl;
  trace.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage() {
  PIN_ERROR("This Pintool traces each instruction and memory access.\n" +
            KNOB_BASE::StringKnobSummary() + "\n");
  return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {
  trace.open("trace.out", std::ofstream::out);
  trace << "IP | Call Stack | Function | Instruction | Memory Accesses"
        << std::endl;

  // Load debug symbols.
  PIN_InitSymbols();

  // Initialize pin
  if (PIN_Init(argc, argv))
    return Usage();

  // Register Instruction to be called to instrument instructions
  INS_AddInstrumentFunction(Instruction, 0);

  // Register Fini to be called when the application exits
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}
