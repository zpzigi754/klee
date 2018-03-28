/* -*- mode: c++; c-basic-offset: 2; -*- */

//===-- ktest-dehavoc.cpp ---------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/perf-contracts.h"
#include "llvm/Support/CommandLine.h"
#include <dlfcn.h>
#include <iostream>

namespace {
llvm::cl::opt<std::string>
    ContractLib("contract",
                llvm::cl::desc("A performance contract library to load that "
                               "describes the data structure performance."),
                llvm::cl::Required);

llvm::cl::opt<std::string> InputCallPathFile(llvm::cl::desc("<call path>"),
                                             llvm::cl::Positional,
                                             llvm::cl::Required);

llvm::cl::opt<std::string>
    InputInstructionTraceFile(llvm::cl::desc("<instruction trace>"),
                              llvm::cl::Positional, llvm::cl::Required);
}

int main(int argc, char **argv, char **envp) {
  llvm::cl::ParseCommandLineOptions(argc, argv);

  dlerror();
  const char *err = NULL;
  void *contract = dlopen(ContractLib.c_str(), RTLD_NOW);
  if ((err = dlerror())) {
    std::cout << "Error loading contract plugin " << ContractLib << ": " << err
              << std::endl;
    exit(-1);
  }
  assert(contract);

  // Get contract symbols
  LOAD_SYMBOL(contract, contract_init);
  LOAD_SYMBOL(contract, contract_get_user_variables);
  LOAD_SYMBOL(contract, contract_has_contract);
  LOAD_SYMBOL(contract, contract_get_optimization_variables);
  LOAD_SYMBOL(contract, contract_num_sub_contracts);
  LOAD_SYMBOL(contract, contract_get_subcontract_constraints);
  LOAD_SYMBOL(contract, contract_get_sub_contract_performance);

  contract_init();

  return 0;
}
