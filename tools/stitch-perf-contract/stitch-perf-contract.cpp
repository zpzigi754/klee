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

llvm::cl::opt<std::string> UserVariables(
    "user-vars",
    llvm::cl::desc("Sets the value of user variables (var1=val1,var2=val2)."));

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
    std::cerr << "Error loading contract plugin " << ContractLib << ": " << err
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

  std::map<std::string, std::string> user_variables =
      contract_get_user_variables();

  std::string user_variables_string = UserVariables;
  while (!user_variables_string.empty()) {
    std::string user_variable_string =
        user_variables_string.substr(0, user_variables_string.find(","));
    user_variables_string =
        user_variable_string.size() == user_variables_string.size()
            ? ""
            : user_variables_string.substr(user_variable_string.size() + 1);

    std::string user_var =
        user_variable_string.substr(0, user_variable_string.find("="));
    std::string user_val =
        user_variable_string.substr(user_variable_string.find("=") + 1);

    if (!user_variables.count(user_var)) {
      std::cerr << "User variable " << user_var << " not defined in contract."
                << std::endl
                << "Valid user variables:" << std::endl;
      for (auto it : user_variables) {
        std::cerr << "  " << it.first << std::endl;
      }
      exit(-1);
    }
  }

  return 0;
}
