/* -*- mode: c++; c-basic-offset: 2; -*- */

//===-- ktest-dehavoc.cpp ---------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Internal/ADT/KTest.h"
#include "llvm/Support/CommandLine.h"
#include <iostream>
#include <map>
#include <vector>

#define HAVOC_PREFIX "reset_"

namespace {
llvm::cl::opt<std::string> InputFile(llvm::cl::desc("<input ktest>"),
                                     llvm::cl::Positional, llvm::cl::init("-"));

llvm::cl::opt<std::string> OutputFile(llvm::cl::desc("<output ktest>"),
                                      llvm::cl::Positional,
                                      llvm::cl::init("-"));
}

int main(int argc, char **argv, char **envp) {
  llvm::cl::ParseCommandLineOptions(argc, argv);

  KTest *in = kTest_fromFile(InputFile.c_str());
  assert(in && "Error opening input KTEST file.");

  KTest out;
  out.numArgs = in->numArgs;
  out.args = in->args;
  out.symArgvs = in->symArgvs;
  out.symArgvLen = in->symArgvLen;

  std::vector<KTestObject> objects(in->objects, in->objects + in->numObjects);
  std::map<std::string, KTestObject> havoced_objects;

  for (auto it : objects) {
    std::string name = it.name;

    if (!name.compare(0, sizeof(HAVOC_PREFIX) - 1, HAVOC_PREFIX)) {
      while (!name.compare(0, sizeof(HAVOC_PREFIX) - 1, HAVOC_PREFIX)) {
        // Drop prefix.
        name = name.substr(sizeof(HAVOC_PREFIX) - 1);
        // Drop suffix.
        name = name.substr(0, name.rfind("_"));
      }

      havoced_objects[name] = it;
    }
  }

  for (auto it = objects.begin(); it != objects.end();) {
    std::string name = it->name;

    if (!name.compare(0, sizeof(HAVOC_PREFIX) - 1, HAVOC_PREFIX)) {
      it = objects.erase(it);
    } else {
      if (havoced_objects.count(name)) {
        std::cout << "Dehavocing " << name << std::endl;
        *it = havoced_objects[name];
        it->name = (char *) (new std::string(name))->c_str();
      }
      it++;
    }
  }

  out.numObjects = objects.size();
  out.objects = objects.data();

  assert(kTest_toFile(&out, OutputFile.c_str()) &&
         "Error writing output KTEST file.");
}
