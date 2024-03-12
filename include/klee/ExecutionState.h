//===-- ExecutionState.h ----------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_EXECUTIONSTATE_H
#define KLEE_EXECUTIONSTATE_H

#include "klee/Constraints.h"
#include "klee/Expr.h"
#include "klee/Internal/ADT/TreeStream.h"
#include "klee/MergeHandler.h"
#include "klee/util/GetExprSymbols.h"

// FIXME: We do not want to be exposing these? :(
#include "../../lib/Core/AddressSpace.h"
#include "klee/Internal/Module/KInstIterator.h"

//TODO: generalize for otehr LLVM versions like the above
#include <llvm/Analysis/LoopInfo.h>

#include <map>
#include <set>
#include <vector>

namespace llvm {
  class Function;
  class BasicBlock;
}

namespace klee {
class Array;
class CallPathNode;
struct Cell;
struct KFunction;
struct KInstruction;
class MemoryObject;
class PTreeNode;
struct InstructionInfo;

llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const MemoryMap &mm);

struct StackFrame {
  KInstIterator caller;
  KFunction *kf;
  CallPathNode *callPathNode;

  std::vector<const MemoryObject *> allocas;
  Cell *locals;

  /// Minimum distance to an uncovered instruction once the function
  /// returns. This is not a good place for this but is used to
  /// quickly compute the context sensitive minimum distance to an
  /// uncovered instruction. This value is updated by the StatsTracker
  /// periodically.
  unsigned minDistToUncoveredOnReturn;

  // For vararg functions: arguments not passed via parameter are
  // stored (packed tightly) in a local (alloca) memory object. This
  // is set up to match the way the front-end generates vaarg code (it
  // does not pass vaarg through as expected). VACopy is lowered inside
  // of intrinsic lowering.
  MemoryObject *varargs;

  StackFrame(KInstIterator caller, KFunction *kf);
  StackFrame(const StackFrame &s);
  ~StackFrame();
};

struct FieldDescr {
  Expr::Width width;
  std::string name;
  ref<Expr> inVal;
  ref<Expr> outVal;
  std::map<int, FieldDescr> fields;

  bool eq(const FieldDescr& other) const;
};

struct CallArg {
  ref<Expr> expr;
  ref<Expr> val;
  bool isPtr;
  ref<Expr> outVal;
  Expr::Width outWidth;
  llvm::Function* funPtr;
  std::string name;
  std::map<int, FieldDescr> fields;

  bool eq(const CallArg& other) const;
  bool sameInvocationValue(const CallArg& other) const;
};

struct RetVal {
  ref<Expr> expr;
  bool isPtr;
  Expr::Width width;
  ref<Expr> val;
  llvm::Function* funPtr;
  std::map<int, FieldDescr> fields;

  bool eq(const RetVal& other) const;
};

//TODO: Store assumptions increment as well. it is an important part of the call
// these assumptions allow then to correctly match and distinguish call path prefixes.
struct CallInfo {
  llvm::Function* f;
  std::vector< CallArg > args;
  RetVal ret;
  bool returned;
  std::vector< ref<Expr> > callContext;
  std::vector< ref<Expr> > returnContext;

  CallArg* getCallArgPtrp(ref<Expr> ptr);
  bool eq(const CallInfo& other) const;
  bool sameInvocation(const CallInfo* other) const;
  SymbolSet computeSymbolicVariablesSet() const;
  SymbolSet computeInvocationSymbolSet() const;
  SymbolSet computeRetSymbolSet() const;
};

class ExecutionState;

/// @brief LoopInProcess keeps all the necessary information for
/// dynamic loop invariant deduction.
class LoopInProcess {
public:
  /// for the ref class. This count also determines how many
  /// paths are in the loop.
  int refCount;
private: public: //TODO a proper encapsulation.
  const llvm::Loop *loop; //Owner: KFunction::loopInfo
  // No circular dependency here: the restartState must not have
  // loop in process.
  ExecutionState *restartState; //Owner.
  bool lastRoundUpdated;
  std::set<const MemoryObject *> changedObjects;

  ExecutionState *makeRestartState();

public:
  // Captures ownership of the _headerState.
  // TODO: rewrite in terms of std::uniquePtr
  LoopInProcess(llvm::Loop *_loop, ExecutionState *_headerState);
  ~LoopInProcess();

  void updateChangedObjects(const ExecutionState& current);
  ExecutionState* nextRoundState(std::set<const llvm::Loop*> *analyzedLoops);
};

/// @brief ExecutionState representing a path under exploration
class ExecutionState {
public:
  typedef std::vector<StackFrame> stack_ty;

private:
  // unsupported, use copy constructor
  ExecutionState &operator=(const ExecutionState &);

  std::map<std::string, std::string> fnAliases;

public:
  // Execution - Control Flow specific

  /// @brief Pointer to instruction to be executed after the current
  /// instruction
  KInstIterator pc;

  /// @brief Pointer to instruction which is currently executed
  KInstIterator prevPC;

  /// @brief Stack representing the current instruction stream
  stack_ty stack;

  /// @brief Remember from which Basic Block control flow arrived
  /// (i.e. to select the right phi values)
  unsigned incomingBBIndex;

  // Overall state of the state - Data specific

  /// @brief Address space used by this state (e.g. Global and Heap)
  AddressSpace addressSpace;

  /// @brief Information necessary for loop invariant induction.
  /// Owner.
  ref<LoopInProcess> loopInProcess;

  /// @brief This pointer keeps a copy of the state in case
  ///  we will need to process this loop. Owner.
  // TODO: replace with std::unique_ptr;
  ExecutionState *executionStateForLoopInProcess;

  /// @brief Constraints collected so far
  ConstraintManager constraints;

  /// Statistics and information

  /// @brief Costs for all queries issued for this state, in seconds
  mutable double queryCost;

  /// @brief Weight assigned for importance of this state.  Can be
  /// used for searchers to decide what paths to explore
  double weight;

  /// @brief Exploration depth, i.e., number of times KLEE branched for this state
  unsigned depth;

  /// @brief History of complete path: represents branches taken to
  /// reach/create this state (both concrete and symbolic)
  TreeOStream pathOS;

  /// @brief History of symbolic path: represents symbolic branches
  /// taken to reach/create this state
  TreeOStream symPathOS;

  /// @brief Counts how many instructions were executed since the last new
  /// instruction was covered.
  unsigned instsSinceCovNew;

  /// @brief Whether a new instruction was covered in this state
  bool coveredNew;

  /// @brief Disables forking for this state. Set by user code
  bool forkDisabled;

  /// @brief Set containing which lines in which files are covered by this state
  std::map<const std::string *, std::set<unsigned> > coveredLines;

  /// @brief Pointer to the process tree of the current state
  PTreeNode *ptreeNode;

  /// @brief Ordered list of symbolics: used to generate test cases.
  //
  // FIXME: Move to a shared list structure (not critical).
  std::vector<std::pair<const MemoryObject *, const Array *> > symbolics;

  /// @brief Set of used array names for this state.  Used to avoid collisions.
  std::set<std::string> arrayNames;

  std::vector<CallInfo> callPath;

  std::string getFnAlias(std::string fn);
  void addFnAlias(std::string old_fn, std::string new_fn);
  void removeFnAlias(std::string fn);

  // The objects handling the klee_open_merge calls this state ran through
  std::vector<ref<MergeHandler> > openMergeStack;

  // The numbers of times this state has run through Executor::stepInstruction
  std::uint64_t steppedInstructions;

private:
  ExecutionState() : ptreeNode(0) {}

public:
  ExecutionState(KFunction *kf);

  // XXX total hack, just used to make a state so solver can
  // use on structure
  ExecutionState(const std::vector<ref<Expr> > &assumptions);

  ExecutionState(const ExecutionState &state);

  ~ExecutionState();

  ExecutionState *branch();

  void pushFrame(KInstIterator caller, KFunction *kf);
  void popFrame();

  void addSymbolic(const MemoryObject *mo, const Array *array);
  void addConstraint(ref<Expr> e) { constraints.addConstraint(e); }

  bool merge(const ExecutionState &b);
  void dumpStack(llvm::raw_ostream &out) const;
  ref<Expr> readMemoryChunk(ref<Expr> addr,
                            Expr::Width width) const;
  void traceArgValue(ref<Expr> val, std::string name);
  void traceArgPtr(ref<Expr> arg, Expr::Width width,
                   std::string name);
  void traceArgFunPtr(ref<Expr> arg,
                      std::string name);
  void traceRet();
  void traceRetPtr(Expr::Width width);
  void traceArgPtrField(ref<Expr> arg, int offset,
                        Expr::Width width, std::string name);
  void traceArgPtrNestedField(ref<Expr> arg, int base_offset, int offset,
                              Expr::Width width, std::string name);
  void traceRetPtrField(int offset, Expr::Width width, std::string name);
  void traceRetPtrNestedField(int base_offset, int offset,
                              Expr::Width width, std::string name);

  void doNotResetThis(const ref<ConstantExpr> &addr,
                      Expr::Width w);
  void symbolizeConcretes();
  ExecutionState* finishLoopRound(std::set<const llvm::Loop *> *analyzedLoops);
  void updateLoopAnalysisForBlockTransfer(llvm::BasicBlock *dst,
                                          llvm::BasicBlock *src,
                                          bool *terminate,
                                          ExecutionState **addState);
  std::vector<ref<Expr> > relevantConstraints(SymbolSet symbols) const;
};
}

//#define DO_LOG_LOOP_ANALYSIS
#ifdef DO_LOG_LOOP_ANALYSIS
#define LOG_LA(expr) \
  llvm::errs() <<"[LA]" <<__FILE__ <<":" <<__LINE__ \
  <<": " << expr <<"\n";
#else//DO_LOG_LOOP_ANALYSIS
#define LOG_LA(expr)
#endif//DO_LOG_LOOP_ANALYSIS

#endif
