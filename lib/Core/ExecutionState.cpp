//===-- ExecutionState.cpp ------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/ExecutionState.h"

#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/InstructionInfoTable.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"

#include "klee/Expr.h"

#include "Memory.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include <iomanip>
#include <sstream>
#include <cassert>
#include <map>
#include <set>
#include <stdarg.h>

using namespace llvm;
using namespace klee;

namespace { 
  cl::opt<bool>
  DebugLogStateMerge("debug-log-state-merge");
}

/***/

StackFrame::StackFrame(KInstIterator _caller, KFunction *_kf)
  : caller(_caller), kf(_kf), callPathNode(0), 
    minDistToUncoveredOnReturn(0), varargs(0) {
  locals = new Cell[kf->numRegisters];
}

StackFrame::StackFrame(const StackFrame &s) 
  : caller(s.caller),
    kf(s.kf),
    callPathNode(s.callPathNode),
    allocas(s.allocas),
    minDistToUncoveredOnReturn(s.minDistToUncoveredOnReturn),
    varargs(s.varargs) {
  locals = new Cell[s.kf->numRegisters];
  for (unsigned i=0; i<s.kf->numRegisters; i++)
    locals[i] = s.locals[i];
}

StackFrame::~StackFrame() { 
  delete[] locals; 
}

/***/

ExecutionState::ExecutionState(KFunction *kf) :
    pc(kf->instructions),
    prevPC(pc),

    queryCost(0.), 
    weight(1),
    depth(0),

    instsSinceCovNew(0),
    coveredNew(false),
    forkDisabled(false),
    ptreeNode(0),
    steppedInstructions(0){
  pushFrame(0, kf);
}

ExecutionState::ExecutionState(const std::vector<ref<Expr> > &assumptions)
    : constraints(assumptions), queryCost(0.), ptreeNode(0) {}

ExecutionState::~ExecutionState() {
  for (unsigned int i=0; i<symbolics.size(); i++)
  {
    const MemoryObject *mo = symbolics[i].first;
    assert(mo->refCount > 0);
    mo->refCount--;
    if (mo->refCount == 0)
      delete mo;
  }

  for (auto cur_mergehandler: openMergeStack){
    cur_mergehandler->removeOpenState(this);
  }


  while (!stack.empty()) popFrame();
}

ExecutionState::ExecutionState(const ExecutionState& state):
    fnAliases(state.fnAliases),
    pc(state.pc),
    prevPC(state.prevPC),
    stack(state.stack),
    incomingBBIndex(state.incomingBBIndex),

    addressSpace(state.addressSpace),
    loopInProcess(state.loopInProcess) ,
    constraints(state.constraints),

    queryCost(state.queryCost),
    weight(state.weight),
    depth(state.depth),

    pathOS(state.pathOS),
    symPathOS(state.symPathOS),

    instsSinceCovNew(state.instsSinceCovNew),
    coveredNew(state.coveredNew),
    forkDisabled(state.forkDisabled),
    coveredLines(state.coveredLines),
    ptreeNode(state.ptreeNode),
    symbolics(state.symbolics),
    arrayNames(state.arrayNames),
    openMergeStack(state.openMergeStack),
    steppedInstructions(state.steppedInstructions),
    callPath(state.callPath)
{
  for (unsigned int i=0; i<symbolics.size(); i++)
    symbolics[i].first->refCount++;

  for (auto cur_mergehandler: openMergeStack)
    cur_mergehandler->addOpenState(this);
}

ExecutionState *ExecutionState::branch() {
  depth++;

  ExecutionState *falseState = new ExecutionState(*this);
  falseState->coveredNew = false;
  falseState->coveredLines.clear();

  weight *= .5;
  falseState->weight -= weight;

  return falseState;
}

void ExecutionState::pushFrame(KInstIterator caller, KFunction *kf) {
  stack.push_back(StackFrame(caller,kf));
}

void ExecutionState::popFrame() {
  StackFrame &sf = stack.back();
  for (std::vector<const MemoryObject*>::iterator it = sf.allocas.begin(), 
         ie = sf.allocas.end(); it != ie; ++it)
    addressSpace.unbindObject(*it);
  stack.pop_back();
}

void ExecutionState::addSymbolic(const MemoryObject *mo, const Array *array) { 
  mo->refCount++;
  symbolics.push_back(std::make_pair(mo, array));
}
///

std::string ExecutionState::getFnAlias(std::string fn) {
  std::map < std::string, std::string >::iterator it = fnAliases.find(fn);
  if (it != fnAliases.end())
    return it->second;
  else return "";
}

void ExecutionState::addFnAlias(std::string old_fn, std::string new_fn) {
  fnAliases[old_fn] = new_fn;
}

void ExecutionState::removeFnAlias(std::string fn) {
  fnAliases.erase(fn);
}

/**/

llvm::raw_ostream &klee::operator<<(llvm::raw_ostream &os, const MemoryMap &mm) {
  os << "{";
  MemoryMap::iterator it = mm.begin();
  MemoryMap::iterator ie = mm.end();
  if (it!=ie) {
    os << "MO" << it->first->id << ":" << it->second;
    for (++it; it!=ie; ++it)
      os << ", MO" << it->first->id << ":" << it->second;
  }
  os << "}";
  return os;
}

bool ExecutionState::merge(const ExecutionState &b) {
  if (DebugLogStateMerge)
    llvm::errs() << "-- attempting merge of A:" << this << " with B:" << &b
                 << "--\n";
  if (pc != b.pc)
    return false;

  if ((!loopInProcess.isNull()) || !b.loopInProcess.isNull()) {
    llvm::errs() <<"-- Loop in process: merge unsupported "
                 << "for loop invariant analysis.\n";
    return false;
  }

  // XXX is it even possible for these to differ? does it matter? probably
  // implies difference in object states?
  if (symbolics!=b.symbolics)
    return false;

  {
    std::vector<StackFrame>::const_iterator itA = stack.begin();
    std::vector<StackFrame>::const_iterator itB = b.stack.begin();
    while (itA!=stack.end() && itB!=b.stack.end()) {
      // XXX vaargs?
      if (itA->caller!=itB->caller || itA->kf!=itB->kf)
        return false;
      ++itA;
      ++itB;
    }
    if (itA!=stack.end() || itB!=b.stack.end())
      return false;
  }

  std::set< ref<Expr> > aConstraints(constraints.begin(), constraints.end());
  std::set< ref<Expr> > bConstraints(b.constraints.begin(), 
                                     b.constraints.end());
  std::set< ref<Expr> > commonConstraints, aSuffix, bSuffix;
  std::set_intersection(aConstraints.begin(), aConstraints.end(),
                        bConstraints.begin(), bConstraints.end(),
                        std::inserter(commonConstraints, commonConstraints.begin()));
  std::set_difference(aConstraints.begin(), aConstraints.end(),
                      commonConstraints.begin(), commonConstraints.end(),
                      std::inserter(aSuffix, aSuffix.end()));
  std::set_difference(bConstraints.begin(), bConstraints.end(),
                      commonConstraints.begin(), commonConstraints.end(),
                      std::inserter(bSuffix, bSuffix.end()));
  if (DebugLogStateMerge) {
    llvm::errs() << "\tconstraint prefix: [";
    for (std::set<ref<Expr> >::iterator it = commonConstraints.begin(),
                                        ie = commonConstraints.end();
         it != ie; ++it)
      llvm::errs() << *it << ", ";
    llvm::errs() << "]\n";
    llvm::errs() << "\tA suffix: [";
    for (std::set<ref<Expr> >::iterator it = aSuffix.begin(),
                                        ie = aSuffix.end();
         it != ie; ++it)
      llvm::errs() << *it << ", ";
    llvm::errs() << "]\n";
    llvm::errs() << "\tB suffix: [";
    for (std::set<ref<Expr> >::iterator it = bSuffix.begin(),
                                        ie = bSuffix.end();
         it != ie; ++it)
      llvm::errs() << *it << ", ";
    llvm::errs() << "]\n";
  }

  // We cannot merge if addresses would resolve differently in the
  // states. This means:
  // 
  // 1. Any objects created since the branch in either object must
  // have been free'd.
  //
  // 2. We cannot have free'd any pre-existing object in one state
  // and not the other

  if (DebugLogStateMerge) {
    llvm::errs() << "\tchecking object states\n";
    llvm::errs() << "A: " << addressSpace.objects << "\n";
    llvm::errs() << "B: " << b.addressSpace.objects << "\n";
  }
    
  std::set<const MemoryObject*> mutated;
  MemoryMap::iterator ai = addressSpace.objects.begin();
  MemoryMap::iterator bi = b.addressSpace.objects.begin();
  MemoryMap::iterator ae = addressSpace.objects.end();
  MemoryMap::iterator be = b.addressSpace.objects.end();
  for (; ai!=ae && bi!=be; ++ai, ++bi) {
    if (ai->first != bi->first) {
      if (DebugLogStateMerge) {
        if (ai->first < bi->first) {
          llvm::errs() << "\t\tB misses binding for: " << ai->first->id << "\n";
        } else {
          llvm::errs() << "\t\tA misses binding for: " << bi->first->id << "\n";
        }
      }
      return false;
    }
    if (ai->second != bi->second) {
      if (DebugLogStateMerge)
        llvm::errs() << "\t\tmutated: " << ai->first->id << "\n";
      mutated.insert(ai->first);
    }
  }
  if (ai!=ae || bi!=be) {
    if (DebugLogStateMerge)
      llvm::errs() << "\t\tmappings differ\n";
    return false;
  }
  
  // merge stack

  ref<Expr> inA = ConstantExpr::alloc(1, Expr::Bool);
  ref<Expr> inB = ConstantExpr::alloc(1, Expr::Bool);
  for (std::set< ref<Expr> >::iterator it = aSuffix.begin(), 
         ie = aSuffix.end(); it != ie; ++it)
    inA = AndExpr::create(inA, *it);
  for (std::set< ref<Expr> >::iterator it = bSuffix.begin(), 
         ie = bSuffix.end(); it != ie; ++it)
    inB = AndExpr::create(inB, *it);

  // XXX should we have a preference as to which predicate to use?
  // it seems like it can make a difference, even though logically
  // they must contradict each other and so inA => !inB

  std::vector<StackFrame>::iterator itA = stack.begin();
  std::vector<StackFrame>::const_iterator itB = b.stack.begin();
  for (; itA!=stack.end(); ++itA, ++itB) {
    StackFrame &af = *itA;
    const StackFrame &bf = *itB;
    for (unsigned i=0; i<af.kf->numRegisters; i++) {
      ref<Expr> &av = af.locals[i].value;
      const ref<Expr> &bv = bf.locals[i].value;
      if (av.isNull() || bv.isNull()) {
        // if one is null then by implication (we are at same pc)
        // we cannot reuse this local, so just ignore
      } else {
        av = SelectExpr::create(inA, av, bv);
      }
    }
  }

  for (std::set<const MemoryObject*>::iterator it = mutated.begin(), 
         ie = mutated.end(); it != ie; ++it) {
    const MemoryObject *mo = *it;
    const ObjectState *os = addressSpace.findObject(mo);
    const ObjectState *otherOS = b.addressSpace.findObject(mo);
    assert(os && !os->readOnly && 
           "objects mutated but not writable in merging state");
    assert(otherOS);

    ObjectState *wos = addressSpace.getWriteable(mo, os);
    for (unsigned i=0; i<mo->size; i++) {
      ref<Expr> av = wos->read8(i);
      ref<Expr> bv = otherOS->read8(i);
      wos->write(i, SelectExpr::create(inA, av, bv));
    }
  }

  constraints = ConstraintManager();
  for (std::set< ref<Expr> >::iterator it = commonConstraints.begin(), 
         ie = commonConstraints.end(); it != ie; ++it)
    constraints.addConstraint(*it);
  constraints.addConstraint(OrExpr::create(inA, inB));

  return true;
}

void ExecutionState::dumpStack(llvm::raw_ostream &out) const {
  unsigned idx = 0;
  const KInstruction *target = prevPC;
  for (ExecutionState::stack_ty::const_reverse_iterator
         it = stack.rbegin(), ie = stack.rend();
       it != ie; ++it) {
    const StackFrame &sf = *it;
    Function *f = sf.kf->function;
    const InstructionInfo &ii = *target->info;
    out << "\t#" << idx++;
    std::stringstream AssStream;
    AssStream << std::setw(8) << std::setfill('0') << ii.assemblyLine;
    out << AssStream.str();
    out << " in " << f->getName().str() << " (";
    // Yawn, we could go up and print varargs if we wanted to.
    unsigned index = 0;
    for (Function::arg_iterator ai = f->arg_begin(), ae = f->arg_end();
         ai != ae; ++ai) {
      if (ai!=f->arg_begin()) out << ", ";

      out << ai->getName().str();
      // XXX should go through function
      ref<Expr> value = sf.locals[sf.kf->getArgRegister(index++)].value;
      if (value.get() && isa<ConstantExpr>(value))
        out << "=" << value;
    }
    out << ")";
    if (ii.file != "")
      out << " at " << ii.file << ":" << ii.line;
    out << "\n";
    target = sf.caller;
  }
}

bool symbolSetsIntersect(const SymbolSet& a, const SymbolSet& b) {
  if (a.size() > b.size()) return symbolSetsIntersect(b, a);
  for (SymbolSet::const_iterator i = a.begin(), e = a.end(); i != e; ++i) {
    if (b.count(*i)) return true;
  }
  return false;
}

std::vector<ref<Expr> > ExecutionState::
relevantConstraints(SymbolSet symbols) const {
  std::vector<ref<Expr> > ret;
  for (ConstraintManager::constraint_iterator ci = constraints.begin(),
         cEnd = constraints.end(); ci != cEnd; ++ci) {
    SymbolSet constrainedSymbols = GetExprSymbols::visit(*ci);
    if (symbolSetsIntersect(constrainedSymbols, symbols)) {
      symbols.insert(constrainedSymbols.begin(), constrainedSymbols.end());
      ret.push_back(*ci);
    }
  }
  return ret;
}

ref<Expr> ExecutionState::readMemoryChunk(ref<Expr> addr,
                                          Expr::Width width) const {
  ObjectPair op;
  ref<klee::ConstantExpr> address = cast<klee::ConstantExpr>(addr);
  bool success = addressSpace.resolveOne(address, op);
  assert(success && "Unknown pointer result!");
  const MemoryObject *mo = op.first;
  const ObjectState *os = op.second;
  //FIXME: assume inbounds.
  ref<Expr> offset = mo->getOffsetExpr(address);
  return os->read(offset, width);
}

void ExecutionState::traceRet() {
  if (callPath.empty() ||
      callPath.back().f != stack.back().kf->function) {
    assert((callPath.empty() || callPath.back().returned) &&
           "Nested traced functions are not supported.");
    callPath.push_back(CallInfo());
    callPath.back().f = stack.back().kf->function;
    callPath.back().returned = false;
  }
}

void ExecutionState::traceRetPtr(Expr::Width width) {
  traceRet();
  RetVal *ret = &callPath.back().ret;
  ret->isPtr = true;
  ret->width = width;
}

void ExecutionState::traceArgValue(ref<Expr> val, std::string name) {
  traceRet();
  callPath.back().args.push_back(CallArg());
  CallArg *argInfo = &callPath.back().args.back();
  argInfo->expr = val;
  argInfo->isPtr = false;
  argInfo->name = name;
  std::vector<ref<Expr> > constrs =
    relevantConstraints(GetExprSymbols::visit(val));
  callPath.back().callContext.insert(callPath.back().callContext.end(),
                                     constrs.begin(), constrs.end());
}

void ExecutionState::traceArgPtr(ref<Expr> arg, Expr::Width width,
                                 std::string name) {
  traceArgValue(arg, name);
  CallArg *argInfo = &callPath.back().args.back();
  argInfo->isPtr = true;
  argInfo->outWidth = width;
  argInfo->funPtr = NULL;
  argInfo->val = readMemoryChunk(arg, width);
  SymbolSet symbols = GetExprSymbols::visit(arg);
  SymbolSet indirectSymbols = GetExprSymbols::visit(argInfo->val);
  symbols.insert(indirectSymbols.begin(), indirectSymbols.end());
  std::vector<ref<Expr> > constrs = relevantConstraints(symbols);
  callPath.back().callContext.insert(callPath.back().callContext.end(),
                              constrs.begin(), constrs.end());
}

void ExecutionState::traceArgFunPtr(ref<Expr> arg,
                                    std::string name) {
  traceArgValue(arg, name);
  CallArg *argInfo = &callPath.back().args.back();
  argInfo->isPtr = true;
  ref<klee::ConstantExpr> address = cast<klee::ConstantExpr>(arg);
  argInfo->funPtr = (Function*)address->getZExtValue();
}

void ExecutionState::traceArgPtrField(ref<Expr> arg,
                                      int offset,
                                      Expr::Width width,
                                      std::string name) {
  assert(!callPath.empty() &&
         callPath.back().f == stack.back().kf->function &&
         "Must trace the function first to trace a particular field.");
  CallArg *argInfo = callPath.back().getCallArgPtrp(arg);
  assert(argInfo != 0 &&
         "Must first trace the pointer arg to trace a particular field.");
  assert(argInfo->outWidth > 0 && "Cannot fit a field into zero bytes.");
  assert(argInfo->fields.count(offset) == 0 && "Conflicting field.");
  FieldDescr descr;
  descr.width = width;
  descr.name = name;
  size_t base = (cast<ConstantExpr>(arg))->getZExtValue();
  ref<ConstantExpr> addrExpr = ConstantExpr::alloc(base + offset, sizeof(size_t)*8);
  descr.inVal = readMemoryChunk(addrExpr, width);
  argInfo->fields[offset] = descr;
}

void ExecutionState::traceArgPtrNestedField(ref<Expr> arg,
                                            int base_offset,
                                            int offset,
                                            Expr::Width width,
                                            std::string name) {
  assert(!callPath.empty() &&
         callPath.back().f == stack.back().kf->function &&
         "Must trace the function first to trace a particular field.");
  CallArg *argInfo = callPath.back().getCallArgPtrp(arg);
  assert(argInfo != 0 &&
         "Must first trace the pointer arg to trace a particular field.");
  assert(argInfo->outWidth > 0 && "Cannot fit a field into zero bytes.");
  assert(argInfo->fields.count(base_offset) != 0 &&
         "Must first trace the field itself.");
  assert(argInfo->fields[base_offset].fields.count(offset) == 0 &&
         "Conflicting field.");
  FieldDescr descr;
  descr.width = width;
  descr.name = name;
  size_t base = (cast<ConstantExpr>(arg))->getZExtValue();
  ref<ConstantExpr> addrExpr = ConstantExpr::alloc(base + base_offset + offset, sizeof(size_t)*8);
  descr.inVal = readMemoryChunk(addrExpr, width);
  argInfo->fields[base_offset].fields[offset] = descr;
}

void ExecutionState::traceRetPtrField(int offset,
                                      Expr::Width width,
                                      std::string name) {
  assert(!callPath.empty() &&
         callPath.back().f == stack.back().kf->function &&
         "Must trace the function first to trace a particular field.");
  RetVal *ret = &callPath.back().ret;
  assert(ret->isPtr && "Only a pointer can have fields traced.");
  assert(ret->width > 0 && "Cannot fit a field in zero sized mem chunk.");
  assert(ret->fields.count(offset) == 0 && "Fields conflict");
  FieldDescr descr;
  descr.width = width;
  descr.name = name;
  ret->fields[offset] = descr;
}

void ExecutionState::traceRetPtrNestedField(int base_offset,
                                            int offset,
                                            Expr::Width width,
                                            std::string name) {
  assert(!callPath.empty() &&
         callPath.back().f == stack.back().kf->function &&
         "Must trace the function first to trace a particular field.");
  RetVal *ret = &callPath.back().ret;
  assert(ret->isPtr && "Only a pointer can have fields traced.");
  assert(ret->width > 0 && "Cannot fit a field in zero sized mem chunk.");
  assert(ret->fields.count(base_offset) != 0 &&
         "Must first trace the base field.");
  assert(ret->fields[base_offset].fields.count(offset) == 0 && "Fields conflict");
  FieldDescr descr;
  descr.width = width;
  descr.name = name;
  ret->fields[base_offset].fields[offset] = descr;
}

void ExecutionState::doNotResetThis(const ref<ConstantExpr> &addr,
                                    Expr::Width w) {
  ObjectPair op;
  if (!addressSpace.resolveOne(addr, op)) {
    llvm::errs() << "Can not remember this address:" <<
      addr->getZExtValue() <<": NOT FOUND\n";
    return;
  }
  const MemoryObject *mo = op.first;
  ref<Expr> offset = mo->getOffsetExpr(addr);
  assert(isa<klee::ConstantExpr>(offset));
  uint64_t offset_val = (cast<klee::ConstantExpr>(offset))->getZExtValue();
  //TODO check bounds.
  const ObjectState *os = op.second;
  addressSpace.getWriteable(mo, os)->setUnforgettable(offset_val, w);
}

void ExecutionState::symbolizeConcretes() {
  for (MemoryMap::iterator obj_I = addressSpace.objects.begin(),
         obj_E = addressSpace.objects.end(); obj_I != obj_E; ++obj_I) {
    const MemoryObject *mo = obj_I->first;
    ObjectState *os = obj_I->second;
    if (!os->readOnly) {
      ObjectState *osw = addressSpace.getWriteable(mo, os);
      osw->forgetAll();
      osw->resetUnforgettable();
    }
  }
}

bool FieldDescr::eq(const FieldDescr& other) const {
  return width == other.width &&
    name == other.name &&
    (inVal.isNull() ? other.inVal.isNull() :
     (!other.inVal.isNull()) && 0 == inVal->compare(*other.inVal)) &&
    (outVal.isNull() ? other.outVal.isNull() :
     (!other.outVal.isNull()) && 0 == outVal->compare(*other.outVal));
}

bool CallArg::eq(const CallArg& other) const {
  if (fields.size() != other.fields.size()) return false;
  std::map<int, FieldDescr>::const_iterator i = fields.begin(),
    e = fields.end();
  for (; i != e; ++i) {
    std::map<int, FieldDescr>::const_iterator it = other.fields.find(i->first);
    if (it == other.fields.end() || !it->second.eq(i->second)) return false;
  }
  return (expr.isNull() ? other.expr.isNull() :
          (!other.expr.isNull()) && 0 == expr->compare(*other.expr)) &&
    (val.isNull() ? other.val.isNull() :
     (!other.val.isNull()) && 0 == val->compare(*other.val)) &&
    isPtr == other.isPtr &&
    (outVal.isNull() ? other.outVal.isNull() :
     (!other.outVal.isNull()) && 0 == outVal->compare(*other.outVal)) &&
    outWidth == other.outWidth &&
    funPtr == other.funPtr &&
    name == other.name;
}

bool CallArg::sameInvocationValue(const CallArg& other) const {
  return (expr.isNull() ? other.expr.isNull() :
          (!other.expr.isNull()) && 0 == expr->compare(*other.expr)) &&
    name == other.name &&
    (isPtr ?
     (other.isPtr &&
      (val.isNull() ? other.val.isNull() && funPtr == other.funPtr :
       (!other.val.isNull() && 0 == val->compare(*other.val)))) :
     !other.isPtr);
}

bool RetVal::eq(const RetVal& other) const {
  if (fields.size() != other.fields.size()) return false;
  std::map<int, FieldDescr>::const_iterator i = fields.begin(),
    e = fields.end();
  for (; i != e; ++i) {
    std::map<int, FieldDescr>::const_iterator it = other.fields.find(i->first);
    if (it == other.fields.end() || !it->second.eq(i->second)) return false;
  }
  return (expr.isNull() ? other.expr.isNull() :
          (!other.expr.isNull()) && 0 == expr->compare(*other.expr)) &&
    isPtr == other.isPtr &&
    width == other.width &&
    (val.isNull() ? other.val.isNull() :
     (!other.val.isNull()) && 0 == val->compare(*other.val)) &&
    funPtr == other.funPtr;
}

CallArg* CallInfo::getCallArgPtrp(ref<Expr> ptr) {
  for (unsigned i = 0; i < args.size(); ++i) {
    CallArg *cur = &args[i];
    if (cur->isPtr && 0 == cur->expr->compare(*ptr)) return cur;
  }
  return 0;
}

bool equalContexts(const std::vector<ref<Expr> >& a,
                   const std::vector<ref<Expr> >& b) {
  //TODO: naive comparison. should query the solver for the equality of conjunctions.
  if (a.size() != b.size()) return false;
  for (unsigned i = 0; i < a.size(); ++i) {
    bool notFound = true;
    for (unsigned j = 0; j < b.size(); ++j) {
      if (*a[i] == *b[j]) {
        notFound = false;
        break;
      }
    }
    if (notFound) return false;
  }
  for (unsigned i = 0; i < b.size(); ++i) {
    bool notFound = true;
    for (unsigned j = 0; j < a.size(); ++j) {
      if (*a[i] == *b[j]) {
        notFound = false;
        break;
      }
    }
    if (notFound) return false;
  }
  return true;
}

bool CallInfo::eq(const CallInfo& other) const {
  if (args.size() != other.args.size()) return false;
  for (unsigned i = 0; i < args.size(); ++i) {
    if (!args[i].eq(other.args[i])) return false;
  }
  return f == other.f &&
    ret.eq(other.ret) &&
    equalContexts(callContext, other.callContext) &&
    equalContexts(returnContext, other.returnContext) &&
    returned == other.returned;
}

bool CallInfo::sameInvocation(const CallInfo* other) const {
  //TODO: compare assumptions as well.
  if (args.size() != other->args.size()) return false;
  if (f != other->f) return false;
  for (unsigned i = 0; i < args.size(); ++i) {
    if (!args[i].sameInvocationValue(other->args[i])) return false;
  }
  return equalContexts(callContext, other->callContext);
}

SymbolSet CallInfo::computeInvocationSymbolSet() const {
  SymbolSet symbols;
  for (unsigned i = 0; i < args.size(); ++i) {
    SymbolSet argSymbols = GetExprSymbols::visit(args[i].expr);
    symbols.insert(argSymbols.begin(), argSymbols.end());
    if (args[i].isPtr && args[i].funPtr == NULL) {
      argSymbols = GetExprSymbols::visit(args[i].val);
      symbols.insert(argSymbols.begin(), argSymbols.end());
    }
  }
  return symbols;
}

SymbolSet CallInfo::computeRetSymbolSet() const {
  assert(returned && "incomplete");
  SymbolSet symbols;
  if (!ret.expr.isNull()) {
    symbols = GetExprSymbols::visit(ret.expr);
  }
  if (ret.isPtr && ret.funPtr != NULL) {
    SymbolSet ptrSymbols = GetExprSymbols::visit(ret.val);
    symbols.insert(ptrSymbols.begin(), ptrSymbols.end());
  }
  for (unsigned i = 0; i < args.size(); ++i) {
    if (args[i].isPtr && args[i].funPtr == NULL) {
      SymbolSet argSymbols = GetExprSymbols::visit(args[i].outVal);
      symbols.insert(argSymbols.begin(), argSymbols.end());
    }
  }
  return symbols;
}

SymbolSet CallInfo::computeSymbolicVariablesSet() const {
  SymbolSet symbols = computeInvocationSymbolSet();
  SymbolSet retSymbols = computeRetSymbolSet();
  symbols.insert(retSymbols.begin(), retSymbols.end());
  return symbols;
}

LoopInProcess::LoopInProcess(llvm::Loop *_loop,
                             const ExecutionState &_headerState)
  :loop(_loop), unfinishedPaths(1), headerAddressSpace(_headerState.addressSpace)
{
}
