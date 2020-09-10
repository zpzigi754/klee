# KLEE fork for the Vigor project

Changes:
- Add functionality to trace specific calls and dump all call paths/prefixes
- Add loop-havocing functionality with automatic invariant inducing
- Add memory-access restriction methods to allow/forbid code from accessing specific objects (so that their use as opaque pointers can be enforced)
- Add read/write intercepts (to model hardware)
- Add regex support for function aliases (to alias static inline functions whose name is mangled)
- Add support for calling functions with less arguments than they need (via a cast to a function pointer), which DPDK does
- Add basic support for some vector instructions; most are just replaced with an "unreachable" instr since we don't actually execute them


KLEE Symbolic Virtual Machine
=============================

`KLEE` is a symbolic virtual machine built on top of the LLVM compiler
infrastructure. Currently, there are two primary components:

  1. The core symbolic virtual machine engine; this is responsible for
     executing LLVM bitcode modules with support for symbolic
     values. This is comprised of the code in lib/.

  2. A POSIX/Linux emulation layer oriented towards supporting uClibc,
     with additional support for making parts of the operating system
     environment symbolic.

Additionally, there is a simple library for replaying computed inputs
on native code (for closed programs). There is also a more complicated
infrastructure for replaying the inputs generated for the POSIX/Linux
emulation layer, which handles running native programs in an
environment that matches a computed test input, including setting up
files, pipes, environment variables, and passing command line
arguments.

For further information, see the [webpage](http://klee.github.io/).
