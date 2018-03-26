#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
add_executable(ktest-dehavoc
  ktest-dehavoc.cpp
)

set(KLEE_LIBS
  kleeCore
)

target_link_libraries(ktest-dehavoc ${KLEE_LIBS})

install(TARGETS ktest-dehavoc RUNTIME DESTINATION bin)
