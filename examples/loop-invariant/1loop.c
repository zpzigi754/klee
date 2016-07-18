#include <klee/klee.h>

int main() {
  int x = 3;
  while(klee_induce_invariants() & --x)
    {}
  return 0;
}
