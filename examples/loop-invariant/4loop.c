
#include <klee/klee.h>
#include <stdio.h>

int main() {
  int x[4] = {1, 2, 3, 4};
  while(klee_induce_invariants() & x[1]) {
    int idx = x[1];//2, 1, 0
    klee_assume(0 <= idx);
    klee_assume(idx < 3);
    x[idx] = 0;
    --idx;
    x[1] = idx;

    if (x[3] == 4) {
      printf("x[3] may be 4.\n");
    } else {
      printf("x[3] may be NOT 4.\n");
    }
  }//x={1, 0, 0, 4}
  klee_assert(x[3] == 4);
  printf("afterloop");
  return 0;
}
